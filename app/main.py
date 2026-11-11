"""FastAPI 离线诊断服务 + TUF 根信任轮换管理。

诊断部分全部计算基于用户提交的 JSON，不访问宿主文件系统；
TUF 部分的受信 root 保存在 SQLite（容器命名卷），仅在首次启动时
从启动文件载入引导 root，之后完全通过浏览器上传的轮换链更新。
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from contextlib import asynccontextmanager

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .engine import RequestError, SnapshotError, build_request, build_snapshot
from .resolver import diagnose
from .tuf.root_verify import (
    MAX_CHAIN_LENGTH,
    ChainError,
    RootFormatError,
)
from .tuf.settings import MAX_UPLOAD_BYTES
from .tuf.store import RootStore, StoreError

STATIC_DIR = Path(__file__).resolve().parent / "static"

# 单进程内复用一个 RootStore；两个 uvicorn 工作进程各持一个实例，
# 通过文件锁 + SQLite 事务协同。测试中可用 app.state.tuf_store 覆盖。
_store: Optional[RootStore] = None


def app_state_store() -> Optional[RootStore]:
    return getattr(app.state, "tuf_store", None)


def get_store() -> RootStore:
    global _store
    override = app_state_store()
    if override is not None:
        return override
    if _store is None:
        _store = RootStore()
    return _store


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # 显式初始化：引导文件缺失时启动失败，而不是首个请求才报错
    get_store()
    yield


app = FastAPI(
    title="共享文件服务器读取权限离线诊断 + TUF 根信任轮换",
    version="2.0.0",
    lifespan=lifespan,
    description=(
        "基于运维采集的目录快照 JSON，模拟 Linux 无特权进程的路径解析与权限判定；"
        "并提供 TUF 1.0.37 Ed25519 root 元数据轮换链的浏览器上传、验签与受信根管理。"
    ),
)


class DiagnosePayload(BaseModel):
    snapshot: Any
    request: Any


def _json_error(exc: SnapshotError | RequestError, status: int = 422) -> JSONResponse:
    kind = "snapshot_error" if isinstance(exc, SnapshotError) else "request_error"
    return JSONResponse(
        status_code=status,
        content={
            "ok": False,
            "error_type": kind,
            "message": exc.message,
            "loc": exc.loc,
            "loc_text": "$" + "".join(f"[{p!r}]" for p in exc.loc) if exc.loc else "$",
        },
    )


# --------------------------------------------------------------------------- #
# 页面
# --------------------------------------------------------------------------- #
@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/roots", include_in_schema=False)
def roots_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "roots.html")


# 示例 root 元数据等静态资源（页面本身仍由显式路由返回）
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/examples")
def examples() -> JSONResponse:
    data = json.loads((STATIC_DIR / "examples.json").read_text(encoding="utf-8"))
    return JSONResponse(data)


# --------------------------------------------------------------------------- #
# 诊断 API（原有能力保持不变）
# --------------------------------------------------------------------------- #
@app.post("/api/validate-snapshot")
def validate_snapshot(payload: dict[str, Any]) -> JSONResponse:
    try:
        snap = build_snapshot(payload.get("snapshot"))
    except SnapshotError as exc:
        return _json_error(exc)
    return JSONResponse(
        content={
            "ok": True,
            "node_count": len(snap.nodes),
            "warnings": snap.warnings,
            "paths": sorted(snap.nodes.keys()),
        }
    )


@app.post("/api/diagnose")
def diagnose_endpoint(payload: DiagnosePayload) -> JSONResponse:
    # 先校验快照（带定位），再校验请求
    try:
        snap = build_snapshot(payload.snapshot)
    except SnapshotError as exc:
        return _json_error(exc)
    try:
        req = build_request(payload.request)
    except RequestError as exc:
        return _json_error(exc)

    result = diagnose(snap, req)
    result["snapshot_warnings"] = snap.warnings
    return JSONResponse(content={"ok": True, "result": result})


# --------------------------------------------------------------------------- #
# TUF 根信任轮换 API
# --------------------------------------------------------------------------- #
@app.exception_handler(StoreError)
def _store_error_handler(request: Request, exc: StoreError) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={"ok": False, "error_type": "store_error", "message": str(exc)},
    )


@app.get("/api/root")
def trusted_root_info() -> JSONResponse:
    """当前受信 root 的概要信息（不直接回传完整元数据，下载走独立接口）。"""
    store = get_store()
    info = store.get_trusted_info()
    return JSONResponse(content={"ok": True, "trusted_root": info})


@app.get("/api/root/download")
def trusted_root_download() -> Response:
    """下载当前受信 root 元数据原文，供长期断网的更新客户端安装。"""
    store = get_store()
    parsed = store.get_trusted()
    filename = f"trusted-root.v{parsed.version}.json"
    return Response(
        content=parsed.raw_bytes,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/root/audit")
def root_audit(limit: int = 20) -> JSONResponse:
    store = get_store()
    limit = max(1, min(int(limit), 100))
    return JSONResponse(content={"ok": True, "entries": store.list_audit(limit)})


@app.post("/api/root/update")
async def root_update(files: list[UploadFile] = File(...)) -> JSONResponse:
    """接收按版本排列的 1~8 份 root 元数据并执行整链验证替换。"""
    update_started_at = datetime.now(timezone.utc)

    if not 1 <= len(files) <= MAX_CHAIN_LENGTH:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error_type": "chain_error",
                "failed_version": None,
                "message": f"每次必须上传 1~{MAX_CHAIN_LENGTH} 份 root 元数据，"
                           f"当前收到 {len(files)} 份",
            },
        )

    raw_files: list[bytes] = []
    for index, upload in enumerate(files):
        data = await upload.read()
        if len(data) > MAX_UPLOAD_BYTES:
            return JSONResponse(
                status_code=422,
                content={
                    "ok": False,
                    "error_type": "chain_error",
                    "failed_version": None,
                    "message": f"第 {index + 1} 份文件（{upload.filename}）超过 "
                               f"{MAX_UPLOAD_BYTES} 字节上限",
                },
            )
        if not data:
            return JSONResponse(
                status_code=422,
                content={
                    "ok": False,
                    "error_type": "chain_error",
                    "failed_version": None,
                    "message": f"第 {index + 1} 份文件（{upload.filename}）内容为空",
                },
            )
        raw_files.append(data)

    store = get_store()
    try:
        result = store.submit_chain(raw_files, update_started_at)
    except RootFormatError as exc:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error_type": "root_format_error",
                "failed_version": exc.version,
                "message": exc.message,
            },
        )
    except ChainError as exc:
        return JSONResponse(
            status_code=422,
            content={
                "ok": False,
                "error_type": "chain_error",
                "failed_version": exc.version,
                "message": exc.reason,
            },
        )
    result["trusted_root"] = store.get_trusted_info()
    result["update_started_at"] = update_started_at.isoformat().replace("+00:00", "Z")
    return JSONResponse(content=result)
