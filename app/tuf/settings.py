"""运行配置（全部来自环境变量，带容器内可用的默认值）。"""

from __future__ import annotations

import os
from pathlib import Path

# 包目录 app/tuf -> 项目根目录
_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent.parent

# SQLite 数据库位置：容器内默认 /data/tuf.db（由 compose 挂载命名卷）；
# 本机运行时 /data 不可写则回退到项目根 var/ 目录。
DEFAULT_DB_DIR = Path(os.environ.get("TUF_DATA_DIR", "/data"))
if not os.access(DEFAULT_DB_DIR, os.W_OK):
    DEFAULT_DB_DIR = _PROJECT_ROOT / "var"

DB_PATH = Path(os.environ.get("TUF_DB_PATH", DEFAULT_DB_DIR / "tuf.db"))

# 仅首次启动（数据库中尚无受信 root）时，从该启动文件载入引导 root
BOOTSTRAP_ROOT_PATH = Path(
    os.environ.get(
        "TUF_BOOTSTRAP_ROOT",
        _PROJECT_ROOT / "app" / "bootstrap" / "trusted-root.v1.json",
    )
)

# 单次上传文件大小上限（每份 root，默认 1 MiB）
MAX_UPLOAD_BYTES = int(os.environ.get("TUF_MAX_UPLOAD_BYTES", str(1024 * 1024)))
