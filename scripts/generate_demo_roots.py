#!/usr/bin/env python3
"""生成 TUF 1.0.37 Ed25519 root 轮换演示数据（固定种子，可重复生成）。

产物：
* app/bootstrap/trusted-root.v1.json      —— 首次启动载入的受信 root（v1）
* app/static/demo/root.v2.json            —— 合法链第 1 份（v1 密钥签名，阈值不变）
* app/static/demo/root.v3.json            —— 合法链第 2 份（轮换到 K3/K4，双阈值）
* app/static/demo/root.v4.json            —— 合法链第 3 份（加入 K5，最终根未过期）
* app/static/demo/root.bad-threshold.v4.json —— 失败示例：自身阈值不足 + 未受信签名
* app/static/demo/root.bad-expired.v4.json   —— 失败示例：最终根已过期
* app/static/demo/README.md

运行：/tmp/venv/bin/python scripts/generate_demo_roots.py
（脚本只依赖 pynacl，与服务代码分离，放在 scripts/ 目录。）
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from nacl.signing import SigningKey

from app.tuf.canonicaljson import canonical_bytes, encode
from app.tuf.keys import compute_keyid

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_DIR = PROJECT_ROOT / "app" / "bootstrap"
DEMO_DIR = PROJECT_ROOT / "app" / "static" / "demo"

# 固定参考日期：v1~v3 已过期（中间根允许过期），合法 v4 远未到期
EXPIRED = "2026-10-01T00:00:00Z"
FUTURE = "2032-12-31T00:00:00Z"
PAST_FINAL = "2026-10-01T00:00:00Z"
SPEC_VERSION = "1.0.37"


def gen_signing_key(seed_byte: int) -> SigningKey:
    # 32 字节确定性种子，保证演示文件可重复生成
    return SigningKey(bytes([seed_byte]) * 32)


def make_key_obj(signing: SigningKey) -> dict:
    return {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": signing.verify_key.encode().hex()},
    }


def build_root(
    version: int,
    expires: str,
    signers: dict[str, SigningKey],
    root_threshold: int,
    root_keyids: list[str],
    sign_with: list[str],
    listed_keyids: list[str] | None = None,
) -> dict:
    """构造并签名一份 root 元数据。

    signers: keyid -> 签名密钥；root_keyids: 本版 root 角色登记的 keyid；
    sign_with: 实际用哪些 keyid 对 signed 部分签名；
    listed_keyids: signed.keys 中列出的 keyid（默认等于 signers 的全部键）。
    """
    listed = listed_keyids if listed_keyids is not None else sorted(signers)
    keys = {keyid: make_key_obj(signers[keyid]) for keyid in listed}
    # 复核 keyid 与 TUF 1.0.37 算法一致
    for keyid, key_obj in keys.items():
        assert compute_keyid(key_obj) == keyid

    signed = {
        "_type": "root",
        "spec_version": SPEC_VERSION,
        "version": version,
        "expires": expires,
        "keys": keys,
        "roles": {
            "root": {"keyids": list(root_keyids), "threshold": root_threshold},
            "timestamp": {"keyids": list(root_keyids)[:1], "threshold": 1},
            "snapshot": {"keyids": list(root_keyids)[:1], "threshold": 1},
            "targets": {"keyids": list(root_keyids)[:1], "threshold": 1},
        },
    }
    signed_bytes = canonical_bytes(signed)
    signatures = []
    for keyid in sign_with:
        sig_hex = signers[keyid].sign(signed_bytes).signature.hex()
        signatures.append({"keyid": keyid, "sig": sig_hex})
    return {"signatures": signatures, "signed": signed}


def write_json(path: Path, envelope: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(envelope, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> None:
    # ---- 五把确定性 Ed25519 密钥 ----------------------------------------
    sk1, sk2, sk3, sk4, sk5 = (gen_signing_key(i) for i in (1, 2, 3, 4, 5))
    k1, k2, k3, k4, k5 = (
        compute_keyid(make_key_obj(sk)) for sk in (sk1, sk2, sk3, sk4, sk5)
    )
    print("keyids:")
    for name, kid in (("K1", k1), ("K2", k2), ("K3", k3), ("K4", k4), ("K5", k5)):
        print(f"  {name} = {kid}")

    old_set = {k1: sk1, k2: sk2, k3: sk3}
    new_set = {k3: sk3, k4: sk4}

    # ---- v1：引导受信 root（K1/K2/K3，阈值 2，已过期也可作为信任锚） ----
    v1 = build_root(1, EXPIRED, old_set, 2, [k1, k2, k3], [k1, k2])
    write_json(BOOTSTRAP_DIR / "trusted-root.v1.json", v1)

    # ---- v2：阈值/密钥不变，由 v1 的两把密钥批准 -------------------------
    v2 = build_root(2, EXPIRED, old_set, 2, [k1, k2, k3], [k1, k2])
    write_json(DEMO_DIR / "root.v2.json", v2)

    # ---- v3：轮换到 K3/K4（阈值 2）；旧锚 K1/K2 签 + 自身 K3/K4 签 ------
    # signed.keys 只登记新信任集 K3/K4；旧密钥 K1/K2 仅用于产生
    # “上一版 root 阈值”要求的签名，不进入本版 keys 映射。
    v3_signers = {k1: sk1, k2: sk2, k3: sk3, k4: sk4}
    v3 = build_root(
        3, EXPIRED, v3_signers, 2, [k3, k4], [k1, k2, k3, k4],
        listed_keyids=[k3, k4],
    )
    write_json(DEMO_DIR / "root.v3.json", v3)

    # ---- v4：加入 K5（阈值仍 2）；v3 锚 K3/K4 签 + 自身 K3/K4 签 --------
    v4_set = {k3: sk3, k4: sk4, k5: sk5}
    v4 = build_root(4, FUTURE, v4_set, 2, [k3, k4, k5], [k3, k4])
    write_json(DEMO_DIR / "root.v4.json", v4)

    # ---- 失败示例 A：v4 自身阈值不足 ------------------------------------
    # 上一版（v3）阈值满足：K3/K4 两签均在 v3 的 root keyids 中；
    # 本版把 root 阈值提高到 3，但 root 角色只登记 K3/K4 两个 keyid，
    # 去重后最多只有 2 个有效签名，自身阈值必然不足；
    # K5 不在 root 角色 keyids 中，其签名应被忽略。
    bad_thr_signed = {
        "_type": "root",
        "spec_version": SPEC_VERSION,
        "version": 4,
        "expires": FUTURE,
        "keys": {kid: make_key_obj(v4_set[kid]) for kid in sorted(v4_set)},
        "roles": {
            "root": {"keyids": [k3, k4], "threshold": 3},  # 2 个 keyid 无法满足阈值 3
            "timestamp": {"keyids": [k3], "threshold": 1},
            "snapshot": {"keyids": [k3], "threshold": 1},
            "targets": {"keyids": [k3], "threshold": 1},
        },
    }
    bad_thr_bytes = canonical_bytes(bad_thr_signed)
    bad_thr = {
        "signatures": [
            {"keyid": k3, "sig": sk3.sign(bad_thr_bytes).signature.hex()},
            {"keyid": k4, "sig": sk4.sign(bad_thr_bytes).signature.hex()},
            {"keyid": k5, "sig": sk5.sign(bad_thr_bytes).signature.hex()},
        ],
        "signed": bad_thr_signed,
    }
    write_json(DEMO_DIR / "root.bad-threshold.v4.json", bad_thr)

    # ---- 失败示例 B：最终根过期 -----------------------------------------
    bad_exp = build_root(4, PAST_FINAL, v4_set, 2, [k3, k4, k5], [k3, k4])
    write_json(DEMO_DIR / "root.bad-expired.v4.json", bad_exp)

    readme = f"""# TUF root 轮换演示数据（TUF 1.0.37，仅 Ed25519）

由 `scripts/generate_demo_roots.py` 以固定种子生成，可重复构建。
引导受信 root 为 `app/bootstrap/trusted-root.v1.json`（version=1，阈值 2，密钥 K1/K2/K3）。

## 合法链（3 份，v2 → v3 → v4）

| 文件 | 版本 | root 密钥 | 阈值 | expires | 签名密钥 |
| --- | --- | --- | --- | --- | --- |
| root.v2.json | 2 | K1/K2/K3 | 2 | {EXPIRED}（中间根，允许过期） | K1/K2 |
| root.v3.json | 3 | K3/K4 | 2 | {EXPIRED}（中间根，允许过期） | K1/K2（上一版阈值）+ K3/K4（自身阈值） |
| root.v4.json | 4 | K3/K4/K5 | 2 | {FUTURE}（晚于更新开始时间） | K3/K4 |

要点：v3 完成密钥轮换（K1/K2 退出，K4 加入，K3 桥接），每份都同时满足
上一版 root 与自身 root 的角色阈值；v1/v2/v3 已过期但作为中间根被允许。

## 失败链

* `root.bad-threshold.v4.json`：v4 把 root 阈值提高到 3，但 root 角色只登记
  K3/K4 两个 keyid（去重后最多 2 个有效签名），且 K5 未登记进 root 角色、其签名被忽略
  → 自身阈值不足，整链拒绝。
* `root.bad-expired.v4.json`：v4 签名全部有效，但 expires={PAST_FINAL}，
  作为最终根早于本次更新开始时间到期 → 整链拒绝。

失败时服务保留原受信 root，并在响应与审计记录中给出失败版本和原因。

## keyid（sha256(canonical JSON(key))）

| 名称 | keyid |
| --- | --- |
"""
    for name, kid in (("K1", k1), ("K2", k2), ("K3", k3), ("K4", k4), ("K5", k5)):
        readme += f"| {name} | `{kid}` |\n"
    (DEMO_DIR / "README.md").write_text(readme, encoding="utf-8")

    # 简单自检：canonical 输出确定性
    assert encode(v1["signed"]) == encode(json.loads(encode(v1["signed"])))
    assert hashlib.sha256(canonical_bytes(make_key_obj(sk1))).hexdigest() == k1
    print(f"\n生成完成：\n  引导: {BOOTSTRAP_DIR}\n  示例: {DEMO_DIR}")


if __name__ == "__main__":
    main()
