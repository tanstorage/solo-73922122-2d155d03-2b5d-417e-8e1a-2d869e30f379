"""TUF 1.0.37 root 元数据结构校验与根信任轮换整链验证。

验签规则（对齐 TUF 1.0.37 §5.3，配合本项目“仅 Ed25519”约束）：

* 每份候选 root 的版本号必须比上一份严格加 1（首份 = 受信 root 版本 + 1）；
* 候选 root N 必须同时满足两套阈值：
    1. 用 **上一版 root** 中 root 角色登记的密钥与阈值验证（旧信任锚批准）；
    2. 用 **候选 root 自身** 中 root 角色登记的密钥与阈值验证（新信任锚自洽）；
* 同一 keyid 的多条签名只计一次，重复 keyid 不得凑足阈值；
* 只统计结构合法、验签通过的签名；未知 keyid / 非 root 角色密钥的签名忽略；
* 中间版本 root 允许已过期；最终版本 root 的 expires 必须晚于本次更新开始时间；
* keyid 必须等于 sha256(canonical JSON(key))，且仅接受 Ed25519。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .canonicaljson import canonical_bytes
from .keys import (
    KeyFormatError,
    compute_keyid,
    parse_ed25519_public_key,
    verify_ed25519_signature,
)

# TUF 1.0.37 规定的版本号格式（点分十进制）
SPEC_VERSION_RE = re.compile(r"^\d+(\.\d+)*$")
MAX_CHAIN_LENGTH = 8
ROOT_ROLE = "root"
SUPPORTED_SPEC_VERSION = "1.0.37"


class RootFormatError(ValueError):
    """root 元数据格式不符合 TUF 1.0.37。"""

    def __init__(self, message: str, *, version: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.version = version


class ChainError(Exception):
    """整链验证失败；version 指出版本，reason 给出原因。"""

    def __init__(self, version: Optional[int], reason: str):
        super().__init__(f"版本 {version}: {reason}" if version is not None else reason)
        self.version = version
        self.reason = reason


@dataclass
class ParsedRoot:
    """解析后的 root 元数据（结构已经过格式校验）。"""

    envelope: dict[str, Any]
    signed: dict[str, Any]
    version: int
    expires: datetime
    spec_version: str
    keys: dict[str, dict[str, Any]]          # keyid -> key 对象（keyid 已复核）
    roles: dict[str, dict[str, Any]]         # 角色名 -> 角色对象
    raw_bytes: bytes                          # 原始上传字节（整链通过后原样落库）
    role_thresholds: dict[str, int] = field(default_factory=dict)
    role_keyids: dict[str, list[str]] = field(default_factory=dict)
    public_keys: dict[str, bytes] = field(default_factory=dict)  # keyid -> 32B 公钥

    def canonical_signed(self) -> bytes:
        return canonical_bytes(self.signed)


# --------------------------------------------------------------------------- #
# 时间解析
# --------------------------------------------------------------------------- #
def parse_expires(value: Any, *, version: Optional[int]) -> datetime:
    """解析 TUF ISO 8601 UTC 时间，返回带时区的 datetime（UTC）。"""
    if not isinstance(value, str) or not value:
        raise RootFormatError("signed.expires 必须是 ISO 8601 时间字符串", version=version)
    text = value.strip()
    # Python 3.11 的 fromisoformat 支持 Z 与偏移量；低版本兜底替换
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RootFormatError(
            f"signed.expires={value!r} 不是合法的 ISO 8601 时间", version=version
        ) from exc
    if dt.tzinfo is None:
        raise RootFormatError(
            "signed.expires 必须带时区（TUF 使用 UTC，形如 2030-01-01T00:00:00Z）",
            version=version,
        )
    return dt.astimezone(timezone.utc)


# --------------------------------------------------------------------------- #
# 结构校验
# --------------------------------------------------------------------------- #
def _check_signatures(envelope: dict[str, Any], *, version: Optional[int]) -> list[dict[str, Any]]:
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise RootFormatError("signatures 必须是非空数组", version=version)
    seen: set[str] = set()
    for idx, sig in enumerate(sigs):
        loc = f"signatures[{idx}]"
        if not isinstance(sig, dict):
            raise RootFormatError(f"{loc} 必须是对象", version=version)
        keyid = sig.get("keyid")
        if not isinstance(keyid, str) or not keyid:
            raise RootFormatError(f"{loc}.keyid 必须是非空字符串", version=version)
        if not isinstance(sig.get("sig"), str) or not sig["sig"]:
            raise RootFormatError(f"{loc}.sig 必须是非空十六进制签名字符串", version=version)
        if keyid in seen:
            raise RootFormatError(
                f"{loc}: keyid={keyid} 在 signatures 中重复出现，"
                "同一 keyid 只能携带一条签名",
                version=version,
            )
        seen.add(keyid)
    return sigs


def parse_root(envelope: Any, raw_bytes: bytes) -> ParsedRoot:
    """把上传的 root 元数据解析为 ParsedRoot，任何结构问题抛 RootFormatError。"""
    if not isinstance(envelope, dict):
        raise RootFormatError("root 元数据必须是 JSON 对象")
    # TUF 1.0.x 的 _type 位于 signed 内部；外层 envelope 只含 signatures/signed
    if not isinstance(envelope.get("signed"), dict) or envelope["signed"].get("_type") != "root":
        raise RootFormatError("元数据类型必须是 root（signed._type 应为 'root'）")

    signed = envelope.get("signed")
    if not isinstance(signed, dict):
        raise RootFormatError("signed 必须是 JSON 对象")

    # 版本号
    version = signed.get("version")
    if isinstance(version, bool) or not isinstance(version, int):
        raise RootFormatError("signed.version 必须是整数")
    if version < 1:
        raise RootFormatError("signed.version 必须 >= 1", version=version)

    # spec_version
    spec_version = signed.get("spec_version")
    if not isinstance(spec_version, str) or not SPEC_VERSION_RE.fullmatch(spec_version):
        raise RootFormatError(
            "signed.spec_version 必须是点分十进制版本字符串（如 1.0.37）",
            version=version,
        )

    expires = parse_expires(signed.get("expires"), version=version)

    # keys
    raw_keys = signed.get("keys")
    if not isinstance(raw_keys, dict) or not raw_keys:
        raise RootFormatError("signed.keys 必须是非空对象", version=version)

    keys: dict[str, dict[str, Any]] = {}
    public_keys: dict[str, bytes] = {}
    for keyid, key_obj in raw_keys.items():
        if not isinstance(keyid, str) or not keyid:
            raise RootFormatError("signed.keys 的键必须是非空 keyid 字符串", version=version)
        try:
            public_raw = parse_ed25519_public_key(key_obj, loc=f"keys[{keyid}]")
        except KeyFormatError as exc:
            raise RootFormatError(str(exc), version=version) from exc
        actual_id = compute_keyid(key_obj)
        if actual_id != keyid:
            raise RootFormatError(
                f"keys[{keyid}] 的 keyid 与 TUF 1.0.37 计算结果不一致："
                f"应为 {actual_id}（sha256(canonical JSON(key))）",
                version=version,
            )
        if keyid in keys:  # dict 天然唯一，防御性保留
            raise RootFormatError(f"keyid {keyid} 在 keys 中重复", version=version)
        keys[keyid] = key_obj
        public_keys[keyid] = public_raw

    # roles
    raw_roles = signed.get("roles")
    if not isinstance(raw_roles, dict):
        raise RootFormatError("signed.roles 必须是对象", version=version)
    if ROOT_ROLE not in raw_roles:
        raise RootFormatError("signed.roles 必须包含 root 角色", version=version)

    roles: dict[str, dict[str, Any]] = {}
    role_thresholds: dict[str, int] = {}
    role_keyids: dict[str, list[str]] = {}
    for role_name, role in raw_roles.items():
        if not isinstance(role_name, str) or not role_name:
            raise RootFormatError("roles 的键必须是非空角色名字符串", version=version)
        if not isinstance(role, dict):
            raise RootFormatError(f"roles[{role_name}] 必须是对象", version=version)
        threshold = role.get("threshold")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 1:
            raise RootFormatError(
                f"roles[{role_name}].threshold 必须是 >= 1 的整数", version=version
            )
        keyids = role.get("keyids")
        if not isinstance(keyids, list) or not keyids:
            raise RootFormatError(
                f"roles[{role_name}].keyids 必须是非空数组", version=version
            )
        dedup: set[str] = set()
        for keyid in keyids:
            if not isinstance(keyid, str) or not keyid:
                raise RootFormatError(
                    f"roles[{role_name}].keyids 中的条目必须是非空字符串",
                    version=version,
                )
            if keyid in dedup:
                raise RootFormatError(
                    f"roles[{role_name}].keyids 中 keyid={keyid} 重复登记，"
                    "重复 keyid 不得用于凑足阈值",
                    version=version,
                )
            dedup.add(keyid)
            if keyid not in keys:
                raise RootFormatError(
                    f"roles[{role_name}].keyids 引用了 keys 中不存在的 keyid={keyid}",
                    version=version,
                )
        roles[role_name] = role
        role_thresholds[role_name] = threshold
        role_keyids[role_name] = list(keyids)

    _check_signatures(envelope, version=version)

    return ParsedRoot(
        envelope=envelope,
        signed=signed,
        version=version,
        expires=expires,
        spec_version=spec_version,
        keys=keys,
        roles=roles,
        raw_bytes=raw_bytes,
        role_thresholds=role_thresholds,
        role_keyids=role_keyids,
        public_keys=public_keys,
    )


# --------------------------------------------------------------------------- #
# 角色阈值验证
# --------------------------------------------------------------------------- #
def verify_role_threshold(
    candidate: ParsedRoot,
    trust_root: ParsedRoot,
    *,
    role: str = ROOT_ROLE,
) -> dict[str, Any]:
    """用 ``trust_root`` 中登记的 role 密钥/阈值验证 candidate 的签名。

    返回验证细节（通过数、阈值、各签名处置）。失败抛 ChainError。
    """
    threshold = trust_root.role_thresholds[role]
    trusted_keyids = trust_root.role_keyids[role]
    signed_bytes = candidate.canonical_signed()

    accepted: set[str] = set()          # 已通过验签的去重 keyid
    signature_details: list[dict[str, Any]] = []

    for sig in candidate.envelope["signatures"]:
        keyid = sig["keyid"]
        detail = {"keyid": keyid}
        if keyid not in trusted_keyids:
            detail["status"] = "ignored_untrusted_keyid"
            detail["detail"] = "该 keyid 不在受信 root 的 root 角色 keyids 中，签名忽略"
            signature_details.append(detail)
            continue
        if keyid in accepted:
            # parse_root 已拒绝 envelope 内同 keyid 重复；这里保留兜底语义
            detail["status"] = "duplicate_ignored"
            detail["detail"] = "同一 keyid 的重复签名只计一次"
            signature_details.append(detail)
            continue
        public_raw = trust_root.public_keys[keyid]
        ok = verify_ed25519_signature(public_raw, sig["sig"], signed_bytes)
        if ok:
            accepted.add(keyid)
            detail["status"] = "accepted"
            detail["detail"] = "Ed25519 验签通过"
        else:
            detail["status"] = "bad_signature"
            detail["detail"] = "签名编码非法或验签不通过"
        signature_details.append(detail)

    result = {
        "role": role,
        "threshold": threshold,
        "accepted_keyids": sorted(accepted),
        "accepted_count": len(accepted),
        "trusted_keyids": trusted_keyids,
        "signatures": signature_details,
    }
    if len(accepted) < threshold:
        err = ChainError(
            candidate.version,
            f"未达到 {role} 角色阈值：去重后有效签名 {len(accepted)} 个，"
            f"阈值为 {threshold}（重复 keyid 不重复计数）",
        )
        err.detail = result  # type: ignore[attr-defined]
        raise err
    return result


# --------------------------------------------------------------------------- #
# 整链验证
# --------------------------------------------------------------------------- #
def verify_chain(
    trusted: ParsedRoot,
    candidates: list[ParsedRoot],
    update_started_at: datetime,
) -> list[dict[str, Any]]:
    """按 TUF 1.0.37 验证完整轮换链。

    * 版本必须从 trusted.version + 1 开始逐次加 1；
    * 每份同时通过上一版 root 与自身 root 角色的阈值；
    * 中间 root 允许过期，最终 root 的 expires 必须晚于 update_started_at；
    * 任一环节失败抛 ChainError（带版本号与原因）；成功返回逐版本验证报告。
    """
    if not candidates:
        raise ChainError(None, "没有可验证的候选 root（需要 1~8 份）")
    if len(candidates) > MAX_CHAIN_LENGTH:
        raise ChainError(
            None, f"一次最多提交 {MAX_CHAIN_LENGTH} 份 root，当前 {len(candidates)} 份"
        )

    started_utc = update_started_at.astimezone(timezone.utc)
    reports: list[dict[str, Any]] = []
    previous = trusted

    for index, candidate in enumerate(candidates):
        expected_version = previous.version + 1
        if candidate.version != expected_version:
            raise ChainError(
                candidate.version,
                f"版本不连续：期望版本 {expected_version}（上一版 {previous.version} 加 1），"
                f"实际收到版本 {candidate.version}",
            )

        # 1) 上一版受信 root 的 root 角色阈值
        previous_check = verify_role_threshold(candidate, previous, role=ROOT_ROLE)
        # 2) 候选 root 自身的 root 角色阈值
        self_check = verify_role_threshold(candidate, candidate, role=ROOT_ROLE)

        # 3) 过期策略：中间版本允许过期，最终版本必须晚于更新开始时间
        is_final = index == len(candidates) - 1
        expired = candidate.expires <= started_utc
        if is_final and expired:
            raise ChainError(
                candidate.version,
                f"最终 root 已过期或恰好到期：expires={candidate.expires.isoformat()} "
                f"不晚于本次更新开始时间 {started_utc.isoformat()}",
            )

        reports.append({
            "version": candidate.version,
            "expires": candidate.expires.isoformat().replace("+00:00", "Z"),
            "expired_at_update_start": expired,
            "intermediate_expired_allowed": expired and not is_final,
            "threshold_checks": {
                "previous_root": previous_check,
                "self_root": self_check,
            },
        })
        previous = candidate

    return reports
