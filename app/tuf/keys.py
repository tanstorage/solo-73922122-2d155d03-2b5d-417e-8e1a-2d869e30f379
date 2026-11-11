"""TUF 1.0.37 Ed25519 密钥：keyid 计算、公钥解析与签名验证。

本项目仅支持 Ed25519：
* key 对象形如
  ``{"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "<hex>"}}``；
* keyid = sha256(canonical_json(key)) 的十六进制摘要（TUF 1.0.37 §4.2）；
* 签名为 64 字节 Ed25519 签名的十六进制表示。
"""

from __future__ import annotations

import binascii
import hashlib
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from .canonicaljson import CanonicalJSONError, canonical_bytes

SUPPORTED_KEYTYPE = "ed25519"
SUPPORTED_SCHEME = "ed25519"
ED25519_PUBLIC_KEY_LEN = 32
ED25519_SIGNATURE_LEN = 64


class KeyFormatError(ValueError):
    """key 对象结构或编码不符合 TUF 1.0.37 / Ed25519 要求。"""


def compute_keyid(key_obj: Any) -> str:
    """按 TUF 1.0.37 计算 keyid：sha256 hex(canonical JSON(key 对象))。"""
    try:
        payload = canonical_bytes(key_obj)
    except CanonicalJSONError as exc:
        raise KeyFormatError(f"key 对象无法进行 canonical JSON 编码: {exc}") from exc
    return hashlib.sha256(payload).hexdigest()


def parse_ed25519_public_key(key_obj: Any, *, loc: str = "key") -> bytes:
    """校验 key 对象并返回 32 字节原始 Ed25519 公钥。

    只接受 Ed25519，任何其他 keytype/scheme 一律拒绝。
    """
    if not isinstance(key_obj, dict):
        raise KeyFormatError(f"{loc}: key 必须是 JSON 对象")
    keytype = key_obj.get("keytype")
    if keytype != SUPPORTED_KEYTYPE:
        if keytype is None:
            raise KeyFormatError(f"{loc}: 缺少 keytype 字段（仅支持 {SUPPORTED_KEYTYPE}）")
        raise KeyFormatError(
            f"{loc}: 不支持的 keytype={keytype!r}，本服务仅支持 {SUPPORTED_KEYTYPE}"
        )
    scheme = key_obj.get("scheme")
    if scheme != SUPPORTED_SCHEME:
        if scheme is None:
            raise KeyFormatError(f"{loc}: 缺少 scheme 字段（仅支持 {SUPPORTED_SCHEME}）")
        raise KeyFormatError(
            f"{loc}: 不支持的 scheme={scheme!r}，本服务仅支持 {SUPPORTED_SCHEME}"
        )
    keyval = key_obj.get("keyval")
    if not isinstance(keyval, dict):
        raise KeyFormatError(f"{loc}: keyval 必须是 JSON 对象")
    public_hex = keyval.get("public")
    if not isinstance(public_hex, str) or not public_hex:
        raise KeyFormatError(f"{loc}: keyval.public 必须是非空十六进制字符串")
    try:
        raw = bytes.fromhex(public_hex)
    except (ValueError, binascii.Error) as exc:
        raise KeyFormatError(f"{loc}: keyval.public 不是合法的十六进制字符串") from exc
    if len(raw) != ED25519_PUBLIC_KEY_LEN:
        raise KeyFormatError(
            f"{loc}: Ed25519 公钥必须是 {ED25519_PUBLIC_KEY_LEN} 字节，"
            f"当前解码为 {len(raw)} 字节"
        )
    return raw


def verify_ed25519_signature(public_raw: bytes, signature_hex: str, signed_bytes: bytes) -> bool:
    """验证单条 Ed25519 签名。

    签名编码非法时返回 False（与验签失败等价），不向调用方抛出异常。
    """
    if not isinstance(signature_hex, str):
        return False
    try:
        sig = bytes.fromhex(signature_hex)
    except (ValueError, binascii.Error):
        return False
    if len(sig) != ED25519_SIGNATURE_LEN:
        return False
    try:
        VerifyKey(public_raw).verify(signed_bytes, sig)
        return True
    except BadSignatureError:
        return False
