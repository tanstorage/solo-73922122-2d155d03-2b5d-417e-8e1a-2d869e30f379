"""TUF 1.0.37 使用的 canonical JSON 编码（OLPC Canonical JSON）。

规则（与 TUF 规范第 4 节一致）：
* 不输出任何无意义空白；
* 对象的键按码位字典序排列，键必须是字符串；
* 字符串仅转义双引号、反斜杠与控制字符（U+0000..U+001F），
  其中退格/换页/换行/回车/制表符使用短转义，其余控制字符使用小写
  四位十六进制 ``\\u00xx``；正斜杠不转义，非 ASCII 字符原样输出；
* 只允许整数（不允许浮点、指数表示法），布尔与 null 小写；
* 不允许 NaN / Infinity。
"""

from __future__ import annotations

from typing import Any


class CanonicalJSONError(ValueError):
    """对象无法按 canonical JSON 编码。"""


_SHORT_ESCAPES = {
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
}


def _encode_string(s: str) -> str:
    parts: list[str] = ['"']
    for ch in s:
        if ch == '"':
            parts.append('\\"')
        elif ch == "\\":
            parts.append("\\\\")
        elif ch in _SHORT_ESCAPES:
            parts.append(_SHORT_ESCAPES[ch])
        else:
            code = ord(ch)
            if code < 0x20:
                parts.append("\\u%04x" % code)
            else:
                parts.append(ch)
    parts.append('"')
    return "".join(parts)


def encode(obj: Any) -> str:
    """把 Python 对象编码为 canonical JSON 字符串。"""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _encode_string(obj)
    if isinstance(obj, bool):  # 冗余防御：bool 必须在 int 之前判断
        return "true" if obj else "false"
    if isinstance(obj, int):
        return str(obj)
    if isinstance(obj, float):
        raise CanonicalJSONError("canonical JSON 不支持浮点数（TUF 元数据只使用整数）")
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(encode(item) for item in obj) + "]"
    if isinstance(obj, dict):
        for key in obj:
            if not isinstance(key, str):
                raise CanonicalJSONError("canonical JSON 对象的键必须是字符串")
        return "{" + ",".join(
            _encode_string(key) + ":" + encode(obj[key])
            for key in sorted(obj.keys())
        ) + "}"
    raise CanonicalJSONError(f"不支持 canonical JSON 编码的类型: {type(obj).__name__}")


def canonical_bytes(obj: Any) -> bytes:
    """签名/keyid 计算实际使用的 UTF-8 字节序列。"""
    return encode(obj).encode("utf-8")
