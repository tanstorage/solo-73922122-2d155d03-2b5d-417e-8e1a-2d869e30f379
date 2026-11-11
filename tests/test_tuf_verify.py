"""TUF 1.0.37 核心规则单元测试。

覆盖：canonical JSON、Ed25519 keyid/验签、root 结构校验、
版本逐次加 1、双重阈值、重复 keyid 不凑数、非 Ed25519 拒绝、
中间根可过期/最终根必须未过期、坏签名与未知 keyid 忽略。
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from nacl.signing import SigningKey

from app.tuf.canonicaljson import CanonicalJSONError, encode
from app.tuf.keys import (
    KeyFormatError,
    compute_keyid,
    parse_ed25519_public_key,
    verify_ed25519_signature,
)
from app.tuf.root_verify import (
    ChainError,
    RootFormatError,
    parse_root,
    verify_chain,
    verify_role_threshold,
)
from app.tuf.canonicaljson import canonical_bytes

UTC = timezone.utc
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
FUTURE = NOW + timedelta(days=365)
PAST = NOW - timedelta(days=1)


# --------------------------------------------------------------------------- #
# 测试辅助：确定性密钥与 root 构造
# --------------------------------------------------------------------------- #
def skey(byte: int) -> SigningKey:
    return SigningKey(bytes([byte]) * 32)


def key_obj(sk: SigningKey) -> dict:
    return {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": sk.verify_key.encode().hex()},
    }


class RootBuilder:
    def __init__(self):
        self.keys: dict[str, SigningKey] = {}

    def add(self, name: str, sk: SigningKey) -> str:
        kid = compute_keyid(key_obj(sk))
        self.keys[kid] = sk
        return kid

    def make(
        self,
        version: int,
        expires: datetime,
        listed: list[str],
        role_keyids: list[str],
        threshold: int,
        sign_with: list[str],
        *,
        spec_version: str = "1.0.37",
        extra_signatures: list[tuple[str, bytes]] | None = None,
    ) -> dict:
        signed = {
            "_type": "root",
            "spec_version": spec_version,
            "version": version,
            "expires": expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "keys": {kid: key_obj(self.keys[kid]) for kid in listed},
            "roles": {
                "root": {"keyids": list(role_keyids), "threshold": threshold},
            },
        }
        payload = canonical_bytes(signed)
        sigs = [
            {"keyid": kid, "sig": self.keys[kid].sign(payload).signature.hex()}
            for kid in sign_with
        ]
        for kid, raw_sig in extra_signatures or []:
            sigs.append({"keyid": kid, "sig": raw_sig.hex()})
        return {"signatures": sigs, "signed": signed}


@pytest.fixture
def builder():
    return RootBuilder()


def parsed(envelope: dict):
    raw = json.dumps(envelope).encode()
    return parse_root(json.loads(raw), raw)


# --------------------------------------------------------------------------- #
# canonical JSON
# --------------------------------------------------------------------------- #
class TestCanonicalJSON:
    def test_sorted_keys_no_whitespace(self):
        assert encode({"b": 1, "a": 2}) == '{"a":2,"b":1}'

    def test_nested_and_array(self):
        obj = {"z": [1, 2, {"y": True, "x": None}], "a": "hi"}
        assert encode(obj) == '{"a":"hi","z":[1,2,{"x":null,"y":true}]}'

    def test_string_escapes(self):
        assert encode('a"b\\c\n\t\r\b\f') == '"a\\"b\\\\c\\n\\t\\r\\b\\f"'

    def test_control_char_unicode_escape(self):
        assert encode("\x01") == r'"\u0001"'
        # 非 ASCII 原样输出
        assert encode("根") == '"根"'

    def test_float_rejected(self):
        with pytest.raises(CanonicalJSONError):
            encode(1.5)

    def test_non_string_key_rejected(self):
        with pytest.raises(CanonicalJSONError):
            encode({1: "x"})

    def test_deterministic_roundtrip(self):
        obj = {"b": [{"d": 2, "c": 1}], "a": "x"}
        assert encode(json.loads(encode(obj))) == encode(obj)


# --------------------------------------------------------------------------- #
# Ed25519 密钥与 keyid
# --------------------------------------------------------------------------- #
class TestKeys:
    def test_keyid_matches_sha256_canonical(self):
        sk = skey(7)
        ko = key_obj(sk)
        import hashlib
        expected = hashlib.sha256(canonical_bytes(ko)).hexdigest()
        assert compute_keyid(ko) == expected

    def test_non_ed25519_rejected(self):
        ko = key_obj(skey(1))
        ko["keytype"] = "rsa"
        with pytest.raises(KeyFormatError):
            parse_ed25519_public_key(ko)

    def test_bad_scheme_rejected(self):
        ko = key_obj(skey(1))
        ko["scheme"] = "rsassa-pss-sha256"
        with pytest.raises(KeyFormatError):
            parse_ed25519_public_key(ko)

    def test_bad_public_key_length(self):
        ko = key_obj(skey(1))
        ko["keyval"]["public"] = "ab" * 16
        with pytest.raises(KeyFormatError):
            parse_ed25519_public_key(ko)

    def test_bad_hex_rejected(self):
        ko = key_obj(skey(1))
        ko["keyval"]["public"] = "zz" * 32
        with pytest.raises(KeyFormatError):
            parse_ed25519_public_key(ko)

    def test_signature_verify(self):
        sk = skey(9)
        pub = sk.verify_key.encode()
        msg = b"tuf-message"
        sig = sk.sign(msg).signature
        assert verify_ed25519_signature(pub, sig.hex(), msg) is True
        assert verify_ed25519_signature(pub, sig.hex(), b"other") is False
        assert verify_ed25519_signature(pub, "not-hex", msg) is False
        assert verify_ed25519_signature(pub, "ab", msg) is False


# --------------------------------------------------------------------------- #
# root 结构校验
# --------------------------------------------------------------------------- #
class TestRootFormat:
    def test_keyid_mismatch_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a], 1, [a])
        env["signed"]["keys"][a]["keyval"]["public"] = skey(2).verify_key.encode().hex()
        with pytest.raises(RootFormatError) as ei:
            parsed(env)
        assert "keyid" in ei.value.message

    def test_duplicate_signature_keyid_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a], 1, [a])
        env["signatures"].append(dict(env["signatures"][0]))
        with pytest.raises(RootFormatError):
            parsed(env)

    def test_duplicate_role_keyid_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a, a], 1, [a])
        with pytest.raises(RootFormatError) as ei:
            parsed(env)
        assert "重复" in ei.value.message

    def test_role_keyid_not_in_keys_rejected(self, builder):
        a = builder.add("a", skey(1))
        b = builder.add("b", skey(2))
        env = builder.make(1, FUTURE, [a], [a, b], 1, [a])
        with pytest.raises(RootFormatError):
            parsed(env)

    def test_bad_spec_version_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a], 1, [a], spec_version="v1")
        with pytest.raises(RootFormatError):
            parsed(env)

    def test_naive_expires_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a], 1, [a])
        env["signed"]["expires"] = "2030-01-01T00:00:00"
        with pytest.raises(RootFormatError):
            parsed(env)

    def test_bool_version_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a], 1, [a])
        env["signed"]["version"] = True
        with pytest.raises(RootFormatError):
            parsed(env)

    def test_missing_root_role_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a], 1, [a])
        del env["signed"]["roles"]["root"]
        with pytest.raises(RootFormatError):
            parsed(env)

    def test_threshold_zero_rejected(self, builder):
        a = builder.add("a", skey(1))
        env = builder.make(1, FUTURE, [a], [a], 0, [a])
        with pytest.raises(RootFormatError):
            parsed(env)


# --------------------------------------------------------------------------- #
# 整链验证
# --------------------------------------------------------------------------- #
class TestChainVerification:
    def _bootstrap(self, builder, n=3, threshold=2):
        kids = [builder.add(f"k{i}", skey(i + 1)) for i in range(n)]
        env = builder.make(1, PAST, kids, kids, threshold, kids[:threshold])
        return parsed(env), kids

    def test_happy_path_single_file(self, builder):
        trusted, kids = self._bootstrap(builder)
        env = builder.make(2, FUTURE, kids, kids, 2, kids[:2])
        reports = verify_chain(trusted, [parsed(env)], NOW)
        assert len(reports) == 1
        assert reports[0]["version"] == 2
        assert reports[0]["threshold_checks"]["previous_root"]["accepted_count"] == 2
        assert reports[0]["threshold_checks"]["self_root"]["accepted_count"] == 2

    def test_versions_must_increment_by_one(self, builder):
        trusted, kids = self._bootstrap(builder)
        env = builder.make(3, FUTURE, kids, kids, 2, kids[:2])
        with pytest.raises(ChainError) as ei:
            verify_chain(trusted, [parsed(env)], NOW)
        assert ei.value.version == 3
        assert "版本不连续" in ei.value.reason

    def test_gap_inside_chain(self, builder):
        trusted, kids = self._bootstrap(builder)
        v2 = parsed(builder.make(2, PAST, kids, kids, 2, kids[:2]))
        v4 = parsed(builder.make(4, FUTURE, kids, kids, 2, kids[:2]))
        with pytest.raises(ChainError) as ei:
            verify_chain(trusted, [v2, v4], NOW)
        assert ei.value.version == 4

    def test_intermediate_expired_allowed_final_must_be_fresh(self, builder):
        trusted, kids = self._bootstrap(builder)
        v2 = parsed(builder.make(2, PAST, kids, kids, 2, kids[:2]))
        v3 = parsed(builder.make(3, FUTURE, kids, kids, 2, kids[:2]))
        reports = verify_chain(trusted, [v2, v3], NOW)
        assert reports[0]["intermediate_expired_allowed"] is True
        assert reports[1]["expired_at_update_start"] is False

    def test_final_expired_rejected(self, builder):
        trusted, kids = self._bootstrap(builder)
        v2 = parsed(builder.make(2, PAST, kids, kids, 2, kids[:2]))
        v3 = parsed(builder.make(3, PAST, kids, kids, 2, kids[:2]))
        with pytest.raises(ChainError) as ei:
            verify_chain(trusted, [v2, v3], NOW)
        assert ei.value.version == 3
        assert "最终 root 已过期" in ei.value.reason

    def test_duplicate_keyid_cannot_pad_threshold(self, builder):
        # envelope 内重复 keyid 在 parse_root 即被拒；构造阈值 3 但只有 2 个
        # 角色密钥的场景，验证去重计数语义
        trusted, kids = self._bootstrap(builder, n=3, threshold=2)
        env = builder.make(2, FUTURE, kids, kids[:2], 3, kids[:2])
        candidate = parsed(env)
        with pytest.raises(ChainError) as ei:
            verify_chain(trusted, [candidate], NOW)
        assert "阈值" in ei.value.reason
        assert ei.value.version == 2

    def test_unknown_keyid_signature_ignored(self, builder):
        trusted, kids = self._bootstrap(builder)
        outsider_sk = skey(99)
        outsider = builder.add("out", outsider_sk)
        # 阈值 2：只有 1 个受信签名 + 1 个未知 keyid 签名（有效但不受信）→ 失败
        env = builder.make(2, FUTURE, kids, kids, 2, [kids[0]])
        outsider_payload = canonical_bytes(env["signed"])
        env["signatures"].append(
            {"keyid": outsider, "sig": outsider_sk.sign(outsider_payload).signature.hex()}
        )
        # 注意：outsider 不在 keys 中，envelope 允许携带（TUF 允许未知签名），
        # 但 parse_root 不检查 signatures 的 keyid 是否在 keys 里
        candidate = parsed(env)
        with pytest.raises(ChainError):
            verify_chain(trusted, [candidate], NOW)
        # 角色验证抛出的异常上附带逐签名处置：未知 keyid 被忽略而非计为坏签名
        with pytest.raises(ChainError) as ei:
            verify_role_threshold(candidate, trusted)
        result = ei.value.detail
        assert result["accepted_count"] == 1
        statuses = {s["keyid"]: s["status"] for s in result["signatures"]}
        assert statuses[outsider] == "ignored_untrusted_keyid"

    def test_bad_signature_not_counted(self, builder):
        trusted, kids = self._bootstrap(builder)
        bogus = bytes(64)
        env = builder.make(
            2, FUTURE, kids, kids, 2, [kids[0]],
            extra_signatures=[(kids[1], bogus)],
        )
        candidate = parsed(env)
        with pytest.raises(ChainError):
            verify_chain(trusted, [candidate], NOW)

    def test_self_threshold_independent_of_previous(self, builder):
        # 上一版阈值满足、自身阈值不满足 → 拒绝
        trusted, kids = self._bootstrap(builder, n=3, threshold=2)
        # 新 root 角色只登记 1 个密钥且阈值 2，自身无法满足
        env = builder.make(2, FUTURE, kids, kids[:1], 2, kids[:2])
        candidate = parsed(env)
        with pytest.raises(ChainError) as ei:
            verify_chain(trusted, [candidate], NOW)
        assert "自身" in ei.value.reason or "阈值" in ei.value.reason

    def test_key_rotation_bridge_key(self, builder):
        # 完整轮换：v1(K1,K2,K3 阈值2) -> v2(K3,K4 阈值2)，
        # v2 同时带旧锚签名 K1/K2 与自身签名 K3/K4
        k1 = builder.add("k1", skey(1))
        k2 = builder.add("k2", skey(2))
        k3 = builder.add("k3", skey(3))
        k4 = builder.add("k4", skey(4))
        v1 = parsed(builder.make(1, PAST, [k1, k2, k3], [k1, k2, k3], 2, [k1, k2]))
        v2_env = builder.make(
            2, FUTURE, [k3, k4], [k3, k4], 2, [k1, k2, k3, k4]
        )
        reports = verify_chain(v1, [parsed(v2_env)], NOW)
        prev = reports[0]["threshold_checks"]["previous_root"]
        selfc = reports[0]["threshold_checks"]["self_root"]
        # 旧锚 v1 的 root 角色含 K1/K2/K3，v2 携带的 K1/K2/K3 签名均有效（>= 阈值 2）
        assert prev["accepted_count"] == 3
        assert prev["threshold"] == 2
        # 自身 root 角色只有 K3/K4，恰好两签满足阈值 2
        assert selfc["accepted_count"] == 2
        assert selfc["threshold"] == 2

    def test_max_chain_length_enforced(self, builder):
        trusted, kids = self._bootstrap(builder)
        candidates = []
        for v in range(2, 11):  # 9 份，超过 8 份上限
            expires = FUTURE if v == 10 else PAST
            candidates.append(parsed(builder.make(v, expires, kids, kids, 2, kids[:2])))
        with pytest.raises(ChainError) as ei:
            verify_chain(trusted, candidates, NOW)
        assert "最多" in ei.value.reason

    def test_empty_chain_rejected(self, builder):
        trusted, _ = self._bootstrap(builder)
        with pytest.raises(ChainError):
            verify_chain(trusted, [], NOW)

    def test_expires_equal_start_time_rejected(self, builder):
        # 最终根 expires 恰好等于更新开始时间 → “晚于”不成立
        trusted, kids = self._bootstrap(builder)
        env = builder.make(2, NOW, kids, kids, 2, kids[:2])
        with pytest.raises(ChainError):
            verify_chain(trusted, [parsed(env)], NOW)
