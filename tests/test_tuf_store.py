"""RootStore 测试：首次引导、整链替换、失败保留、重启保留、并发不覆盖。"""

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.tuf.root_verify import ChainError, RootFormatError
from app.tuf.store import RootStore, StoreError

PROJECT = Path(__file__).resolve().parents[1]
BOOTSTRAP = PROJECT / "app" / "bootstrap" / "trusted-root.v1.json"
DEMO = PROJECT / "app" / "static" / "demo"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def demo_bytes(name: str) -> bytes:
    return (DEMO / name).read_bytes()


@pytest.fixture
def store(tmp_path):
    return RootStore(
        db_path=tmp_path / "tuf.db",
        bootstrap_path=BOOTSTRAP,
    )


class TestBootstrap:
    def test_first_start_loads_bootstrap_file(self, store):
        info = store.get_trusted_info()
        assert info["version"] == 1
        assert info["spec_version"] == "1.0.37"
        assert info["root_threshold"] == 2
        audit = store.list_audit()
        assert audit[0]["result"] == "bootstrap"

    def test_bootstrap_missing_file_raises(self, tmp_path):
        with pytest.raises(StoreError):
            RootStore(
                db_path=tmp_path / "x" / "tuf.db",
                bootstrap_path=tmp_path / "missing.json",
            )

    def test_bootstrap_only_on_first_start(self, tmp_path, store):
        # 第二次构造同库：即便引导文件被“替换”，也不会重新载入
        other_bootstrap = tmp_path / "fake-root.json"
        other_bootstrap.write_text("{}")
        store2 = RootStore(tmp_path / "tuf.db", other_bootstrap)
        assert store2.get_trusted_info()["version"] == 1
        # 审计里仍然只有一条 bootstrap，没有第二次引导
        results = [e["result"] for e in store2.list_audit()]
        assert results.count("bootstrap") == 1


class TestSubmitChain:
    def test_valid_chain_replaces_trusted_root(self, store):
        files = [demo_bytes(f"root.v{i}.json") for i in (2, 3, 4)]
        result = store.submit_chain(files, NOW)
        assert result["ok"] is True
        assert result["previous_version"] == 1
        assert result["current_version"] == 4
        assert store.get_trusted_info()["version"] == 4
        audit = store.list_audit()
        assert audit[0]["result"] == "success"
        assert audit[0]["to_version"] == 4

    def test_failed_chain_keeps_original_root(self, store):
        before = store.get_trusted()
        files = [
            demo_bytes("root.v2.json"),
            demo_bytes("root.v3.json"),
            demo_bytes("root.bad-expired.v4.json"),
        ]
        with pytest.raises(ChainError) as ei:
            store.submit_chain(files, NOW)
        assert ei.value.version == 4
        after = store.get_trusted()
        assert after.version == before.version == 1
        assert after.raw_bytes == before.raw_bytes
        audit = store.list_audit()
        assert audit[0]["result"] == "failure"
        assert audit[0]["failed_version"] == 4
        assert "过期" in audit[0]["reason"]

    def test_bad_threshold_chain_rejected_with_version(self, store):
        files = [
            demo_bytes("root.v2.json"),
            demo_bytes("root.v3.json"),
            demo_bytes("root.bad-threshold.v4.json"),
        ]
        with pytest.raises(ChainError) as ei:
            store.submit_chain(files, NOW)
        assert ei.value.version == 4
        assert "阈值" in ei.value.reason
        assert store.get_trusted_info()["version"] == 1

    def test_invalid_json_rejected(self, store):
        with pytest.raises(RootFormatError):
            store.submit_chain([b"{not json"], NOW)
        assert store.get_trusted_info()["version"] == 1

    def test_duplicate_versions_rejected(self, store):
        files = [demo_bytes("root.v2.json"), demo_bytes("root.v2.json")]
        with pytest.raises(ChainError) as ei:
            store.submit_chain(files, NOW)
        assert ei.value.version == 2

    def test_version_gap_rejected(self, store):
        # 直接上传 v3（受信是 v1）
        with pytest.raises(ChainError) as ei:
            store.submit_chain([demo_bytes("root.v3.json")], NOW)
        assert ei.value.version == 3

    def test_subsequent_update_builds_on_new_trusted(self, store):
        # 第一次提交完整合法链，推进到 v4（v2/v3 为允许过期的中间根，v4 新鲜）
        first = store.submit_chain(
            [demo_bytes(f"root.v{i}.json") for i in (2, 3, 4)], NOW
        )
        assert first["previous_version"] == 1
        assert store.get_trusted_info()["version"] == 4
        # 第二次提交必须以最新受信根 v4 为起点：再传 v2 会因版本不连续被拒，
        # 证明验证起点已经是新受信根，而不是进程内缓存的旧 v1
        with pytest.raises(ChainError) as ei:
            store.submit_chain([demo_bytes("root.v2.json")], NOW)
        assert ei.value.version == 2
        assert "版本不连续" in ei.value.reason
        assert store.get_trusted_info()["version"] == 4

    def test_persistence_across_restart(self, tmp_path, store):
        store.submit_chain(
            [demo_bytes(f"root.v{i}.json") for i in (2, 3, 4)], NOW
        )
        # 模拟进程重启：新建 RootStore，指向同一个 SQLite 文件
        restarted = RootStore(tmp_path / "tuf.db", BOOTSTRAP)
        assert restarted.get_trusted_info()["version"] == 4
        entries = restarted.list_audit()
        kinds = [e["result"] for e in entries]
        assert "bootstrap" in kinds and "success" in kinds

    def test_trusted_root_download_bytes_roundtrip(self, store):
        store.submit_chain(
            [demo_bytes(f"root.v{i}.json") for i in (2, 3, 4)], NOW
        )
        parsed = store.get_trusted()
        on_disk = json.loads(demo_bytes("root.v4.json"))
        assert json.loads(parsed.raw_bytes) == on_disk

    def test_unordered_upload_sorted_by_version(self, store):
        # 浏览器选择文件的顺序不确定；服务按 signed.version 排序后验证
        files = [
            demo_bytes("root.v4.json"),
            demo_bytes("root.v2.json"),
            demo_bytes("root.v3.json"),
        ]
        result = store.submit_chain(files, NOW)
        assert result["current_version"] == 4
        assert [r["version"] for r in result["reports"]] == [2, 3, 4]


class TestConcurrency:
    def test_concurrent_submissions_do_not_overwrite(self, tmp_path):
        """两个线程并发提交同一条链：一个成功，另一个必须基于最新根重新验证。

        第一次提交把 v1 提升到 v4；第二次提交仍从 v2 开始，会因版本不连续
        被拒绝（而不是覆盖已提交的 v4）。
        """
        store = RootStore(tmp_path / "tuf.db", BOOTSTRAP)
        files = [demo_bytes(f"root.v{i}.json") for i in (2, 3, 4)]
        outcomes: list[Exception | dict] = []

        def worker():
            try:
                outcomes.append(
                    store.submit_chain([b for b in files], NOW)
                )
            except Exception as exc:  # noqa: BLE001
                outcomes.append(exc)

        t1 = threading.Thread(target=worker)
        t2 = threading.Thread(target=worker)
        t1.start(); t2.start()
        t1.join(); t2.join()

        assert len(outcomes) == 2
        successes = [o for o in outcomes if isinstance(o, dict)]
        failures = [o for o in outcomes if isinstance(o, Exception)]
        assert len(successes) == 1
        assert len(failures) == 1
        assert isinstance(failures[0], ChainError)
        # 受信 root 只被推进一次，没有被覆盖回旧版本
        assert store.get_trusted_info()["version"] == 4
        versions = [e["result"] for e in store.list_audit()]
        assert versions.count("success") == 1
        assert versions.count("failure") == 1

    def test_lock_serializes_transactions(self, tmp_path):
        """锁内事务串行：重复串行提交同一链，第二次必然因版本不连续失败。"""
        store = RootStore(tmp_path / "tuf.db", BOOTSTRAP)
        files = [demo_bytes(f"root.v{i}.json") for i in (2, 3, 4)]
        first = store.submit_chain(list(files), NOW)
        assert first["current_version"] == 4
        with pytest.raises(ChainError):
            store.submit_chain(list(files), NOW)
        assert store.get_trusted_info()["version"] == 4
