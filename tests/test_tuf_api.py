"""TUF 轮换 HTTP API 测试：页面、受信根信息/下载、上传整链、失败原因、审计。"""

from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.tuf.store import RootStore

PROJECT = Path(__file__).resolve().parents[1]
BOOTSTRAP = PROJECT / "app" / "bootstrap" / "trusted-root.v1.json"
DEMO = PROJECT / "app" / "static" / "demo"
NOW = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def client(tmp_path):
    store = RootStore(tmp_path / "tuf.db", BOOTSTRAP)
    app.state.tuf_store = store
    with TestClient(app) as c:
        yield c
    app.state.tuf_store = None


def _upload(client, names):
    files = [
        ("files", (name, (DEMO / name).read_bytes(), "application/json"))
        for name in names
    ]
    return client.post("/api/root/update", files=files)


class TestPagesAndInfo:
    def test_roots_page_served(self, client):
        r = client.get("/roots")
        assert r.status_code == 200
        assert "TUF" in r.text

    def test_homepage_links_to_roots(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert 'href="/roots"' in r.text

    def test_demo_static_files_mounted(self, client):
        r = client.get("/static/demo/root.v2.json")
        assert r.status_code == 200
        assert r.json()["signed"]["version"] == 2

    def test_trusted_root_info(self, client):
        r = client.get("/api/root")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["trusted_root"]["version"] == 1
        assert data["trusted_root"]["root_threshold"] == 2

    def test_download_trusted_root(self, client):
        r = client.get("/api/root/download")
        assert r.status_code == 200
        body = r.json()
        assert body["signed"]["_type"] == "root"
        assert "attachment" in r.headers["content-disposition"]
        assert "trusted-root.v1.json" in r.headers["content-disposition"]


class TestUpdateAPI:
    def test_valid_chain_success(self, client):
        r = _upload(client, ["root.v2.json", "root.v3.json", "root.v4.json"])
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True
        assert data["previous_version"] == 1
        assert data["current_version"] == 4
        # 逐版本报告包含双重阈值检查
        versions = [rep["version"] for rep in data["reports"]]
        assert versions == [2, 3, 4]
        for rep in data["reports"]:
            assert "previous_root" in rep["threshold_checks"]
            assert "self_root" in rep["threshold_checks"]
        # 受信根信息同步刷新
        assert client.get("/api/root").json()["trusted_root"]["version"] == 4
        # 下载文件名跟随版本
        assert "trusted-root.v4.json" in client.get(
            "/api/root/download"
        ).headers["content-disposition"]

    def test_expired_final_root_failure_keeps_v1(self, client):
        r = _upload(
            client,
            ["root.v2.json", "root.v3.json", "root.bad-expired.v4.json"],
        )
        assert r.status_code == 422
        data = r.json()
        assert data["ok"] is False
        assert data["failed_version"] == 4
        assert "过期" in data["message"]
        assert client.get("/api/root").json()["trusted_root"]["version"] == 1

    def test_threshold_failure_reports_version(self, client):
        r = _upload(
            client,
            ["root.v2.json", "root.v3.json", "root.bad-threshold.v4.json"],
        )
        assert r.status_code == 422
        data = r.json()
        assert data["failed_version"] == 4
        assert "阈值" in data["message"]

    def test_version_gap_failure(self, client):
        r = _upload(client, ["root.v3.json"])
        assert r.status_code == 422
        data = r.json()
        assert data["failed_version"] == 3
        assert "版本不连续" in data["message"]

    def test_too_many_files_rejected(self, client):
        names = ["root.v2.json"] * 9
        r = _upload(client, names)
        assert r.status_code == 422
        assert "1~8" in r.json()["message"]

    def test_empty_upload_rejected(self, client):
        r = client.post("/api/root/update", files=[])
        assert r.status_code == 422

    def test_non_json_file_rejected(self, client):
        r = client.post(
            "/api/root/update",
            files=[("files", ("broken.json", b"{not-json", "application/json"))],
        )
        assert r.status_code == 422
        assert r.json()["error_type"] == "root_format_error"

    def test_audit_records_success_and_failure(self, client):
        _upload(
            client,
            ["root.v2.json", "root.v3.json", "root.bad-expired.v4.json"],
        )
        _upload(client, ["root.v2.json", "root.v3.json", "root.v4.json"])
        r = client.get("/api/root/audit")
        entries = r.json()["entries"]
        results = [e["result"] for e in entries]
        assert "failure" in results
        assert "success" in results
        failure = next(e for e in entries if e["result"] == "failure")
        assert failure["failed_version"] == 4

    def test_second_request_uses_latest_trusted_root(self, client):
        # 第一次提交把版本推进到 v4
        r1 = _upload(client, ["root.v2.json", "root.v3.json", "root.v4.json"])
        assert r1.status_code == 200
        # 再次提交旧链 v2：必须以最新 v4 为起点，期望 v5，因而版本不连续被拒
        r2 = _upload(client, ["root.v2.json"])
        assert r2.status_code == 422
        assert r2.json()["failed_version"] == 2
        assert "版本不连续" in r2.json()["message"]
        # 受信 root 保持 v4，未被覆盖
        assert client.get("/api/root").json()["trusted_root"]["version"] == 4

    def test_only_ed25519_accepted(self, client, tmp_path):
        import json
        v1 = client.get("/api/root/download").json()
        # 构造一份 RSA 类型的 v2 root
        rsa_key = {
            "keytype": "rsa",
            "scheme": "rsassa-pss-sha256",
            "keyval": {"public": "ab" * 64},
        }
        v1["signed"]["version"] = 2
        v1["signed"]["keys"] = {"fake-rsa-keyid": rsa_key}
        v1["signed"]["roles"]["root"]["keyids"] = ["fake-rsa-keyid"]
        r = client.post(
            "/api/root/update",
            files=[("files", ("root.v2.json", json.dumps(v1).encode(),
                              "application/json"))],
        )
        assert r.status_code == 422
        assert "ed25519" in r.json()["message"]
