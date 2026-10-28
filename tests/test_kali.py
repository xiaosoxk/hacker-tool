# -*- coding: utf-8 -*-
"""Kali 联动测试：白名单、参数卫生、输出解析器、kali_recon 节点合并。

全部离线：FakeExecutor 返回罐头输出，不需要真实 Kali 环境。
"""
import pytest

from conftest import SAMPLE_TASK
from secagent.graph.nodes import make_kali_recon_node
from secagent.tools import kali
from secagent.tools.registry import ToolMeta


class FakeExecutor:
    """按首个参数（工具名）返回罐头输出。"""

    def __init__(self, canned: dict[str, str]) -> None:
        self.canned = canned
        self.calls: list[list[str]] = []

    def run(self, argv: list[str], timeout: int = 300):
        self.calls.append(argv)
        out = self.canned.get(argv[0], "")
        return kali.ExecResult(0, out, "")


CANNED = {
    "whatweb": "http://10.60.0.11 [200 OK] China, nginx[1.24.0], PHP[8.1], jQuery",
    "wafw00f": "http://10.60.0.11 is behind a ModSecurity WAF.\n",
    "nikto": "+ Target IP: 10.60.0.11\n+ /admin: Admin login page found.\n"
             "+ OSVDB-3092: /backup/: Directory indexing found.\n",
    "searchsploit": '{"RESULTS_EXPLOIT": [{"Title": "Nginx 1.18 - Resolver Dereference", "EDB-ID": 49977, "Type": "dos"}]}',
}


@pytest.fixture()
def fake_executor():
    return FakeExecutor(CANNED)


# ---- 白名单与参数卫生 -------------------------------------------------------
def test_allowlist_blocks_unknown_tool(fake_executor):
    with pytest.raises(PermissionError):
        kali.kali_run(fake_executor, "python3", ["-c", "import os"])


def test_injection_args_blocked(fake_executor):
    with pytest.raises(ValueError):
        kali.kali_run(fake_executor, "nmap", ["10.60.0.11; rm -rf /"])
    with pytest.raises(ValueError):
        kali.kali_run(fake_executor, "nmap", ["$(whoami)"])


def test_whitelisted_tool_passes(fake_executor):
    res = kali.kali_run(fake_executor, "whatweb", ["http://10.60.0.11"])
    assert res.exit_code == 0
    assert fake_executor.calls[0] == ["whatweb", "http://10.60.0.11"]  # argv 直传不走 shell


# ---- 解析器 ----------------------------------------------------------------
def test_parse_whatweb(fake_executor):
    out = kali.parse_whatweb(fake_executor.run(["whatweb", "x"]).stdout)
    r = out["results"][0]
    assert r["target"] == "http://10.60.0.11"
    assert "nginx" in r["techs"] and "PHP" in r["techs"]


def test_parse_wafw00f(fake_executor):
    out = kali.parse_wafw00f(fake_executor.run(["wafw00f", "x"]).stdout)
    assert out["detected"] is True
    assert "ModSecurity" in out["waf"]


def test_parse_nikto_skips_headers(fake_executor):
    out = kali.parse_nikto(fake_executor.run(["nikto", "-h", "x"]).stdout)
    joined = " ".join(out["items"])
    assert "/admin" in joined and "Target IP" not in joined


def test_parse_searchsploit_json(fake_executor):
    out = kali.parse_searchsploit(fake_executor.run(["searchsploit", "-j", "nginx"]).stdout)
    assert out["exploits"][0]["edb_id"] == 49977


# ---- ToolBus 集成 + 节点 ---------------------------------------------------
def test_kali_recon_node(bus, fake_executor):
    bus.register(ToolMeta("kali_whatweb", "fingerprint"),
                 lambda target, executor=fake_executor, **kw: kali.whatweb_tool(target, executor))
    bus.register(ToolMeta("kali_wafw00f", "fingerprint"),
                 lambda target, executor=fake_executor, **kw: kali.wafw00f_tool(target, executor))

    node = make_kali_recon_node(bus)
    out = node({"task": SAMPLE_TASK})

    techs = [f for f in out["findings"] if f["type"] == "web_tech"]
    wafs = [f for f in out["findings"] if f["type"] == "waf_detected"]
    assert any("nginx" in f["product"] for f in techs)
    assert wafs and "ModSecurity" in wafs[0]["summary"]
    # 授权门生效：审计中有 kali_whatweb 记录
    assert any(r["action"] == "kali_whatweb" for r in bus.audit.replay(action="kali_whatweb"))


def test_kali_recon_degrades_when_unreachable(bus):
    class DeadExecutor:
        def run(self, argv, timeout=300):
            return kali.ExecResult(-1, "", "connection refused")

    bus.register(ToolMeta("kali_whatweb", "fingerprint"),
                 lambda target, **kw: kali.whatweb_tool(target, DeadExecutor()))
    node = make_kali_recon_node(bus)
    out = node({"task": SAMPLE_TASK})          # 不抛异常：降级写错误证据
    assert any(e["id"].startswith("ev-kali-err") for e in out["evidence"])
