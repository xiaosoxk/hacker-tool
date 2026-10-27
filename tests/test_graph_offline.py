# -*- coding: utf-8 -*-
"""端到端离线测试：FakeLLM 驱动全图跑通（无网络、无 Docker、无 nmap）。

验证点：主链路 → 扇出收敛 → critic → report；审计有记录；高危未批准不执行。
"""
import json

import pytest

from conftest import SAMPLE_TASK
from secagent.graph.builder import build_graph
from secagent.graph.state import initial_state
from secagent.llm.llm import FakeLLM
from secagent.safety import ROE


@pytest.fixture()
def offline_app(roe):
    import tempfile
    chat = FakeLLM(script={
        "规划器": '{"plan": ["recon", "fingerprint", "vuln_scan", "report"], "next": "recon"}',
    })
    app, bus, breaker = build_graph(chat=chat, roe=roe,
                                    audit_path=tempfile.gettempdir() + "/aegis-test-audit.log",
                                    enable_interrupt=True)
    return app, bus, breaker


def test_full_pipeline_to_report(offline_app, monkeypatch):
    # 确定性打桩：CVE 增强为无候选（避免真实网络调用与 interrupt 分支）
    from secagent.tools.plugins import cve_lookup
    monkeypatch.setattr(cve_lookup, "enrich_findings", lambda findings: findings)

    app, bus, breaker = offline_app
    task = dict(SAMPLE_TASK)
    state = initial_state(task)
    thread = {"configurable": {"thread_id": "t-e2e"}}

    result = app.invoke(state, config=thread)

    # 报告生成且包含关键章节
    report = result.get("report", "")
    assert "安全评估报告" in report
    assert "授权与合规" in report
    assert "攻击路径" in report
    # 侦察发现进入状态
    assert any(f["type"] == "open_service" for f in result.get("findings", []))
    # 攻击路径推演产出
    assert any(f["type"] == "attack_path" for f in result.get("findings", []))
    # 审计有 nmap 记录
    assert any(r["action"] == "nmap_scan" for r in bus.audit.replay(action="nmap_scan"))


def test_interrupt_before_poc(offline_app, monkeypatch):
    """发现候选 CVE 时在 poc_verify 前挂起，等待人工批准。"""
    from secagent.tools.plugins import cve_lookup

    def fake_enrich(findings):
        if findings:
            findings[0]["cves"] = ["CVE-2021-23017"]   # 确定性注入候选 CVE
        return findings

    monkeypatch.setattr(cve_lookup, "enrich_findings", fake_enrich)

    app, bus, breaker = offline_app
    task = dict(SAMPLE_TASK)
    state = initial_state(task)
    thread = {"configurable": {"thread_id": "t-interrupt"}}
    app.invoke(state, config=thread)
    snap = app.get_state(thread)
    assert snap.next == ("poc_verify",)          # 挂起在高危动作前

    # 人工批准后恢复执行，最终出报告
    app.update_state(thread, {"human_approval": True})
    result = app.invoke(None, config=thread)
    assert "安全评估报告" in result.get("report", "")


def test_toolbus_blocks_unregistered(bus):
    import pytest
    with pytest.raises(KeyError):
        bus.call("no_such_tool", target="10.60.0.11")


def test_toolbus_audit_written(bus):
    bus.call("nmap_scan", target="10.60.0.11")
    recs = bus.audit.replay(action="nmap_scan")
    assert len(recs) == 1
    assert recs[0]["result"] == "ok"
    assert recs[0]["target"] == "10.60.0.11"
