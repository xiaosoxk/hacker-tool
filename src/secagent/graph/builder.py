# -*- coding: utf-8 -*-
"""StateGraph 组装：多分支状态机 + 人工审批中断 + 检查点。

图结构（与文档第 5 章状态流转图一致）：

  START -> memory_recall -> planner -> recon -> fingerprint -> vuln_scan
        -> [需 POC 验证且未批准] -> poc_verify （interrupt_before 人工审批）
        -> _fanout --Send--> [pcap_analysis, lateral_sim, blue_sim] 并行分支
        -> critic -> {reflect -> planner 回环 | report} -> END

安全钩子：
  - interrupt_before=["poc_verify"]：高危动作执行前挂起，人工批准后恢复
  - route_after_critic 受 max_iterations / max_reflections 约束防死循环
"""
from __future__ import annotations

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from secagent.config import CONFIG
from secagent.graph import nodes as N
from secagent.graph.state import AgentState
from secagent.llm.llm import ChatFn, make_chat
from secagent.memory.vector_store import make_store
from secagent.safety import AuditLogger, AuthorizationGate, CircuitBreaker, ROE
from secagent.tools.plugins import cve_lookup, fingerprint, malware_static, pcap, recon
from secagent.tools.registry import ToolBus, ToolMeta


def build_toolbus(roe: ROE, audit_path: str) -> ToolBus:
    """注册工具并绑定 安全三件套（授权门 / 熔断 / 审计）。"""
    gate = AuthorizationGate(roe)
    breaker = CircuitBreaker()
    audit = AuditLogger(audit_path)
    bus = ToolBus(gate, breaker, audit)

    import shutil
    scan_impl = recon.nmap_scan if shutil.which("nmap") else recon.fake_scan

    bus.register(ToolMeta("nmap_scan", "recon"), scan_impl)
    bus.register(ToolMeta("http_fingerprint", "fingerprint"), fingerprint.http_fingerprint)
    bus.register(ToolMeta("cve_enrich", "intel"),
                 lambda target, findings, **kw: cve_lookup.enrich_findings(findings))
    bus.register(ToolMeta("pcap_analyze", "analysis"), pcap.analyze_pcap)
    bus.register(ToolMeta("malware_static", "analysis", risk="high"), malware_static.static_analyze)
    bus.register(ToolMeta("poc_verify", "poc_verify", risk="high"), _poc_verify_impl)
    return bus


def _poc_verify_impl(target: str, finding: dict, **_: object) -> dict:
    """POC 验证实现：仅委托沙箱内验证脚本，沙箱不可用一律返回未确认。

    沙箱镜像内 /opt/verify/run.sh 输出含 CONFIRMED 才判定验证成功；
    保守默认：宁可不确认，不做未授权断言。
    """
    from secagent.safety import Sandbox
    try:
        sandbox = Sandbox()
        res = sandbox.run(["/opt/verify/run.sh", (finding.get("cves") or ["?"])[0], target])
        return {"confirmed": res.exit_code == 0 and "CONFIRMED" in res.stdout,
                "detail": res.stdout[:500]}
    except Exception as exc:  # noqa: BLE001
        return {"confirmed": False, "detail": f"sandbox unavailable: {exc}"[:200]}


def _fanout(state: dict) -> str | list[Send]:
    """vuln_scan / poc_verify 之后的动态扇出（Send API 并行分支）。"""
    if _needs_poc(state) and not state.get("human_approval"):
        return "poc_verify"                      # 先走审批中断分支
    task = state.get("task", {})
    sends: list[Send] = []
    if task.get("pcap_path"):
        sends.append(Send("pcap_analysis", dict(state)))
    if task.get("mode") in ("assess", "blue_sim"):
        sends.append(Send("lateral_sim", dict(state)))
    if task.get("mode") == "blue_sim":
        sends.append(Send("blue_sim", dict(state)))
    return sends or [Send("critic", dict(state))]


def _needs_poc(state: dict) -> bool:
    return any(f.get("cves") for f in state.get("findings", []))


def build_graph(chat: ChatFn | None = None, roe: ROE | None = None,
                audit_path: str | None = None, enable_interrupt: bool = True):
    """组装并编译图；返回 (app, bus, breaker)。"""
    chat = chat or make_chat()
    roe = roe or ROE.load(CONFIG.roe_path)
    audit_path = audit_path or CONFIG.audit_path
    bus = build_toolbus(roe, audit_path)
    store = make_store()
    breaker = bus.breaker

    g = StateGraph(AgentState)
    g.add_node("memory_recall", N.make_memory_node(store))
    g.add_node("planner", N.make_planner_node(chat))
    g.add_node("recon", N.make_recon_node(bus))
    g.add_node("fingerprint", N.make_fingerprint_node(bus, chat))
    g.add_node("vuln_scan", N.make_vulnscan_node(bus, chat))
    g.add_node("poc_verify", N.make_poc_verify_node(bus, chat))
    g.add_node("pcap_analysis", N.make_pcap_node(bus))
    g.add_node("lateral_sim", N.make_lateral_node())
    g.add_node("blue_sim", N.make_blue_node(chat))
    g.add_node("critic", N.make_critic_node(chat))
    g.add_node("reflect", N.make_reflector_node(chat))
    g.add_node("report", N.make_report_node(chat))

    g.add_edge(START, "memory_recall")
    g.add_edge("memory_recall", "planner")
    g.add_edge("planner", "recon")
    g.add_edge("recon", "fingerprint")
    g.add_edge("fingerprint", "vuln_scan")
    g.add_conditional_edges("vuln_scan", _fanout,
                            ["poc_verify", "pcap_analysis", "lateral_sim", "blue_sim", "critic"])
    g.add_conditional_edges("poc_verify", _fanout,
                            ["poc_verify", "pcap_analysis", "lateral_sim", "blue_sim", "critic"])
    for node in ("pcap_analysis", "lateral_sim", "blue_sim"):
        g.add_edge(node, "critic")
    g.add_conditional_edges("critic", N.route_after_critic, {"reflect": "reflect", "report": "report"})
    g.add_edge("reflect", "planner")
    g.add_edge("report", END)

    checkpointer = MemorySaver()
    interrupt_before = ["poc_verify"] if enable_interrupt else None
    app = g.compile(checkpointer=checkpointer, interrupt_before=interrupt_before)
    return app, bus, breaker
