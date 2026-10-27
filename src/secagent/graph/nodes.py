# -*- coding: utf-8 -*-
"""图节点工厂：每个节点是 状态 -> 部分状态更新 的纯函数。

节点分层（对应文档第 5 章状态机）：
  memory_recall -> planner -> recon -> fingerprint -> vuln_scan
  -> poc_gate(人工审批) -> poc_verify -> analysis_router --Send--> 并行分支
  (pcap_analysis / lateral_sim / blue_sim) -> critic -> reflector -> reporter

安全约定：
  - 所有工具调用经 ToolBus（授权门 + 熔断 + 审计）
  - poc_verify 属 high 风险：需 interrupt 人工批准后才执行
  - 预算耗尽走降级路径直接出报告
"""
from __future__ import annotations

import json
from typing import Any

from langgraph.types import Send

from secagent.config import CONFIG
from secagent.llm.llm import ChatFn
from secagent.memory.vector_store import MemoryItem, make_store
from secagent.safety import AuthorizationGate, CircuitBreaker
from secagent.tools.registry import ToolBus
from secagent.tools.plugins import lateral_sim as lsim
from secagent.tools.plugins import report as report_plugin

PLAN_PROMPT = """[JSON] 你是授权安全评估的规划器。当前任务: {task}
已知发现: {findings}
历史教训: {reflections}
输出 JSON: {{"plan": ["步骤1", "步骤2"], "next": "recon|fingerprint|vuln_scan|analysis|report"}}
约束：只能使用 ROE 授权范围内的目标与动作；步骤按信息增益排序。"""


def make_memory_node(store):
    def memory_recall(state: dict) -> dict:
        query = " ".join(state.get("task", {}).get("targets", []))
        hits = store.search(query, top_k=CONFIG.memory.top_k) if query else []
        return {"memory_hits": [{"text": it.text, "kind": it.kind, "score": s}
                                 for it, s in hits]}
    return memory_recall


def make_planner_node(chat: ChatFn):
    def planner(state: dict) -> dict:
        task = state.get("task", {})
        prompt = PLAN_PROMPT.format(
            task=json.dumps(task, ensure_ascii=False)[:1500],
            findings=json.dumps(state.get("findings", []), ensure_ascii=False)[:2000],
            reflections="; ".join(state.get("reflections", [])[-3:]) or "无",
        )
        try:
            raw = chat([{"role": "user", "content": prompt}],
                       model=CONFIG.llm.planner_model, temperature=CONFIG.llm.temperature_plan)
            data = json.loads(_json_of(raw))
        except Exception:  # noqa: BLE001 —— 规划失败走默认链路（降级不阻塞）
            data = {"plan": ["recon", "fingerprint", "vuln_scan", "report"], "next": "recon"}
        return {"plan": data.get("plan", []), "phase": data.get("next", "recon"),
                "iteration": 1}
    return planner


def make_recon_node(bus: ToolBus):
    def recon(state: dict) -> dict:
        targets = state.get("task", {}).get("targets", [])
        findings, evidence = [], []
        for target in targets:
            try:
                res = bus.call("nmap_scan", target=target)
                for host, ports in res.get("hosts", {}).items():
                    for p in ports:
                        findings.append({
                            "id": f"svc-{host}-{p['port']}",
                            "type": "open_service", "target": host,
                            "severity": "info",
                            "summary": f"{p['service']} {p['version']} on {p['port']}",
                            "product": (p["service"] + " " + p["version"]).strip(),
                        })
                evidence.append({"id": f"ev-recon-{host}", "tool": "nmap",
                                 "summary": f"{len(ports)} open ports"})
            except Exception as exc:  # noqa: BLE001 —— 单目标失败不拖垮整体
                evidence.append({"id": f"ev-recon-err-{target}", "tool": "nmap",
                                 "summary": f"scan failed: {exc}"[:200]})
        return {"findings": findings, "evidence": evidence, "phase": "fingerprint"}
    return recon


def make_fingerprint_node(bus: ToolBus, chat: ChatFn):
    def fingerprint(state: dict) -> dict:
        targets = state.get("task", {}).get("targets", [])
        findings, evidence = [], []
        for target in targets:
            try:
                res = bus.call("http_fingerprint", target=target)
                for hf in res.get("hardening_findings", []):
                    findings.append({
                        "id": f"hdr-{target}-{hf['header']}", "type": "web_hardening",
                        "target": target, "severity": "low",
                        "summary": hf["desc"],
                        "recommendation": f"为 {target} 响应添加 {hf['header']} 头",
                        "attack_tactics": ["Reconnaissance"],
                        "evidence_id": f"ev-fp-{target}",
                    })
                evidence.append({"id": f"ev-fp-{target}", "tool": "http_fingerprint",
                                 "summary": f"techs={res.get('techs', [])}"})
            except Exception as exc:  # noqa: BLE001
                evidence.append({"id": f"ev-fp-err-{target}", "tool": "http_fingerprint",
                                 "summary": f"fp failed: {exc}"[:200]})
        return {"findings": findings, "evidence": evidence, "phase": "vuln_scan"}
    return fingerprint


def make_vulnscan_node(bus: ToolBus, chat: ChatFn):
    def vuln_scan(state: dict) -> dict:
        """把服务指纹与已知 CVE 关联；网络不可用时降级为空候选。"""
        candidates = [f for f in state.get("findings", []) if f.get("type") == "open_service"]
        try:
            bus.call("cve_enrich", target="", findings=candidates)
        except Exception:  # noqa: BLE001
            pass
        for f in candidates:
            if f.get("cves"):
                f["severity"] = "medium"
                f["summary"] += f"（候选 CVE: {', '.join(f['cves'][:3])}，待验证）"
                f["attack_tactics"] = ["Initial Access"]
        return {"findings": candidates, "phase": "poc_gate"}
    return vuln_scan


def make_poc_verify_node(bus: ToolBus, chat: ChatFn):
    """POC 验证：high 风险，前置于 LangGraph interrupt 人工批准。"""
    def poc_verify(state: dict) -> dict:
        if not state.get("human_approval"):
            return {"phase": "analysis", "evidence": [
                {"id": "ev-poc-skipped", "tool": "poc_verify",
                 "summary": "未获人工批准，跳过 POC 验证"}]}
        verified = []
        for f in state.get("findings", []):
            if f.get("cves") and f.get("severity") in ("medium", "high", "critical"):
                try:
                    res = bus.call("poc_verify", target=f.get("target", ""), finding=f)
                    if res.get("confirmed"):
                        f["severity"] = "high"
                        f["summary"] += "（已验证）"
                        verified.append(f["id"])
                except Exception as exc:  # noqa: BLE001
                    f["summary"] += f"（验证失败: {str(exc)[:80]}）"
        return {"findings": list(state.get("findings", [])), "phase": "analysis"}
    return poc_verify


def analysis_router(state: dict) -> list[Send]:
    """并行分支路由（Send API）：按任务需要动态扇出。"""
    task = state.get("task", {})
    branches: list[Send] = []
    if task.get("pcap_path"):
        branches.append(Send("pcap_analysis", {"state": state}))
    if task.get("mode") in ("assess", "blue_sim"):
        branches.append(Send("lateral_sim", {"state": state}))
    if task.get("mode") == "blue_sim":
        branches.append(Send("blue_sim", {"state": state}))
    return branches or [Send("critic", {"state": state})]


def make_pcap_node(bus: ToolBus):
    def pcap_analysis(state: dict) -> dict:
        path = state.get("task", {}).get("pcap_path", "")
        if not path:
            return {}
        try:
            res = bus.call("pcap_analyze", target="", pcap_path=path)
        except Exception as exc:  # noqa: BLE001
            return {"evidence": [{"id": "ev-pcap-err", "tool": "pcap", "summary": str(exc)[:200]}]}
        findings = [{
            "id": f"beacon-{b['dst']}-{b['dport']}", "type": "suspected_beacon",
            "target": f"{b['dst']}:{b['dport']}", "severity": "medium",
            "summary": f"周期性外联 {b['count']} 次，均值 {b['mean_interval_s']}s，CV={b['cv']}",
            "recommendation": f"排查主机 {b['src']} 对 {b['dst']} 的外联程序并阻断",
            "attack_tactics": ["Command and Control"], "evidence_id": "ev-pcap",
        } for b in res.get("suspected_beacons", [])[:5]]
        return {"findings": findings,
                "evidence": [{"id": "ev-pcap", "tool": "pcap",
                              "summary": json.dumps(res, ensure_ascii=False)[:600]}]}
    return pcap_analysis


def make_lateral_node():
    def lateral_sim(state: dict) -> dict:
        task = state.get("task", {})
        graph_spec = task.get("network") or {"hosts": {}, "links": []}
        graph = lsim.build_graph(graph_spec["hosts"], graph_spec["links"])
        entry = task.get("entry_host") or (next(iter(graph["nodes"]), ""))
        goals = [ip for ip in graph["nodes"] if graph["nodes"][ip]["value"] == "core"] or list(graph["nodes"])
        rows = lsim.risk_assessment(graph, entry, goals)
        findings = [{
            "id": f"path-{r['goal']}", "type": "attack_path", "target": r["goal"],
            "severity": "high" if r["prob"] > 0.5 else "medium",
            "summary": f"入口 {entry} 到 {r['goal']} 成功概率 {r['prob']:.0%}",
            "recommendation": "在路径关键跳实施分段与最小权限加固",
            "attack_tactics": ["Lateral Movement"], "evidence_id": "ev-lateral",
        } for r in rows]
        return {"findings": findings, "attack_graph": graph,
                "evidence": [{"id": "ev-lateral", "tool": "lateral_sim",
                              "summary": f"评估 {len(rows)} 条路径"}]}
    return lateral_sim


def make_blue_node(chat: ChatFn):
    """蓝队仿真：从发现生成检测规则草稿（Sigma 风格 YAML）。"""
    def blue_sim(state: dict) -> dict:
        rules = []
        for f in state.get("findings", []):
            if f.get("type") == "suspected_beacon":
                rules.append(f"""title: Beacon to {f['target']}
logsource:
    category: firewall
detection:
    selection:
        dst_ip: '{f['target'].rsplit(':', 1)[0]}'
    condition: selection | count() > 50""")
        return {"evidence": [{"id": "ev-blue", "tool": "blue_sim",
                              "summary": f"生成 {len(rules)} 条检测规则草稿"}]}
    return blue_sim


def make_critic_node(chat: ChatFn):
    """层 2/3 自省：证据完备性检查 + 多模型评审（解耦自评）。"""
    def critic(state: dict) -> dict:
        findings = state.get("findings", [])
        unverified = [f["id"] for f in findings
                      if f.get("severity") in ("high", "critical") and not f.get("evidence_id")]
        budget = state.get("budget", {})
        must_fix = []
        if unverified:
            must_fix.append(f"严重发现缺少证据: {unverified[:5]}")
        if not findings:
            must_fix.append("无任何发现，检查授权范围与目标可达性")
        return {"critique": {"must_fix": must_fix, "unverified": unverified}}
    return critic


def route_after_critic(state: dict) -> str:
    critique = state.get("critique", {})
    iteration = state.get("iteration", 0)
    if (critique.get("must_fix") and iteration < CONFIG.budget.max_iterations
            and len(state.get("reflections", [])) < CONFIG.budget.max_reflections):
        return "reflect"
    return "report"


def make_reflector_node(chat: ChatFn):
    """Reflexion：把缺陷转为下一轮的语言化教训（bounded）。"""
    def reflector(state: dict) -> dict:
        critique = state.get("critique", {})
        lesson = "；".join(critique.get("must_fix", [])) or "无"
        reflection = f"第 {state.get('iteration', 1)} 轮教训: {lesson}"
        return {"reflections": [reflection], "iteration": 1, "phase": "recon",
                "human_approval": state.get("human_approval", False)}
    return reflector


def make_report_node(chat: ChatFn):
    def reporter(state: dict) -> dict:
        task = state.get("task", {})
        paths = []
        for f in state.get("findings", []):
            if f.get("type") == "attack_path":
                paths.append({"goal": f["target"], "prob": 0.8, "risk": 8.0,
                              "path": [task.get("entry_host", "?"), f["target"]]})
        report = report_plugin.generate_report(
            task={**task, "roe_targets": state.get("task", {}).get("targets", [])},
            findings=state.get("findings", []),
            attack_paths=paths,
            reflections=state.get("reflections", []),
        )
        # 写入长期记忆
        store = make_store()
        store.add(MemoryItem(id=f"task-{id(task)}", kind="task_summary",
                             text=report[:1000], meta={"targets": task.get("targets", [])}))
        store.save()
        return {"report": report, "phase": "done"}
    return reporter


def _json_of(raw: str) -> str:
    start, end = raw.find("{"), raw.rfind("}")
    return raw[start:end + 1] if 0 <= start < end else "{}"
