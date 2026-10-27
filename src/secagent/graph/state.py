# -*- coding: utf-8 -*-
"""AgentState：多分支状态机的单一事实源（Single Source of Truth）。

对应文档第 5 章的状态转移方程：
  s' = δ(s, node(s, obs))

LangGraph 的 Annotated reducer 定义了并发写入的合并规则：
  - findings / evidence: 按 id 去重合并（多分支并行的关键）
  - messages:            append（对话轨迹）
  - iteration 等标量:     last_value（后写覆盖）
"""
from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

from langgraph.graph.message import add_messages


def merge_by_id(left: list[dict], right: list[dict]) -> list[dict]:
    """按 id 去重的列表合并 reducer（并行分支安全）。"""
    seen: dict[str, dict] = {item["id"]: item for item in left if isinstance(item, dict) and "id" in item}
    for item in right:
        if isinstance(item, dict) and "id" in item:
            seen[item["id"]] = item          # 新值覆盖同 id
        else:
            seen[str(len(seen))] = item
    return list(seen.values())


def append_int(left: int | None, right: int | None) -> int:
    return (left or 0) + (right or 0)


class AgentState(TypedDict, total=False):
    # ---- 对话与任务 ------------------------------------------------------
    messages: Annotated[list, add_messages]
    task: dict[str, Any]                  # {"objective", "targets", "mode", ...}
    phase: Literal[
        "init", "recon", "fingerprint", "vuln_scan", "poc_verify",
        "analysis", "detection", "reporting", "done", "blocked",
    ]

    # ---- 计划与迭代 ------------------------------------------------------
    plan: list[str]                       # 当前任务计划（Plan-and-Execute）
    iteration: Annotated[int, append_int]  # 全局迭代计数
    reflections: Annotated[list[str], operator.add]  # Reflexion 教训（只增）

    # ---- 结果数据（并行分支合并）-----------------------------------------
    findings: Annotated[list[dict], merge_by_id]     # 漏洞/风险发现
    evidence: Annotated[list[dict], merge_by_id]     # 证据（含原始输出摘要）
    attack_graph: dict[str, Any]          # {"nodes": {...}, "edges": [...]} 攻击路径图
    memory_hits: list[dict]               # 长期记忆检索命中

    # ---- 安全与预算 ------------------------------------------------------
    audit_refs: Annotated[list[dict], operator.add]  # 审计记录引用
    budget: dict[str, Any]                # 熔断与预算快照
    critique: dict[str, Any]              # 评审输出（must_fix / unverified）
    human_approval: bool                  # 高危动作是否已获人工批准（interrupt 恢复后置位）

    # ---- 输出 ------------------------------------------------------------
    report: str                           # 最终 Markdown 报告


def initial_state(task: dict[str, Any]) -> AgentState:
    return AgentState(
        messages=[],
        task=task,
        phase="init",
        plan=[],
        iteration=0,
        reflections=[],
        findings=[],
        evidence=[],
        attack_graph={"nodes": {}, "edges": []},
        memory_hits=[],
        audit_refs=[],
        budget={},
        critique={},
        human_approval=False,
        report="",
    )
