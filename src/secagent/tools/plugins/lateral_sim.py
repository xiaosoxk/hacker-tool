# -*- coding: utf-8 -*-
"""横向移动路径推演：基于攻击图的概率建模（纯防御推演，不执行任何访问）。

建模（对应文档第 6 章）：
  节点 = 主机，含前置条件（可达性）与漏洞面（CVSS -> 利用成功概率 p）
  边   = 利用边 u -> v，边权 = P(success)
  目标 = 给定入口与目标主机，求最大成功概率路径 = 概率域最长路径
        转换：log(1/p) 作边权跑 Dijkstra（防连乘下溢）
"""
from __future__ import annotations

import math

# CVSS 分数 -> 利用成功概率的映射（工程经验校准，可按红队命中率回归修正）
def cvss_to_prob(score: float) -> float:
    if score >= 9.0:
        return 0.95
    if score >= 7.0:
        return 0.80
    if score >= 4.0:
        return 0.50
    return 0.15


def build_graph(hosts: dict[str, dict], links: list[tuple[str, str]]) -> dict:
    """hosts: {ip: {"cvss": 9.8|None, "creds": bool, "value": "core|normal"}}"""
    nodes = {}
    for ip, meta in hosts.items():
        score = meta.get("cvss") or 0.0
        nodes[ip] = {
            "p_own": cvss_to_prob(score) if score else 0.0,
            "has_creds": bool(meta.get("creds")),
            "value": meta.get("value", "normal"),
        }
    return {"nodes": nodes, "edges": [tuple(e) for e in links]}


def max_prob_path(graph: dict, entry: str, goal: str) -> dict:
    """最大成功概率路径：代价 = sum(log(1/p_edge))，Dijkstra 求最小代价。"""
    adjacency: dict[str, list[tuple[str, float]]] = {}
    for u, v in graph["edges"]:
        p = graph["nodes"].get(v, {}).get("p_own", 0.1)
        w = math.log(1 / max(p, 1e-6))
        adjacency.setdefault(u, []).append((v, w))

    import heapq
    best: dict[str, float] = {entry: 0.0}
    prev: dict[str, str] = {}
    heap = [(0.0, entry)]
    while heap:
        cost, node = heapq.heappop(heap)
        if cost > best.get(node, float("inf")):
            continue
        for nxt, w in adjacency.get(node, []):
            if cost + w < best.get(nxt, float("inf")):
                best[nxt] = cost + w
                prev[nxt] = node
                heapq.heappush(heap, (cost + w, nxt))

    if goal not in best:
        return {"reachable": False, "path": [], "prob": 0.0}

    path, cur = [goal], goal
    while cur != entry:
        cur = prev[cur]
        path.append(cur)
    path.reverse()

    prob = 1.0
    for node in path:                       # 含入口节点自身的攻陷概率
        prob *= graph["nodes"][node]["p_own"]
    return {"reachable": True, "path": path, "prob": round(prob, 4)}


def risk_assessment(graph: dict, entry: str, goals: list[str]) -> list[dict]:
    """对多个目标资产做风险排序：概率 x 资产价值权重。"""
    weight = {"core": 10.0, "normal": 1.0}
    rows = []
    for goal in goals:
        res = max_prob_path(graph, entry, goal)
        if res["reachable"]:
            w = weight.get(graph["nodes"].get(goal, {}).get("value", "normal"), 1.0)
            rows.append({"goal": goal, "prob": res["prob"], "value": w,
                         "risk": round(res["prob"] * w, 3), "path": res["path"]})
    rows.sort(key=lambda r: r["risk"], reverse=True)
    return rows
