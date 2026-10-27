# -*- coding: utf-8 -*-
"""报告生成插件：findings -> Markdown 评估报告。

结构固定：执行摘要、范围与授权、发现与风险、ATT&CK 映射、攻击路径、
加固建议。每个发现必须携带 evidence_id —— 无证据不报告（幻觉抑制闸门）。
"""
from __future__ import annotations

from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def generate_report(task: dict, findings: list[dict], attack_paths: list[dict],
                    reflections: list[str], **_: object) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "info"), 4))

    lines = [
        "# 安全评估报告",
        f"*生成时间：{now} · 由 Aegis Agent 自动生成，需人工复核后发布*",
        "",
        "## 1. 执行摘要",
        f"- 目标范围：{', '.join(task.get('targets', []))}",
        f"- 评估模式：{task.get('mode', 'assessment')}",
        f"- 发现总数：{len(findings)}（严重 {sum(1 for f in findings if f.get('severity') == 'critical')} /"
        f" 高 {sum(1 for f in findings if f.get('severity') == 'high')}）",
        "",
        "## 2. 授权与合规声明",
        f"- ROE 目标清单：{', '.join(task.get('roe_targets', []))}",
        "- 本报告仅覆盖授权范围内的目标与动作；证据均可溯源。",
        "",
        "## 3. 发现明细",
        "| # | 严重度 | 类型 | 目标 | 摘要 | 证据 |",
        "|---|--------|------|------|------|------|",
    ]
    for i, f in enumerate(findings, 1):
        lines.append(
            f"| {i} | {f.get('severity', 'info')} | {f.get('type', '-')} |"
            f" {f.get('target', '-')} | {f.get('summary', '')[:60]} | {f.get('evidence_id', '-')} |"
        )

    lines += ["", "## 4. 攻击路径推演（防御视角）"]
    if attack_paths:
        for p in attack_paths:
            lines.append(f"- 目标 {p['goal']}：成功概率 {p['prob']:.0%}，风险 {p['risk']}，"
                         f"路径 {' -> '.join(p['path'])}")
    else:
        lines.append("- 未构建攻击图（探测面不足或未授权）")

    lines += ["", "## 5. ATT&CK 映射", ""]
    tactics = sorted({t for f in findings for t in f.get("attack_tactics", [])})
    lines += [f"- {tactic}" for tactic in tactics] or ["- 无"]

    lines += ["", "## 6. 加固建议（优先级排序）", ""]
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. [{f.get('severity')}] {f.get('recommendation', '待补充')}")

    if reflections:
        lines += ["", "## 7. 过程反思记录（Reflexion）", ""]
        lines += [f"> {r}" for r in reflections[-5:]]

    return "\n".join(lines)
