# -*- coding: utf-8 -*-
"""多模型协同评审（Self-Critique 解耦实现）。

设计要点（对应文档第 3、14 章）：
  - 评审模型与执行模型分离，避免自评偏高（自我确认偏差）
  - 多评审独立打分 -> 规则聚合（去极值均值 + 一票否决项）
  - 评审输出强制结构化：score / issues / must_verify
"""
from __future__ import annotations

import json
import statistics
from typing import Any

from secagent.llm.llm import ChatFn

REVIEW_PROMPT = """[JSON] 你是安全评估报告的独立评审员（与执行者无关）。评审以下发现：
{payload}

输出 JSON：{{"score": 0-100, "issues": ["..."], "must_verify": ["..."], "verdict": "accept|revise|reject"}}
评分维度：证据充分性(40)、技术正确性(30)、风险定级合理性(30)。"""


def review_findings(chat: ChatFn, models: list[str], findings: list[dict]) -> dict[str, Any]:
    """多模型评审；models 为空时返回 skip 结果（离线模式）。"""
    if not models:
        return {"verdict": "skip", "score": None, "issues": [], "must_verify": []}

    payload = json.dumps(findings, ensure_ascii=False)[:6000]
    scores: list[float] = []
    issues: list[str] = []
    must_verify: list[str] = []
    verdicts: list[str] = []

    for model in models:
        try:
            raw = chat([{"role": "user", "content": REVIEW_PROMPT.format(payload=payload)}],
                       model=model, temperature=0.0)
            data = json.loads(_extract_json(raw))
            scores.append(float(data.get("score", 50)))
            issues.extend(data.get("issues", [])[:5])
            must_verify.extend(data.get("must_verify", [])[:5])
            verdicts.append(data.get("verdict", "revise"))
        except Exception:  # noqa: BLE001  单评审失败不阻塞，记录即可
            issues.append(f"评审模型 {model} 不可用")
            verdicts.append("revise")

    # 去极值均值：>2 个评审时去掉最高最低，抗单模型偏见
    trimmed = scores[1:-1] if len(scores) > 2 else scores
    avg = round(statistics.fmean(trimmed), 1) if trimmed else None
    final = "reject" if verdicts.count("reject") >= 2 else ("accept" if verdicts.count("accept") > len(verdicts) / 2 else "revise")
    return {"verdict": final, "score": avg, "issues": list(dict.fromkeys(issues))[:8],
            "must_verify": list(dict.fromkeys(must_verify))[:8]}


def _extract_json(raw: str) -> str:
    start, end = raw.find("{"), raw.rfind("}")
    return raw[start:end + 1] if 0 <= start < end else "{}"
