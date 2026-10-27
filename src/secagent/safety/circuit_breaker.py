# -*- coding: utf-8 -*-
"""动作熔断器：失败率 / 频次 / 预算任一超限即熔断。

三态模型（与电子断路器同构）：
  CLOSED   -> 正常放行，滚动统计失败
  OPEN     -> 直接拒绝，冷却期内不再尝试
  HALF_OPEN-> 冷却结束，放行一次探测，成功则恢复
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BreakerState(str, Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class BreakerPolicy:
    failure_threshold: int = 5        # 连续失败 N 次进入 OPEN
    cooldown_seconds: float = 60.0    # OPEN 持续时间
    half_open_max_probe: int = 1      # HALF_OPEN 允许的探测次数


@dataclass
class TokenBudget:
    """Token / 工具调用预算（对应文档第 7 章 Token 经济的工程闸门）。"""

    max_tokens: int = 400_000
    max_tool_calls: int = 300
    tokens_used: int = 0
    tool_calls: int = 0

    def charge(self, tokens: int = 0, tool_calls: int = 0) -> None:
        self.tokens_used += tokens
        self.tool_calls += tool_calls

    def exhausted(self) -> bool:
        return self.tokens_used >= self.max_tokens or self.tool_calls >= self.max_tool_calls

    def snapshot(self) -> dict[str, Any]:
        return {
            "tokens_used": self.tokens_used,
            "max_tokens": self.max_tokens,
            "tool_calls": self.tool_calls,
            "max_tool_calls": self.max_tool_calls,
        }


class CircuitBreaker:
    """按工具名隔离的熔断器集合；单工具故障不拖垮全局。"""

    def __init__(self, policy: BreakerPolicy | None = None, budget: TokenBudget | None = None) -> None:
        self.policy = policy or BreakerPolicy()
        self.budget = budget or TokenBudget()
        self._states: dict[str, dict[str, Any]] = {}

    def _state(self, key: str) -> dict[str, Any]:
        return self._states.setdefault(
            key, {"state": BreakerState.CLOSED, "failures": 0, "opened_at": 0.0, "probes": 0}
        )

    def allow(self, key: str) -> bool:
        """是否允许本次调用；预算耗尽对所有 key 生效。"""
        if self.budget.exhausted():
            return False
        s = self._state(key)
        if s["state"] is BreakerState.CLOSED:
            return True
        if s["state"] is BreakerState.OPEN:
            if time.time() - s["opened_at"] >= self.policy.cooldown_seconds:
                s["state"] = BreakerState.HALF_OPEN
                s["probes"] = 0
            else:
                return False
        # HALF_OPEN
        if s["probes"] < self.policy.half_open_max_probe:
            s["probes"] += 1
            return True
        return False

    def record_success(self, key: str) -> None:
        s = self._state(key)
        s["state"] = BreakerState.CLOSED
        s["failures"] = 0

    def record_failure(self, key: str) -> None:
        s = self._state(key)
        s["failures"] += 1
        if s["failures"] >= self.policy.failure_threshold:
            s["state"] = BreakerState.OPEN
            s["opened_at"] = time.time()

    def snapshot(self) -> dict[str, Any]:
        return {
            "breakers": {k: v["state"].value for k, v in self._states.items()},
            "budget": self.budget.snapshot(),
        }
