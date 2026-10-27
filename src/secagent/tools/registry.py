# -*- coding: utf-8 -*-
"""工具总线：所有工具调用的唯一通道。

每次调用强制经过：授权门 -> 熔断器 -> 审计日志。绕过总线的直连调用
在代码评审中视为安全缺陷（与文档第 13 章的多级权限隔离对应）。
"""
from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from secagent.safety import AuditLogger, AuthorizationGate, CircuitBreaker


@dataclass
class ToolMeta:
    name: str
    action: str            # ROE 动作类型（recon/fingerprint/...）
    risk: str = "low"      # low / medium / high（high 需人工审批 + 沙箱）


class ToolBus:
    def __init__(
        self,
        gate: AuthorizationGate,
        breaker: CircuitBreaker,
        audit: AuditLogger,
        require_approval: Callable[[str, str], bool] | None = None,
    ) -> None:
        self.gate = gate
        self.breaker = breaker
        self.audit = audit
        self._tools: dict[str, tuple[ToolMeta, Callable[..., Any]]] = {}
        self.require_approval = require_approval or (lambda action, target: False)

    def register(self, meta: ToolMeta, fn: Callable[..., Any]) -> None:
        self._tools[meta.name] = (meta, fn)

    def call(self, name: str, target: str = "", **kwargs: Any) -> Any:
        if name not in self._tools:
            raise KeyError(f"未注册的工具: {name}")
        meta, fn = self._tools[name]

        # 1) 授权门：目标 + 动作 + 频次
        self.gate.check_target(target) if target else None
        self.gate.acquire(target or "-", meta.action)

        # 2) 高危动作需人工批准（配合 LangGraph interrupt 使用）
        if meta.risk == "high" and not self.require_approval(meta.action, target):
            raise PermissionError(f"高危动作 [{name}] 需人工批准后方可执行")

        # 3) 熔断
        if not self.breaker.allow(name):
            self.audit.log(actor="toolbus", action=name, target=target,
                           result="breaker_open", detail={"kwargs": kwargs})
            raise RuntimeError(f"工具 [{name}] 处于熔断状态")

        # 4) 执行 + 审计（约定：所有工具函数第一个参数为 target）
        t0 = time.time()
        try:
            result = fn(target=target, **kwargs)
            self.breaker.record_success(name)
            self.audit.log(actor="toolbus", action=name, target=target, args=kwargs,
                           result="ok", detail=_summarize(result),
                           duration_ms=int((time.time() - t0) * 1000))
            return result
        except Exception as exc:  # noqa: BLE001
            self.breaker.record_failure(name)
            self.audit.log(actor="toolbus", action=name, target=target, args=kwargs,
                           result=f"error:{type(exc).__name__}", detail=str(exc)[:500],
                           duration_ms=int((time.time() - t0) * 1000))
            raise


def _summarize(result: Any, limit: int = 4000) -> Any:
    """审计日志存摘要而非全量输出，控制日志体积。"""
    text = result if isinstance(result, str) else str(result)
    return text[:limit]
