# -*- coding: utf-8 -*-
"""ROE 授权门：智能体的第一优先级安全组件。

所有目标类动作（扫描、验证、访问）在执行前必须通过 `AuthorizationGate.check`，
未授权目标直接抛出 AuthorizationError —— 硬约束优先于任务目标，
任何节点都不得以「任务需要」为由绕过。
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Any

import yaml


class AuthorizationError(PermissionError):
    """目标或动作不在 ROE 授权范围内。"""


@dataclass
class ROE:
    """Rules of Engagement：书面授权的结构化表达。

    allowed_targets: 允许的目标（CIDR、单 IP、域名通配，如 *.lab.example.com）
    allowed_actions: 允许的动作类型（recon/fingerprint/vuln_scan/poc_verify/...）
    denied_actions:  显式禁止动作，优先级高于 allowed_actions
    max_requests_per_host: 单主机请求频次上限（防失控）
    time_window:     允许执行的时间窗（ISO 日期字符串）
    """

    allowed_targets: list[str] = field(default_factory=list)
    allowed_actions: list[str] = field(default_factory=list)
    denied_actions: list[str] = field(default_factory=list)
    max_requests_per_host: int = 2000
    time_window: dict[str, str] | None = None

    @classmethod
    def load(cls, path: str) -> "ROE":
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        return cls(**data.get("roe", data))


class AuthorizationGate:
    def __init__(self, roe: ROE) -> None:
        self.roe = roe
        self._request_counts: dict[str, int] = {}

    # ---- 目标校验 -------------------------------------------------------
    def check_target(self, target: str) -> None:
        """target 可以是 IP/CIDR/域名。任一 ROE 条目命中即放行，否则抛错。"""
        for entry in self.roe.allowed_targets:
            if self._match(entry, target):
                return
        raise AuthorizationError(f"target [{target}] 不在 ROE 授权范围 {self.roe.allowed_targets} 内")

    @staticmethod
    def _match(entry: str, target: str) -> bool:
        entry, target = entry.strip(), target.strip()
        # CIDR 精确匹配（含掩码语义，不做宽松包含）
        if "/" in entry:
            try:
                return ipaddress.ip_address(target) in ipaddress.ip_network(entry, strict=False)
            except ValueError:
                return False
        # 单 IP 相等
        try:
            if ipaddress.ip_address(entry) == ipaddress.ip_address(target):
                return True
        except ValueError:
            pass
        # 域名通配（*.lab.example.com）
        return fnmatch.fnmatch(target.lower(), entry.lower())

    # ---- 动作校验 -------------------------------------------------------
    def check_action(self, action: str) -> None:
        if action in self.roe.denied_actions:
            raise AuthorizationError(f"action [{action}] 被 ROE 显式禁止")
        if self.roe.allowed_actions and action not in self.roe.allowed_actions:
            raise AuthorizationError(f"action [{action}] 不在允许清单 {self.roe.allowed_actions} 内")

    # ---- 频次闸门 -------------------------------------------------------
    def acquire(self, host: str, action: str) -> None:
        """组合校验 + 频次记账；任何工具调用前调用一次。"""
        self.check_action(action)
        count = self._request_counts.get(host, 0) + 1
        if count > self.roe.max_requests_per_host:
            raise AuthorizationError(f"host [{host}] 请求次数 {count} 超过 ROE 上限")
        self._request_counts[host] = count

    def snapshot(self) -> dict[str, Any]:
        return {"counts": dict(self._request_counts), "roe_targets": list(self.roe.allowed_targets)}
