# -*- coding: utf-8 -*-
"""全局配置：从环境变量与 ROE 文件加载。"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes")


@dataclass
class LLMConfig:
    """主模型与评审模型的分层路由配置。"""

    planner_model: str = field(default_factory=lambda: os.environ.get("AEGIS_PLANNER_MODEL", "gpt-4o"))
    worker_model: str = field(default_factory=lambda: os.environ.get("AEGIS_WORKER_MODEL", "gpt-4o-mini"))
    reviewer_models: list[str] = field(
        default_factory=lambda: [m for m in os.environ.get("AEGIS_REVIEWERS", "").split(",") if m]
    )
    api_base: str = field(default_factory=lambda: os.environ.get("AEGIS_API_BASE", ""))
    api_key: str = field(default_factory=lambda: os.environ.get("AEGIS_API_KEY", ""))
    temperature_plan: float = float(os.environ.get("AEGIS_TEMP_PLAN", "0.2"))
    temperature_worker: float = float(os.environ.get("AEGIS_TEMP_WORKER", "0.0"))


@dataclass
class BudgetConfig:
    """Token 与动作预算，超限触发熔断（见 safety/circuit_breaker.py）。"""

    max_tokens: int = int(os.environ.get("AEGIS_MAX_TOKENS", "400000"))
    max_tool_calls: int = int(os.environ.get("AEGIS_MAX_TOOL_CALLS", "300"))
    max_iterations: int = int(os.environ.get("AEGIS_MAX_ITERATIONS", "25"))
    max_reflections: int = int(os.environ.get("AEGIS_MAX_REFLECTIONS", "4"))


@dataclass
class SandboxConfig:
    """隔离沙箱配置：与 deploy/docker-compose.yml 中的隔离网络对应。"""

    enabled: bool = field(default_factory=lambda: _bool("AEGIS_SANDBOX", True))
    image: str = field(default_factory=lambda: os.environ.get("AEGIS_SANDBOX_IMAGE", "aegis-sandbox:latest"))
    network: str = field(default_factory=lambda: os.environ.get("AEGIS_SANDBOX_NET", "aegis_sandbox"))
    mem_limit: str = "512m"
    pids_limit: int = 128
    timeout_seconds: int = 120


@dataclass
class MemoryConfig:
    """长期向量记忆配置；无外部依赖时退化为内存余弦检索。"""

    backend: str = field(default_factory=lambda: os.environ.get("AEGIS_MEMORY_BACKEND", "local"))
    persist_dir: str = field(default_factory=lambda: os.environ.get("AEGIS_MEMORY_DIR", "./data/memory"))
    top_k: int = int(os.environ.get("AEGIS_MEMORY_TOPK", "5"))


@dataclass
class KaliConfig:
    """Kali 联动配置：local（运行环境即 Kali）/ docker（隔离容器）/ ssh（远程 Kali 机）。"""

    enabled: bool = field(default_factory=lambda: _bool("AEGIS_KALI", False))
    mode: str = field(default_factory=lambda: os.environ.get("AEGIS_KALI_MODE", "docker"))
    container: str = field(default_factory=lambda: os.environ.get("AEGIS_KALI_CONTAINER", "aegis-kali"))
    host: str = field(default_factory=lambda: os.environ.get("AEGIS_KALI_HOST", ""))
    user: str = field(default_factory=lambda: os.environ.get("AEGIS_KALI_USER", "kali"))
    key: str = field(default_factory=lambda: os.environ.get("AEGIS_KALI_KEY", ""))
    port: int = int(os.environ.get("AEGIS_KALI_PORT", "22"))
    wordlist: str = field(default_factory=lambda: os.environ.get(
        "AEGIS_KALI_WORDLIST", "/usr/share/seclists/Discovery/Web-Content/common.txt"))
    timeout: int = int(os.environ.get("AEGIS_KALI_TIMEOUT", "300"))


@dataclass
class Config:
    llm: LLMConfig = field(default_factory=LLMConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    sandbox: SandboxConfig = field(default_factory=SandboxConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    kali: KaliConfig = field(default_factory=KaliConfig)
    # 审计日志路径（append-only JSONL）
    audit_path: str = field(default_factory=lambda: os.environ.get("AEGIS_AUDIT", "./data/audit.log"))
    # ROE 授权文件（YAML）：允许的目标与动作白名单
    roe_path: str = field(default_factory=lambda: os.environ.get("AEGIS_ROE", "./roe.yaml"))


CONFIG = Config()
