# -*- coding: utf-8 -*-
"""LLM 抽象层：OpenAI 兼容接口 + 离线 FakeLLM（测试用）。

分层路由（与文档第 2、7 章对应）：
  planner -> 强模型（低温度 0.2）：任务分解、决策
  worker  -> 快模型（温度 0.0）：抽取、摘要、格式化
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Protocol

from secagent.config import CONFIG


class ChatFn(Protocol):
    def __call__(self, messages: list[dict[str, str]], *, model: str, temperature: float) -> str: ...


@dataclass
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class OpenAICompatChat:
    """OpenAI 兼容 chat.completions 调用；记录用量供预算熔断。"""

    def __init__(self) -> None:
        self.usage = Usage()
        self._client = None

    def _ensure_client(self) -> Any:
        if self._client is None:
            from openai import OpenAI  # 延迟导入：离线测试无需安装
            base = CONFIG.llm.api_base or None
            self._client = OpenAI(api_key=CONFIG.llm.api_key or os.environ.get("OPENAI_API_KEY", "sk-x"),
                                  base_url=base)
        return self._client

    def __call__(self, messages: list[dict[str, str]], *, model: str, temperature: float) -> str:
        client = self._ensure_client()
        resp = client.chat.completions.create(
            model=model, messages=messages, temperature=temperature,
            response_format={"type": "json_object"} if messages and messages[-1].get("content", "").startswith("[JSON]") else None,
        )
        if resp.usage:
            self.usage.prompt_tokens += resp.usage.prompt_tokens or 0
            self.usage.completion_tokens += resp.usage.completion_tokens or 0
        return resp.choices[0].message.content or ""


class FakeLLM:
    """离线确定性 LLM：按脚本关键词返回固定 JSON，用于无网络测试。"""

    def __init__(self, script: dict[str, str] | None = None) -> None:
        self.script = script or {}
        self.usage = Usage()
        self.calls: list[list[dict[str, str]]] = []

    def __call__(self, messages: list[dict[str, str]], *, model: str, temperature: float) -> str:
        self.calls.append(messages)
        self.usage.prompt_tokens += sum(len(m.get("content", "")) // 4 for m in messages)
        self.usage.completion_tokens += 50
        text = " ".join(m.get("content", "") for m in messages)
        for key, resp in self.script.items():
            if key in text:
                return resp
        return json.dumps({"note": "fake-default"}, ensure_ascii=False)


def make_chat() -> ChatFn:
    """根据环境选择真实/离线实现。AEGIS_OFFLINE=1 时强制离线。"""
    if os.environ.get("AEGIS_OFFLINE", "1") == "1":
        return FakeLLM()
    return OpenAICompatChat()
