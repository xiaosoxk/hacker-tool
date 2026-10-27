# -*- coding: utf-8 -*-
"""审计日志：append-only JSONL，记录每次动作供回放与追责。

一条审计记录：
  {"ts": ..., "actor": "node/recon", "action": "nmap_scan",
   "target": "10.0.0.5", "args": {...}, "result": "ok",
   "detail_hash": "sha256:...", "duration_ms": 123}
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any


class AuditLogger:
    def __init__(self, path: str) -> None:
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def log(
        self,
        actor: str,
        action: str,
        target: str = "",
        args: dict[str, Any] | None = None,
        result: str = "ok",
        detail: Any = None,
        duration_ms: int = 0,
    ) -> dict[str, Any]:
        record = {
            "ts": time.time(),
            "actor": actor,
            "action": action,
            "target": target,
            "args": args or {},
            "result": result,
            "detail_hash": self._hash(detail),
            "duration_ms": duration_ms,
        }
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        return record

    @staticmethod
    def _hash(detail: Any) -> str:
        raw = json.dumps(detail, ensure_ascii=False, default=str, sort_keys=True).encode("utf-8")
        return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]

    def replay(self, actor: str | None = None, action: str | None = None) -> list[dict[str, Any]]:
        """按 actor/action 过滤回放审计记录。"""
        if not os.path.exists(self.path):
            return []
        out = []
        with open(self.path, encoding="utf-8") as f:
            for line in f:
                rec = json.loads(line)
                if actor and rec["actor"] != actor:
                    continue
                if action and rec["action"] != action:
                    continue
                out.append(rec)
        return out
