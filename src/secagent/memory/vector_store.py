# -*- coding: utf-8 -*-
"""长期向量记忆：历史任务、发现、反思的语义检索。

双后端：chroma（可用时）或 local（NumPy 余弦，零依赖，测试默认）。
写入内容带元数据（task_id、kind、ts），检索按 kind 过滤。
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from secagent.config import CONFIG, MemoryConfig


@dataclass
class MemoryItem:
    id: str
    kind: str            # finding / reflection / task_summary / poc_note
    text: str
    meta: dict = field(default_factory=dict)


class LocalVectorStore:
    """零依赖实现：字符 n-gram 词袋 + 余弦相似度（测试与离线默认）。"""

    def __init__(self) -> None:
        self.items: list[MemoryItem] = []
        self._vectors: list[dict[str, float]] = []

    @staticmethod
    def _embed(text: str) -> dict[str, float]:
        grams = re.findall(r"[\w\u4e00-\u9fff]{2,4}", text.lower())
        counts: dict[str, float] = {}
        for g in grams:
            counts[g] = counts.get(g, 0.0) + 1.0
        norm = sum(v * v for v in counts.values()) ** 0.5 or 1.0
        return {k: v / norm for k, v in counts.items()}

    def add(self, item: MemoryItem) -> None:
        self.items.append(item)
        self._vectors.append(self._embed(item.text))

    def search(self, query: str, top_k: int = 5, kind: str | None = None) -> list[tuple[MemoryItem, float]]:
        q = self._embed(query)
        scored = []
        for item, vec in zip(self.items, self._vectors):
            if kind and item.kind != kind:
                continue
            score = sum(q.get(k, 0.0) * v for k, v in vec.items())
            scored.append((item, round(score, 4)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def save(self, path: str | None = None) -> None:
        path = path or os.path.join(CONFIG.memory.persist_dir, "store.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([{"id": i.id, "kind": i.kind, "text": i.text, "meta": i.meta}
                       for i in self.items], f, ensure_ascii=False)

    def load(self, path: str | None = None) -> None:
        path = path or os.path.join(CONFIG.memory.persist_dir, "store.json")
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            for row in json.load(f):
                self.add(MemoryItem(**row))


def make_store(cfg: MemoryConfig | None = None):
    cfg = cfg or CONFIG.memory
    if cfg.backend == "chroma":
        try:
            return _ChromaStore(cfg)
        except ImportError:
            pass
    store = LocalVectorStore()
    store.load()
    return store


class _ChromaStore:
    """Chroma 后端（可选）。接口与 LocalVectorStore 一致。"""

    def __init__(self, cfg: MemoryConfig) -> None:
        import chromadb  # type: ignore
        self.client = chromadb.PersistentClient(path=cfg.persist_dir)
        self.col = self.client.get_or_create_collection("aegis")

    def add(self, item: MemoryItem) -> None:
        self.col.add(ids=[item.id], documents=[item.text],
                     metadatas=[{"kind": item.kind, **item.meta}])

    def search(self, query: str, top_k: int = 5, kind: str | None = None) -> list[tuple[MemoryItem, float]]:
        where = {"kind": kind} if kind else None
        res = self.col.query(query_texts=[query], n_results=top_k, where=where)
        out = []
        for i, doc in enumerate(res["documents"][0]):
            out.append((MemoryItem(id=res["ids"][0][i], kind=res["metadatas"][0][i].get("kind", ""),
                                   text=doc), 1.0 - float(res["distances"][0][i])))
        return out

    def save(self) -> None:
        pass

    def load(self) -> None:
        pass
