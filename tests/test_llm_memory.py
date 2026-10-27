# -*- coding: utf-8 -*-
"""多模型评审与记忆检索测试。"""
import json

from secagent.llm.llm import FakeLLM
from secagent.llm.multi_model import review_findings
from secagent.memory.vector_store import LocalVectorStore, MemoryItem

REVIEW = json.dumps({"score": 82, "issues": ["证据不足"], "must_verify": ["CVE-1"], "verdict": "revise"})


def test_review_with_multiple_models():
    chat = FakeLLM(script={"评审员": REVIEW})
    out = review_findings(chat, ["m1", "m2", "m3"],
                          [{"id": "f1", "severity": "high", "summary": "x"}])
    assert out["verdict"] == "revise"
    assert out["score"] == 82
    assert len(chat.calls) == 3            # 每个评审模型各一次


def test_review_skipped_when_no_models():
    out = review_findings(FakeLLM(), [], [{"id": "f1"}])
    assert out["verdict"] == "skip"


def test_memory_roundtrip(tmp_path):
    store = LocalVectorStore()
    store.add(MemoryItem(id="1", kind="reflection", text="nmap 扫描需先做端口收敛"))
    store.add(MemoryItem(id="2", kind="finding", text="nginx 缺失 HSTS 头"))
    hits = store.search("扫描 端口", top_k=2)
    assert hits[0][0].id == "1"            # 语义相关性排序


def test_memory_kind_filter(tmp_path):
    store = LocalVectorStore()
    store.add(MemoryItem(id="1", kind="reflection", text="beacon 检测用 CV 阈值"))
    store.add(MemoryItem(id="2", kind="finding", text="beacon 外联告警"))
    hits = store.search("beacon", top_k=5, kind="finding")
    assert all(h[0].kind == "finding" for h in hits)
