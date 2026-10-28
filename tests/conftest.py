# -*- coding: utf-8 -*-
"""测试公共夹具：离线 ROE、FakeLLM、内存审计、样例 PCAP 生成。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from secagent.llm.llm import FakeLLM  # noqa: E402
from secagent.safety import AuditLogger, AuthorizationGate, CircuitBreaker, ROE  # noqa: E402
from secagent.tools.registry import ToolBus, ToolMeta  # noqa: E402
from secagent.tools.plugins import recon  # noqa: E402

TEST_ROE = {
    "roe": {
        "allowed_targets": ["10.60.0.0/24", "*.lab.example.com"],
        "allowed_actions": ["recon", "fingerprint", "intel", "analysis", "vuln_scan",
                            "poc_verify", "report"],
        "denied_actions": ["denial_of_service", "data_exfiltration"],
        "max_requests_per_host": 500,
    }
}


@pytest.fixture()
def roe(tmp_path: Path) -> ROE:
    p = tmp_path / "roe.yaml"
    p.write_text(yaml.safe_dump(TEST_ROE), encoding="utf-8")
    return ROE.load(str(p))


@pytest.fixture()
def audit(tmp_path: Path) -> AuditLogger:
    return AuditLogger(str(tmp_path / "audit.log"))


@pytest.fixture()
def gate(roe: ROE) -> AuthorizationGate:
    return AuthorizationGate(roe)


@pytest.fixture()
def breaker() -> CircuitBreaker:
    return CircuitBreaker()


@pytest.fixture()
def bus(gate: AuthorizationGate, breaker: CircuitBreaker, audit: AuditLogger) -> ToolBus:
    b = ToolBus(gate, breaker, audit)
    b.register(ToolMeta("nmap_scan", "recon"), recon.fake_scan)
    return b


@pytest.fixture()
def fake_llm() -> FakeLLM:
    return FakeLLM(script={
        "规划器": '{"plan": ["recon", "fingerprint", "vuln_scan", "report"], "next": "recon"}',
        "评审员": '{"score": 85, "issues": [], "must_verify": [], "verdict": "accept"}',
    })


SAMPLE_TASK = {
    "objective": "对授权实验网段做安全评估",
    "targets": ["10.60.0.11"],
    "mode": "assess",
    "entry_host": "10.60.0.11",
    "network": {
        "hosts": {
            "10.60.0.11": {"cvss": 7.5, "value": "normal"},
            "10.60.0.20": {"cvss": 9.8, "value": "core"},
            "10.60.0.30": {"cvss": 3.1, "value": "normal"},
        },
        "links": [["10.60.0.11", "10.60.0.20"], ["10.60.0.11", "10.60.0.30"],
                  ["10.60.0.20", "10.60.0.30"]],
    },
}


def make_sample_pcap(path) -> None:
    """构造含规律心跳外联的样例 PCAP（beacon 检测测试用）。"""
    from scapy.all import IP, TCP, Ether, wrpcap  # noqa: PLC0415

    pkts = []
    ts = 1_700_000_000.0
    for i in range(30):  # 每 10 秒一次外联，持续 300 秒
        pkts.append(Ether() / IP(src="10.60.0.11", dst="198.51.100.9") /
                    TCP(sport=45000 + i, dport=443, flags="PA") / b"\x17\x03\x03\x00\x20beacon")
        pkts[-1].time = ts + i * 10.0
    # 背景流量：同一目标的随机间隔，不应命中
    import random
    random.seed(42)
    t = ts
    for i in range(10):
        t += random.uniform(1, 200)
        pkts.append(Ether() / IP(src="10.60.0.11", dst="198.51.100.8") /
                    TCP(sport=46000 + i, dport=80, flags="PA") / b"GET / HTTP/1.1")
        pkts[-1].time = t
    wrpcap(str(path), pkts)
