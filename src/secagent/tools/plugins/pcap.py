# -*- coding: utf-8 -*-
"""PCAP 深度分析插件（scapy 实现）。

能力：协议统计、HTTP/DNS 资产提取、外联 IP 汇总、周期性外联（beacon）
检测——用「分组间隔的变异系数 CV」判定规律性心跳（与文档第 11 章呼应）。
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict

from scapy.all import IP, DNS, TCP, UDP, Raw, rdpcap  # type: ignore


def analyze_pcap(target: str = "", pcap_path: str = "", cv_threshold: float = 0.35, **_: object) -> dict:
    packets = rdpcap(pcap_path)
    flows: dict[tuple, list[float]] = defaultdict(list)
    dns_queries: Counter = Counter()
    http_targets: Counter = Counter()
    proto_counter: Counter = Counter()
    bytes_by_dst: Counter = Counter()

    for pkt in packets:
        if IP not in pkt:
            continue
        ip = pkt[IP]
        proto_counter[ip.proto] += 1
        bytes_by_dst[ip.dst] += len(pkt)
        if TCP in pkt:
            flows[(ip.src, ip.dst, pkt[TCP].dport)].append(float(pkt.time))
            payload = bytes(pkt[TCP].payload)
            if payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE"):
                host = _header(payload, b"Host:")
                if host:
                    http_targets[host] += 1
        elif UDP in pkt:
            if DNS in pkt:
                q = pkt[DNS].qd.qname.decode("utf-8", "ignore").rstrip(".") if pkt[DNS].qd else ""
                if q:
                    dns_queries[q] += 1
            else:
                flows[(ip.src, ip.dst, pkt[UDP].dport)].append(float(pkt.time))

    beacons = _detect_beacons(flows, cv_threshold)
    return {
        "packet_count": len(packets),
        "proto_stats": {str(k): v for k, v in proto_counter.items()},
        "top_talkers": dict(bytes_by_dst.most_common(10)),
        "dns_queries": dict(dns_queries.most_common(20)),
        "http_hosts": dict(http_targets.most_common(20)),
        "suspected_beacons": beacons,
    }


def _detect_beacons(flows: dict, cv_threshold: float) -> list[dict]:
    """对每条流计算分组时间间隔的变异系数：CV 小 + 次数多 = 规律心跳。"""
    out = []
    for (src, dst, port), times in flows.items():
        if len(times) < 8:
            continue
        gaps = [b - a for a, b in zip(sorted(times), sorted(times)[1:])]
        if not gaps:
            continue
        mean = statistics.fmean(gaps)
        if mean <= 0:
            continue
        cv = (statistics.pstdev(gaps) / mean) if mean else float("inf")
        if cv < cv_threshold:
            out.append({
                "src": src, "dst": dst, "dport": int(port),
                "count": len(times), "mean_interval_s": round(mean, 2),
                "cv": round(cv, 3), "verdict": "suspected_beacon",
            })
    out.sort(key=lambda x: x["count"], reverse=True)
    return out


def _header(payload: bytes, name: bytes) -> str:
    idx = payload.lower().find(name.lower())
    if idx < 0:
        return ""
    line = payload[idx + len(name): payload.find(b"\r\n", idx)]
    return line.strip().decode("utf-8", "ignore")[:100]
