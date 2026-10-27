# -*- coding: utf-8 -*-
"""PCAP 分析插件测试：beacon 检测的查全与查准。"""


def test_beacon_detected(tmp_path, monkeypatch):
    from conftest import make_sample_pcap
    from secagent.tools.plugins.pcap import analyze_pcap

    pcap = tmp_path / "sample.pcap"
    make_sample_pcap(pcap)
    res = analyze_pcap(pcap_path=str(pcap))

    dsts = {b["dst"] for b in res["suspected_beacons"]}
    assert "198.51.100.9" in dsts            # 规律心跳命中
    assert "198.51.100.8" not in dsts        # 随机间隔不误报
    beacon = next(b for b in res["suspected_beacons"] if b["dst"] == "198.51.100.9")
    assert beacon["count"] >= 25
    assert beacon["cv"] < 0.35
    assert res["packet_count"] == 40


def test_empty_pcap(tmp_path):
    from scapy.all import Ether, IP, wrpcap  # noqa: PLC0415

    pcap = tmp_path / "empty.pcap"
    wrpcap(str(pcap), [Ether() / IP(src="1.1.1.1", dst="2.2.2.2")])
    from secagent.tools.plugins.pcap import analyze_pcap
    res = analyze_pcap(pcap_path=str(pcap))
    assert res["packet_count"] == 1
    assert res["suspected_beacons"] == []
