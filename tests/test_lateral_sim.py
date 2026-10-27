# -*- coding: utf-8 -*-
"""横向移动路径推演测试：概率建模与最大概率路径。"""
from secagent.tools.plugins.lateral_sim import build_graph, cvss_to_prob, max_prob_path, risk_assessment

HOSTS = {
    "10.60.0.11": {"cvss": 7.5, "value": "normal"},   # 入口
    "10.60.0.20": {"cvss": 9.8, "value": "core"},     # 高价值目标
    "10.60.0.30": {"cvss": 3.1, "value": "normal"},
}
LINKS = [["10.60.0.11", "10.60.0.20"], ["10.60.0.11", "10.60.0.30"], ["10.60.0.20", "10.60.0.30"]]


def test_cvss_mapping_monotonic():
    assert cvss_to_prob(9.8) > cvss_to_prob(7.5) > cvss_to_prob(3.1)


def test_max_prob_path_reaches_core():
    g = build_graph(HOSTS, LINKS)
    res = max_prob_path(g, "10.60.0.11", "10.60.0.20")
    assert res["reachable"] is True
    assert res["path"] == ["10.60.0.11", "10.60.0.20"]
    # 0.8 * 0.95 = 0.76
    assert abs(res["prob"] - 0.8 * 0.95) < 1e-6


def test_unreachable_goal():
    g = build_graph(HOSTS, [["10.60.0.11", "10.60.0.30"]])
    res = max_prob_path(g, "10.60.0.11", "10.60.0.20")
    assert res["reachable"] is False
    assert res["prob"] == 0.0


def test_risk_ordering_prefers_core():
    g = build_graph(HOSTS, LINKS)
    rows = risk_assessment(g, "10.60.0.11", list(HOSTS))
    assert rows[0]["goal"] == "10.60.0.20"   # core 资产风险权重最高
    assert rows[0]["risk"] > rows[-1]["risk"]
