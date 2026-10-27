# -*- coding: utf-8 -*-
"""CVE 情报插件：查询 NVD API 2.0，按 CPE/关键词检索已知漏洞。

返回结果仅作为候选线索，必须经本地验证（poc_verify）后才可写入报告 ——
这是幻觉抑制的「外部证据必须独立验证」原则。
"""
from __future__ import annotations

import httpx

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def cve_lookup(keyword: str, max_results: int = 10, **_: object) -> dict:
    """按关键词（产品/版本）查询 NVD。离线环境抛错由调用方降级处理。"""
    params = {"keywordSearch": keyword, "resultsPerPage": max_results}
    resp = httpx.get(NVD_API, params=params, timeout=15.0,
                     headers={"User-Agent": "aegis-agent/0.1"})
    resp.raise_for_status()
    data = resp.json()
    out = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss = None
        for bucket in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(bucket):
                cvss = metrics[bucket][0].get("cvssData", {})
                break
        out.append({
            "id": cve.get("id"),
            "published": cve.get("published"),
            "cvss_score": cvss.get("baseScore") if cvss else None,
            "cvss_vector": cvss.get("vectorString") if cvss else None,
            "summary": (cve.get("descriptions") or [{}])[0].get("value", "")[:300],
        })
    return {"keyword": keyword, "total": data.get("totalResults", 0), "cves": out}


def enrich_findings(findings: list[dict]) -> list[dict]:
    """为带 product 字段的 finding 附加已知 CVE 候选；网络失败时静默降级。"""
    for f in findings:
        product = f.get("product")
        if product and not f.get("cves"):
            try:
                res = cve_lookup(product)
                f["cves"] = [c["id"] for c in res["cves"][:5]]
            except Exception:  # noqa: BLE001
                f["cves"] = []
    return findings
