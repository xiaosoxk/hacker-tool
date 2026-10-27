# -*- coding: utf-8 -*-
"""Web 指纹插件：对 HTTP 服务做被动级探测（技术栈、响应头、安全头缺失）。

只发送正常 GET 请求，频次受授权门约束；安全头缺失直接产出加固类 finding。
"""
from __future__ import annotations

import httpx

SECURITY_HEADERS = {
    "content-security-policy": "缺失 CSP",
    "strict-transport-security": "缺失 HSTS",
    "x-content-type-options": "缺失 X-Content-Type-Options",
    "x-frame-options": "缺失 X-Frame-Options",
}

FINGERPRINT_HINTS = {
    "nginx": "nginx", "apache": "Apache", "tomcat": "Tomcat", "jboss": "JBoss",
    "php": "PHP", "x-powered-by": "后端框架", "jsessionid": "Java Web",
    "__cfduid": "Cloudflare", "wp-content": "WordPress",
}


def http_fingerprint(target: str, timeout: float = 6.0, **_: object) -> dict:
    """对 http/https 各探测一次，聚合指纹与安全头检查结果。"""
    host = target.split("://")[-1].rstrip("/")
    techs: set[str] = set()
    header_sets: dict[str, dict[str, str]] = {}

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            resp = httpx.get(url, timeout=timeout, follow_redirects=True,
                             headers={"User-Agent": "aegis-agent/0.1 (authorized-assessment)"})
        except httpx.HTTPError as exc:
            header_sets[scheme] = {"error": f"{type(exc).__name__}: {exc}"[:120]}
            continue
        header_sets[scheme] = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:20000].lower()
        for hint, name in FINGERPRINT_HINTS.items():
            if hint in body or hint in " ".join(header_sets[scheme].keys()):
                techs.add(name)
        if scheme == "https":
            code = str(resp.status_code)
            header_sets[scheme]["_status"] = code
            header_sets[scheme]["_title"] = _title(resp.text)

    findings = []
    https_headers = header_sets.get("https") or {}
    for missing, label in SECURITY_HEADERS.items():
        if https_headers and missing not in https_headers:
            findings.append({"type": "missing_security_header", "header": missing, "desc": label})

    return {"host": host, "reachable": bool(https_headers and "error" not in https_headers),
            "techs": sorted(techs), "headers": header_sets, "hardening_findings": findings}


def _title(html: str) -> str:
    low = html.lower()
    start, end = low.find("<title>"), low.find("</title>")
    if 0 <= start < end:
        return html[start + 7:end].strip()[:80]
    return ""
