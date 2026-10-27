# -*- coding: utf-8 -*-
"""侦察插件：端口与服务发现（nmap 薄封装）。

仅调用本机 nmap；目标必须先经授权门校验。离线环境下该插件注册
fake 实现（见 tests/conftest.py）。
"""
from __future__ import annotations

import json
import shutil
import subprocess

_NMAP_FLAGS = ["-Pn", "-sV", "--open", "-T3", "--max-rate", "300"]


def nmap_scan(target: str, ports: str = "1-10000", **_: object) -> dict:
    """扫描目标开放端口与服务版本，返回结构化结果。"""
    binary = shutil.which("nmap")
    if not binary:
        raise RuntimeError("nmap 不可用：请安装或使用离线 fake 模式")
    argv = [binary, * _NMAP_FLAGS, "-p", ports, "-oX", "-", target]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(f"nmap 失败: {proc.stderr[:300]}")
    return _parse_xml(proc.stdout)


def _parse_xml(xml: str) -> dict:
    """解析 nmap XML 输出为 {host: [ports]}。"""
    import xml.etree.ElementTree as ET

    root = ET.fromstring(xml)
    hosts: dict[str, list[dict]] = {}
    for host in root.findall("host"):
        addr = host.find("address")
        ip = addr.get("addr") if addr is not None else "unknown"
        ports = []
        for port in host.iter("port"):
            state = port.find("state")
            service = port.find("service")
            if state is not None and state.get("state") == "open":
                ports.append({
                    "port": int(port.get("port", 0)),
                    "proto": port.get("protocol", "tcp"),
                    "service": (service.get("name") if service is not None else "") or "",
                    "version": (service.get("version") if service is not None else "") or "",
                })
        hosts[ip] = ports
    return {"hosts": hosts, "scan_xml_sha": __import__("hashlib").sha256(xml.encode()).hexdigest()[:16]}


def fake_scan(target: str, ports: str = "1-10000", **_: object) -> dict:
    """离线测试用的确定性结果。"""
    return {"hosts": {target: [
        {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9"},
        {"port": 80, "proto": "tcp", "service": "http", "version": "nginx 1.24"},
    ]}}


if __name__ == "__main__":
    print(json.dumps(fake_scan("127.0.0.1"), ensure_ascii=False))
