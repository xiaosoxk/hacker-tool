# -*- coding: utf-8 -*-
"""Kali 适配层：把 Kali 工具生态接入 ToolBus（授权门 -> 熔断 -> 审计）。

三种执行模式（AEGIS_KALI_MODE）：
  local  : 工具在当前 PATH（运行环境本身就是 Kali）
  docker : docker exec 进 deploy/kali 构建的隔离 Kali 容器
  ssh    : BatchMode SSH 连接远程 Kali 机器（联动你已有的 Kali 主机）

安全设计（对应设计文档第 8、13 章）：
  - 工具白名单 ALLOWED_TOOLS：不在名单的二进制一律拒绝
  - 只用 argv 列表执行，永不走 shell；参数做元字符卫生（双保险）
  - 每个 Kali 工具注册时声明 ROE 动作类型与风险等级，照常过授权门
  - 扩展白名单（如 sqlmap/hydra 类攻击工具）必须 risk=high 并走人工审批
"""
from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from typing import Any, Protocol

from secagent.config import CONFIG, KaliConfig

# 默认白名单：检测与情报类工具。攻击型工具（sqlmap/hydra/msfconsole）默认不开放，
# 需要时显式加入并注册为 risk="high"（走人工审批 + ROE 的 poc_verify 动作）。
ALLOWED_TOOLS = {
    "nmap", "nikto", "whatweb", "wafw00f", "gobuster", "sslscan",
    "searchsploit", "dig", "dnsrecon", "whois", "curl", "testssl.sh",
}

_FORBIDDEN_SUBSTR = (";", "&", "|", "`", "$(", "\n", ">", "<")


class ExecResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str, timeout: bool = False):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timeout = timeout


class KaliExecutor(Protocol):
    def run(self, argv: list[str], timeout: int = 300) -> ExecResult: ...


class LocalExecutor:
    """工具在本机 PATH 上（运行环境即 Kali）。"""

    def run(self, argv: list[str], timeout: int = 300) -> ExecResult:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return ExecResult(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired:
            return ExecResult(-1, "", f"timeout after {timeout}s", timeout=True)


class DockerExecutor:
    """docker exec 进入隔离 Kali 容器（deploy/kali 构建的 aegis-kali）。"""

    def __init__(self, container: str) -> None:
        self.container = container

    def run(self, argv: list[str], timeout: int = 300) -> ExecResult:
        full = ["docker", "exec", self.container] + argv
        try:
            p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
            return ExecResult(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired:
            return ExecResult(-1, "", f"timeout after {timeout}s", timeout=True)


class SSHExecutor:
    """BatchMode SSH 连接远程 Kali（联动既有 Kali 主机；需预置免密密钥）。"""

    def __init__(self, host: str, user: str, key: str | None = None, port: int = 22) -> None:
        self.host, self.user, self.key, self.port = host, user, key, port

    def run(self, argv: list[str], timeout: int = 300) -> ExecResult:
        remote = " ".join(shlex.quote(a) for a in argv)  # 远端命令安全引用
        base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-p", str(self.port)]
        if self.key:
            base += ["-i", self.key]
        cmd = base + [f"{self.user}@{self.host}", remote]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return ExecResult(p.returncode, p.stdout, p.stderr)
        except subprocess.TimeoutExpired:
            return ExecResult(-1, "", f"timeout after {timeout}s", timeout=True)


def make_executor(cfg: KaliConfig | None = None) -> KaliExecutor:
    cfg = cfg or CONFIG.kali
    if cfg.mode == "local":
        return LocalExecutor()
    if cfg.mode == "docker":
        return DockerExecutor(cfg.container)
    if cfg.mode == "ssh":
        return SSHExecutor(cfg.host, cfg.user, cfg.key, cfg.port)
    raise ValueError(f"未知 Kali 模式: {cfg.mode}")


def kali_run(executor: KaliExecutor, tool: str, args: list[str],
             timeout: int = 300) -> ExecResult:
    """白名单 + 参数卫生的总入口；所有 Kali 调用必须经过这里。"""
    if tool not in ALLOWED_TOOLS:
        raise PermissionError(f"工具 [{tool}] 不在 Kali 白名单内（可在 kali.ALLOWED_TOOLS 显式扩展）")
    for a in args:
        if not isinstance(a, str):
            continue
        if any(ch in a for ch in _FORBIDDEN_SUBSTR):
            raise ValueError(f"参数含被禁止的 shell 元字符: {a[:60]}")
    return executor.run([tool] + args, timeout=timeout)


# ---------------------------------------------------------------- 解析器
def parse_whatweb(stdout: str) -> dict:
    """whatweb 输出：http://target [200 OK] Country, nginx[1.24.0], jQuery。"""
    out = []
    for line in stdout.splitlines():
        if " [" not in line:
            continue
        target, _, rest = line.partition(" [")
        techs = [t.split("[")[0].strip() for t in rest.rstrip("]").split(",")
                 if t.strip() and "Status" not in t and "Country" not in t]
        out.append({"target": target.strip(), "techs": [t for t in techs if t]})
    return {"results": out}


def parse_wafw00f(stdout: str) -> dict:
    m = re.search(r"(?i)behind a\s+(.+?)\s+WAF", stdout)
    return {"waf": m.group(1).strip() if m else None,
            "detected": bool(m)}


def parse_nikto(stdout: str) -> dict:
    """抓取 '+ ' 开头的发现行（排除 Target/IP 头部行）。"""
    items = []
    for line in stdout.splitlines():
        s = line.strip()
        if s.startswith("+") and not re.match(r"^\+\s*(Target|IP|Start|End|Requests|Server)", s):
            items.append(s[1:].strip()[:160])
    return {"items": items[:40]}


def parse_gobuster(stdout: str) -> dict:
    paths = []
    for line in stdout.splitlines():
        m = re.match(r"^(\S+)\s+\(Status:\s*(\d+)\)", line.strip())
        if m:
            paths.append({"path": m.group(1), "status": int(m.group(2))})
    return {"paths": paths}


def parse_searchsploit(stdout: str) -> dict:
    """searchsploit -j 输出 JSON。"""
    try:
        data = json.loads(stdout[stdout.find("{"):stdout.rfind("}") + 1])
        exploits = data.get("RESULTS_EXPLOIT", [])
        return {"exploits": [{"title": e.get("Title", "")[:120],
                              "edb_id": e.get("EDB-ID"),
                              "type": e.get("Type")} for e in exploits[:20]]}
    except (json.JSONDecodeError, ValueError):
        return {"exploits": []}


def raise_on_failure(res: ExecResult, tool: str) -> ExecResult:
    """非零退出且无输出 = 执行失败，抛错让节点走降级路径（写 ev-err 证据）。"""
    if res.exit_code != 0 and not res.stdout.strip():
        raise RuntimeError(f"kali {tool} failed: {(res.stderr or 'no output')[:120]}")
    return res


# ---------------------------------------------------------------- 工具封装
def whatweb_tool(target: str, executor: KaliExecutor, **_: Any) -> dict:
    res = raise_on_failure(kali_run(executor, "whatweb", [target]), "whatweb")
    return parse_whatweb(res.stdout)


def wafw00f_tool(target: str, executor: KaliExecutor, **_: Any) -> dict:
    url = target if target.startswith("http") else f"http://{target}"
    res = raise_on_failure(kali_run(executor, "wafw00f", [url]), "wafw00f")
    return parse_wafw00f(res.stdout)


def nikto_tool(target: str, executor: KaliExecutor, **_: Any) -> dict:
    host = target.split("://")[-1].rstrip("/")
    res = raise_on_failure(
        kali_run(executor, "nikto", ["-h", host, "-nointeractive", "-Tuning", "123"], timeout=600),
        "nikto")
    return parse_nikto(res.stdout)


def gobuster_tool(target: str, executor: KaliExecutor, wordlist: str = "",
                  **_: Any) -> dict:
    wl = wordlist or CONFIG.kali.wordlist
    url = target if target.startswith("http") else f"http://{target}"
    res = raise_on_failure(
        kali_run(executor, "gobuster", ["dir", "-u", url, "-w", wl, "-q", "--no-error"]),
        "gobuster")
    return parse_gobuster(res.stdout)


def searchsploit_tool(target: str, executor: KaliExecutor, query: str = "", **_: Any) -> dict:
    res = raise_on_failure(kali_run(executor, "searchsploit", ["-j", query or target],
                                    timeout=120), "searchsploit")
    return parse_searchsploit(res.stdout)


def generic_tool(target: str, executor: KaliExecutor, tool: str = "nmap",
                 args: list[str] | None = None, **_: Any) -> dict:
    """白名单内任意工具的通用执行入口（argv 由调用方显式给出）。"""
    res = kali_run(executor, tool, list(args or []))
    return {"tool": tool, "exit_code": res.exit_code,
            "stdout": res.stdout[:8000], "stderr": res.stderr[:1000]}
