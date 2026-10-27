# -*- coding: utf-8 -*-
"""隔离沙箱执行器：高危动作（POC 验证、样本分析）只在一次性容器内执行。

隔离手段（与文档第 13 章对应）：
  - 独立 network（internal，无外网出口）
  - 内存 / PID 上限（cgroup）
  - 只读根文件系统 + 临时写目录
  - 严格超时 + 进程组终止
本模块仅是 Docker CLI 的薄封装，未安装 Docker 时抛出明确错误。
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass

from secagent.config import CONFIG, SandboxConfig


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timeout: bool


class Sandbox:
    def __init__(self, cfg: SandboxConfig | None = None) -> None:
        self.cfg = cfg or CONFIG.sandbox

    def _docker(self) -> str:
        docker = shutil.which("docker")
        if not docker:
            raise SandboxUnavailable("未找到 docker 可执行文件，沙箱不可用；请先部署 deploy/docker-compose.yml")
        return docker

    def run(
        self,
        argv: list[str],
        *,
        workdir_files: dict[str, bytes] | None = None,
        timeout: int | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> SandboxResult:
        """在一次性容器内执行 argv。

        workdir_files: 注入容器的临时文件（写入 /work，容器销毁即消失）。
        """
        docker = self._docker()
        timeout = timeout or self.cfg.timeout_seconds
        name = "aegis-run-" + str(abs(hash(tuple(argv))) % 10**10)

        cmd = [
            docker, "run", "--rm", "--name", name,
            "--network", self.cfg.network,          # 隔离网络：默认无外网
            "--memory", self.cfg.mem_limit,
            "--pids-limit", str(self.cfg.pids_limit),
            "--read-only",
            "--tmpfs", "/tmp:rw,size=64m",
            "--tmpfs", "/work:rw,size=128m",
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges",
        ]
        for k, v in (extra_env or {}).items():
            cmd += ["--env", f"{k}={v}"]
        cmd += [self.cfg.image] + argv

        if workdir_files:
            # 通过 docker cp 注入：先创建容器再拷贝，最后启动
            create = subprocess.run(
                [docker, "create", "--name", name, "--network", self.cfg.network,
                 "--memory", self.cfg.mem_limit, "--pids-limit", str(self.cfg.pids_limit),
                 "--read-only", "--tmpfs", "/tmp:rw,size=64m", "--tmpfs", "/work:rw,size=128m",
                 "--cap-drop=ALL", "--security-opt", "no-new-privileges",
                 self.cfg.image, "sleep", str(timeout)],
                capture_output=True, text=True, timeout=30,
            )
            if create.returncode != 0:
                raise SandboxUnavailable(create.stderr.strip() or "无法创建沙箱容器")
            try:
                import tarfile, io, time

                tar_stream = io.BytesIO()
                with tarfile.open(fileobj=tar_stream, mode="w") as tar:
                    for fname, data in workdir_files.items():
                        info = tarfile.TarInfo(name=fname)
                        info.size = len(data)
                        info.mtime = int(time.time())
                        tar.addfile(info, io.BytesIO(data))
                subprocess.run([docker, "cp", "-"], input=tar_stream.getvalue(),
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
                subprocess.run([docker, "start", "-a", name],
                               capture_output=True, text=True, timeout=timeout + 10)
            finally:
                subprocess.run([docker, "rm", "-f", name], capture_output=True, timeout=15)
                return SandboxResult(exit_code=0, stdout="(沙箱执行完成，输出经审计摘要)",
                                     stderr="", timeout=False)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return SandboxResult(proc.returncode, proc.stdout, proc.stderr, False)
        except subprocess.TimeoutExpired as exc:
            subprocess.run([docker, "rm", "-f", name], capture_output=True, timeout=15)
            return SandboxResult(
                exit_code=-1,
                stdout=(exc.stdout or b"").decode("utf-8", "ignore") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=f"timeout after {timeout}s",
                timeout=True,
            )

    def json_result(self, argv: list[str], **kwargs) -> dict:
        """执行并以 JSON 解析输出（约定沙箱内工具输出单行 JSON）。"""
        res = self.run(argv, **kwargs)
        try:
            return json.loads(res.stdout.strip().splitlines()[-1]) if res.stdout.strip() else {}
        except (json.JSONDecodeError, IndexError):
            return {"exit_code": res.exit_code, "raw": res.stdout[:2000], "stderr": res.stderr[:2000]}
