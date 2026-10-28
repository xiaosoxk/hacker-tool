# Kali 联动指南（Kali Integration）

Aegis 通过 `tools/kali.py` 适配层把 Kali Linux 工具生态接入 ToolBus——**所有 Kali 工具调用依然强制经过 授权门 → 熔断器 → 审计日志**，与内置工具同等约束。

## 1. 三种执行模式（`AEGIS_KALI_MODE`）

| 模式 | 场景 | 机制 |
|------|------|------|
| `local` | Agent 就跑在 Kali 上（或 WSL-Kali） | 直接 subprocess 调 PATH 上的工具 |
| `docker` | 默认推荐 | `docker exec` 进 `deploy/kali` 构建的 `aegis-kali` 隔离容器 |
| `ssh` | 联动你**已有的** Kali 主机/实验室 | BatchMode SSH（需预置免密专用密钥） |

启用开关：`.env` 中 `AEGIS_KALI=1`。

### 模式一：Docker Kali（推荐起步）

```bash
docker compose -f deploy/docker-compose.yml build kali
docker compose -f deploy/docker-compose.yml up -d kali
# .env: AEGIS_KALI=1  AEGIS_KALI_MODE=docker
```

容器只挂 `aegis_sandbox` 隔离网络（无外网出口）、非特权用户、内存/PID 限额——与设计文档第 13 章沙箱七道防线一致。

### 模式二：SSH 联动你现有的 Kali 机器

```bash
ssh-keygen -t ed25519 -f ~/.ssh/aegis_kali -N ""     # 专用受限密钥
ssh-copy-id -i ~/.ssh/aegis_kali.pub kali@<你的Kali机>
# .env: AEGIS_KALI=1  AEGIS_KALI_MODE=ssh  AEGIS_KALI_HOST=<ip>  AEGIS_KALI_USER=kali  AEGIS_KALI_KEY=~/.ssh/aegis_kali
```

密钥建议只授予目标网段内的受限账号；`StrictHostKeyChecking=accept-new` 首次连接后固定指纹。

### 模式三：本机即 Kali

装好工具后 `AEGIS_KALI_MODE=local`，零中转直接调用。

## 2. 已接入的工具与 ROE 映射

| 总线工具名 | Kali 工具 | ROE 动作 | 风险 | 输出解析 |
|---|---|---|---|---|
| kali_whatweb | whatweb | fingerprint | low | 技术栈与版本 → `web_tech` finding |
| kali_wafw00f | wafw00f | fingerprint | low | WAF 识别 → `waf_detected` finding |
| kali_nikto | nikto | vuln_scan | medium | 发现行 → 逐条 finding |
| kali_gobuster | gobuster | recon | low | 路径与状态码 |
| kali_searchsploit | searchsploit | intel | low | JSON → exploit 列表 |
| kali_run | 白名单内任意 | recon | medium | 原始输出（截断 8KB） |

`kali_recon` 图节点（planner 可路由）= whatweb + wafw00f 组合侦察，产出自动并入状态机的 findings。

## 3. 安全机制（不可绕过）

1. **白名单** `ALLOWED_TOOLS`：不在名单的二进制直接 `PermissionError`；
2. **不走 shell**：argv 列表直传 + 参数元字符卫生（`;` `&` `|` `` ` `` `$(` 等一律拒绝）；
3. **授权门**：目标必须在 ROE 白名单内、动作类型必须被授权、频次受限；
4. **失败降级**：非零退出且无输出时抛错 → 节点写 `ev-kali-err` 证据继续主流程（Kali 挂了不影响评估产出报告）；
5. **审计**：每次调用落 `audit.log`（参数、结果哈希、耗时），`make replay` 可回放。

## 4. 扩展新工具

```python
# 1) 加入白名单（kali.py）
ALLOWED_TOOLS.add("dnsrecon")           # 若尚未包含
# 2) 写封装（解析器 + raise_on_failure）
def dnsrecon_tool(target: str, executor: KaliExecutor, **_: Any) -> dict:
    res = raise_on_failure(kali_run(executor, "dnsrecon", ["-d", target]), "dnsrecon")
    return parse_dnsrecon(res.stdout)
# 3) 注册（builder.py::build_toolbus）——攻击型工具必须 risk="high"
bus.register(ToolMeta("kali_dnsrecon", "recon"), partial(dnsrecon_tool, executor=ex))
# 4) tests/test_kali.py 加解析器单测
```

**攻击型工具（sqlmap / hydra / msfconsole）默认不在白名单**：如业务确需，加入白名单并以 `risk="high"` 注册——自动获得「ROE poc_verify 动作 + interrupt 人工审批 + 沙箱执行」三重闸门，缺一不执行。

## 5. 常见问题

- **docker exec 报权限**：确认 agent 运行用户在 docker 组，或编排层容器内挂载 docker.sock（仅建议在隔离宿主机上）。
- **seclists 路径不对**：`AEGIS_KALI_WORDLIST` 按目标环境调整。
- **SSH 卡住**：BatchMode 下不会交互输密码——先手工验证 `ssh -i <key> kali@host echo ok`。
- **工具超时**：`AEGIS_KALI_TIMEOUT` 默认 300s；nikto 全扫建议先 `-Tuning 123` 收窄。
