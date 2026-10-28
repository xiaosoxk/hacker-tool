# Aegis Agent —— 攻防一体网络安全自主智能体

基于 **LangGraph + LangChain 生态** 的授权安全评估自主智能体：ReAct + Reflexion + Self-Critique
多层自省循环、多分支状态机、Send API 并行分析、MCP 风格插件总线、长期向量记忆、
幻觉抑制（证据链 + 多模型评审）、以及以 **ROE 授权门为第一优先级** 的安全架构。

> ⚠️ **法律与合规边界**：本框架仅用于 **书面授权范围内** 的安全评估与防御研究。
> 未授权对任何系统进行探测或利用属于违法行为（《刑法》第 285/286 条）。
> 所有目标与动作必须预先写入 `roe.yaml` 并经授权方确认。

## 目录结构

```
aegis-agent/
├── docs/                       # 设计文档 + 制作指南 + 使用手册
│   ├── BUILD_GUIDE.md          # 制作指南（从零搭建全流程）
│   └── MANUAL.md               # 使用手册（运行、审批、审计回放）
├── src/secagent/
│   ├── config.py               # 配置（模型分层路由 / 预算 / 沙箱 / 记忆）
│   ├── main.py                 # CLI：run / approve / replay
│   ├── graph/
│   │   ├── state.py            # AgentState 与 reducer（并行分支安全）
│   │   ├── nodes.py            # 全部图节点（ReAct / Reflexion / Critic）
│   │   └── builder.py          # StateGraph 组装 + 中断 + 检查点
│   ├── safety/                 # ★ 安全三件套 + 沙箱
│   │   ├── authorization.py    # ROE 授权门（硬约束）
│   │   ├── circuit_breaker.py  # 熔断器三态 + Token 预算
│   │   ├── sandbox.py          # Docker 一次性隔离沙箱
│   │   └── audit.py            # append-only 审计日志（可回放）
│   ├── tools/
│   │   ├── registry.py         # 工具总线（授权门强制通道）
│   │   └── plugins/            # recon / fingerprint / cve / pcap /
│   │                           # malware_static / lateral_sim / report
│   ├── llm/                    # 分层路由 + FakeLLM + 多模型评审
│   └── memory/                 # 长期向量记忆（local / chroma）
├── tests/                      # 29 个离线测试（含全图 e2e 与中断审批）
├── deploy/
│   ├── Dockerfile              # 编排层镜像
│   ├── docker-compose.yml      # 隔离拓扑（internal 网络 + 沙箱 + 靶机）
│   └── sandbox/Dockerfile.sandbox
├── roe.example.yaml            # ROE 授权文件模板
├── task.example.yaml           # 任务定义模板
└── Makefile                    # make setup / test / run / sandbox-up
```

## 快速开始（离线，无需任何 API Key）

```bash
pip install -r requirements.txt
python -m pytest tests            # 29 个测试全绿
make run                          # FakeLLM 离线演示：全图跑通出报告
```

## 真实模型运行

```bash
cp .env.example .env              # 填入 API Key，AEGIS_OFFLINE=0
cp roe.example.yaml roe.yaml      # 按书面授权修改目标与动作
make run                          # 运行评估；高危动作前自动挂起
make approve                      # 人工批准后恢复（POC 沙箱验证）
make replay                       # 回放审计日志
```

## 核心设计（详见 docs/ 设计文档）

| 模块 | 一句话 |
|------|--------|
| 授权门 | ROE 白名单 + 频次闸门，越界即拒，硬约束优先于任务目标 |
| 熔断器 | 工具级三态熔断 + Token/调用数预算，超限自动降级出报告 |
| 状态机 | LangGraph StateGraph，findings 按 id 合并 reducer 保证 Send 并行安全 |
| 自省循环 | 步内自检 → 轨迹级 Reflexion → 独立多模型评审（与执行模型解耦） |
| 人工审批 | interrupt_before=["poc_verify"]，高危动作挂起等批准 |
| 沙箱 | 高危动作仅在 internal 网络 + 只读根 + 资源限额的一次性容器内执行 |
| 幻觉抑制 | 无证据不报告 + 外部情报须独立验证 + 多模型评审去极值聚合 |

## Kali 联动（详见 docs/KALI_INTEGRATION.md）

`AEGIS_KALI=1` 后，Kali 工具生态（whatweb / wafw00f / nikto / gobuster / sslscan / searchsploit…）
经白名单适配层接入 ToolBus，三种模式：**本机 Kali（local）/ 隔离 Kali 容器（docker，默认）/ SSH 联动你已有的 Kali 机（ssh）**。
所有 Kali 调用照常过「授权门 → 熔断 → 审计」，攻击型工具（sqlmap 等）默认不在白名单、需 risk=high + 人工审批显式开放。
