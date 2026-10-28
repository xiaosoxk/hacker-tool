# 制作指南（BUILD GUIDE）—— 从零搭建 Aegis Agent 全流程

本指南对应设计文档《攻防一体网络安全自主智能体》第 15 章的工程流程，给出可复现的搭建步骤。

## 0. 前置条件

- Python 3.11+，Docker Desktop（沙箱必需，纯离线测试可无）
- 一份**书面授权**（ROE）：明确目标网段/域名、允许动作、时间窗
- OpenAI 兼容 API（或离线 FakeLLM 演示）

## 1. 环境搭建

```bash
git init aegis-agent && cd aegis-agent
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## 2. 状态机先行的开发顺序（推荐）

按依赖顺序开发，每步可测试：

1. **safety/ 三件套**：authorization → circuit_breaker → audit（对应 tests/test_authorization.py 等）
2. **graph/state.py**：定义 AgentState 与 reducer；先写 merge_by_id 的交换律/结合律测试
3. **tools/**：registry 工具总线（授权门强制通道）→ 逐个插件（每个插件配 fake 实现供离线测试）
4. **graph/nodes.py**：节点工厂（闭包绑定 bus/chat，保持节点为纯函数）
5. **graph/builder.py**：StateGraph 组装、条件边、Send 扇出、interrupt_before
6. **tests/test_graph_offline.py**：FakeLLM 驱动全图 e2e —— 这是整个项目的安全网
7. **llm/ multi_model.py**：真实模型接入与多模型评审
8. **memory/**：向量记忆（先用 LocalVectorStore，量大后换 chroma）
9. **deploy/**：docker-compose 隔离拓扑（internal 网络）

## 3. 关键实现要点（踩坑记录）

- **ToolBus 统一签名**：所有工具函数第一个参数必须是 `target`，否则总线的授权门
  与审计会漏传参（本项目实际踩过：空 target 走了另一分支导致静默失败）。
- **reducer 缺失 = 并行覆盖**：Send 扇出的分支若写同一 key 而无合并 reducer，
  后写覆盖先写 —— findings 必须用按 id 去重合并。
- **interrupt 恢复**：`app.update_state(thread, {...})` 注入人工决策后用
  `app.invoke(None, config)` 恢复；测试时对网络类工具一律 monkeypatch 打桩。
- **FakeLLM 脚本化**：按关键词返回固定 JSON，让全图测试确定性可重放。

## 4. 新增一个 MCP 风格插件的步骤

1. 在 `tools/plugins/` 新建模块，实现 `def my_tool(target: str = "", **kw) -> dict`
2. 在 `builder.py::build_toolbus` 注册：`bus.register(ToolMeta("my_tool", "<ROE动作>", risk=...), my_tool)`
3. 在节点中通过 `bus.call("my_tool", target=...)` 调用（禁止绕过总线）
4. `tests/` 加单测（真实实现 + fake 实现各一）
5. 更新 ROE 的 allowed_actions（新动作类型需要授权声明）

## 5. 沙箱部署

```bash
make sandbox-build     # 构建编排镜像与沙箱镜像
make sandbox-up        # internal 隔离网络 + 只读 + 资源限额 + 无外网
```

验证隔离性：`docker exec <sandbox容器> ping 8.8.8.8` 应当失败（internal 网络）。

## 5.5 Kali 联动部署

详见 `docs/KALI_INTEGRATION.md`。要点：

```bash
docker compose -f deploy/docker-compose.yml build kali    # 构建隔离 Kali 容器
docker compose -f deploy/docker-compose.yml up -d kali
# .env: AEGIS_KALI=1  AEGIS_KALI_MODE=docker
```

联动你已有的 Kali 主机用 `AEGIS_KALI_MODE=ssh`（专用受限密钥免密）。工具白名单、
ROE 映射与扩展方法见 KALI_INTEGRATION.md 第 2、4 节；38 个测试含 Kali 解析器与降级路径。

## 6. 上线前检查清单

- [ ] ROE 已由授权方书面确认，denied_actions 包含 DoS 与数据外带
- [ ] .env 不入库（.gitignore），密钥走环境变量或 KMS
- [ ] 审计日志目录持久化并接入 SIEM
- [ ] interrupt 人工审批链路演练过（含拒绝路径）
- [ ] Token 预算与熔断阈值按业务压测校准
- [ ] 报告带"人工复核后方可发布"声明
