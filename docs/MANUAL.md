# 使用手册（MANUAL）—— Aegis Agent 操作手册

## 1. 三个命令

| 命令 | 作用 |
|------|------|
| `python -m secagent.main run --task task.yaml --roe roe.yaml` | 运行评估任务 |
| `python -m secagent.main approve --thread T1` | 人工批准高危动作并恢复执行 |
| `python -m secagent.main replay --audit data/audit.log` | 回放审计日志 |

## 2. 一次评估任务的完整生命周期

```
run
 ├─ 读 ROE + 任务 → memory_recall（检索历史经验）→ planner（生成分步计划）
 ├─ recon（端口服务）→ fingerprint（Web 指纹 + 安全头）→ vuln_scan（CVE 关联）
 ├─ [发现候选 CVE] → 挂起（exit code 2，提示 approve）        ← 人工审批点
 │     approve → POC 在隔离沙箱内验证（不批准则自动跳过，标注未验证）
 ├─ 并行分析：PCAP beacon 检测 / 攻击路径推演 / 蓝队规则草稿
 ├─ critic（证据完备性检查）→ 缺陷多则 reflect → planner 回环
 └─ report（Markdown 报告 + 熔断快照）→ 写入长期记忆
```

## 3. 安全操作要点

- **ROE 是宪法**：目标不在 roe.yaml 白名单内，任何动作都会被拒绝
  （AuthorizationError）。改 ROE = 改授权，必须有书面依据。
- **高危动作三级闸门**：ROE 动作白名单 → interrupt 人工批准 → 隔离沙箱执行。
  三者缺一不可，任何一级失败动作即不执行。
- **审批可以拒绝**：不执行 approve 直接重跑或修改任务，POC 验证自动跳过，
  报告中该发现保持"待验证"状态——这是预期行为，不是故障。
- **审计回放**：每条记录含时间戳、执行者、动作、目标、参数、结果与细节哈希；
  `replay --actor toolbus --action poc_verify` 可只看高危动作。

## 4. 任务字段速查（task.yaml）

| 字段 | 必填 | 说明 |
|------|------|------|
| targets | 是 | 目标列表（必须在 ROE 内） |
| mode | 否 | assess（评估）或 blue_sim（蓝队仿真） |
| pcap_path | 否 | 触发 PCAP 深度分析分支 |
| network / entry_host | 否 | 拓扑与入口，触发攻击路径推演 |

## 5. 常见问题

- **退出码 2 且提示 HOLD**：正常，高危动作等待批准；执行 approve 恢复。
- **报告发现均为"待验证"**：沙箱未就绪或未批准；按 BUILD_GUIDE 第 5 节部署沙箱。
- **某工具频繁 error**：熔断器可能已 OPEN，查 `replay` 日志定位根因（多为网络/权限）。
- **想换模型**：改 .env 的 AEGIS_PLANNER_MODEL / AEGIS_WORKER_MODEL / AEGIS_REVIEWERS。
- **想清空记忆**：删除 data/memory/store.json（长期记忆是复利资产，慎删）。

## 6. 免责声明

本工具输出为自动化评估参考，发布前必须由人类安全工程师复核；
对未授权目标使用本工具的一切后果由使用者自行承担。
