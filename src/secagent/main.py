# -*- coding: utf-8 -*-
"""CLI 入口。

用法：
  python -m secagent.main run --task task.yaml     # 运行评估任务
  python -m secagent.main approve --thread T1      # 人工批准高危动作并恢复
  python -m secagent.main replay --audit data/audit.log  # 回放审计日志
"""
from __future__ import annotations

import argparse
import json
import sys

import yaml

from secagent.graph.builder import build_graph
from secagent.graph.state import initial_state
from secagent.safety import ROE


def load_task(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def cmd_run(args: argparse.Namespace) -> int:
    task = load_task(args.task)
    roe = ROE.load(args.roe)
    task.setdefault("targets", roe.allowed_targets)
    task["roe_targets"] = roe.allowed_targets

    app, bus, breaker = build_graph()
    thread = {"configurable": {"thread_id": args.thread}}
    state = initial_state(task)

    result = app.invoke(state, config=thread)
    if app.get_state(thread).next:
        # 在 interrupt 点挂起（高危动作待批准）
        pending = app.get_state(thread).next
        print(f"[HOLD] 高危动作待人工批准，下一步: {pending}", file=sys.stderr)
        print(f"执行: python -m secagent.main approve --thread {args.thread}", file=sys.stderr)
        return 2

    print(result.get("report", "(空报告)"))
    print("\n--- 熔断器快照 ---", file=sys.stderr)
    print(json.dumps(breaker.snapshot(), ensure_ascii=False), file=sys.stderr)
    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    """人工批准：把 human_approval 置位后从 interrupt 恢复。"""
    app, bus, breaker = build_graph()
    thread = {"configurable": {"thread_id": args.thread}}
    app.update_state(thread, {"human_approval": True})
    result = app.invoke(None, config=thread)
    print(result.get("report", "(空报告)"))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from secagent.safety import AuditLogger
    for rec in AuditLogger(args.audit).replay(actor=args.actor, action=args.action):
        print(json.dumps(rec, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="aegis", description="攻防一体网络安全自主智能体")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="运行评估任务")
    p_run.add_argument("--task", required=True, help="任务 YAML 路径")
    p_run.add_argument("--roe", default="roe.yaml", help="ROE 授权文件")
    p_run.add_argument("--thread", default="T1", help="会话线程 ID")
    p_run.set_defaults(fn=cmd_run)

    p_ok = sub.add_parser("approve", help="批准高危动作并恢复执行")
    p_ok.add_argument("--thread", default="T1")
    p_ok.set_defaults(fn=cmd_approve)

    p_re = sub.add_parser("replay", help="回放审计日志")
    p_re.add_argument("--audit", default="data/audit.log")
    p_re.add_argument("--actor")
    p_re.add_argument("--action")
    p_re.set_defaults(fn=cmd_replay)

    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
