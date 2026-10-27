# -*- coding: utf-8 -*-
"""授权门测试：ROE 是硬约束，越界必须被拦截。"""
import pytest

from secagent.safety import AuthorizationError


def test_in_scope_ip_allowed(gate):
    gate.check_target("10.60.0.11")
    gate.acquire("10.60.0.11", "recon")


def test_out_of_scope_ip_blocked(gate):
    with pytest.raises(AuthorizationError):
        gate.check_target("192.0.2.1")


def test_cidr_scope(gate):
    gate.check_target("10.60.0.99")  # 在 10.60.0.0/24 内


def test_wildcard_domain(gate):
    gate.check_target("web01.lab.example.com")


def test_denied_action_blocked(gate):
    with pytest.raises(AuthorizationError):
        gate.check_action("denial_of_service")


def test_unknown_action_blocked(gate):
    with pytest.raises(AuthorizationError):
        gate.check_action("social_engineering")


def test_rate_limit_triggers(gate):
    for _ in range(500):
        gate.acquire("10.60.0.11", "recon")
    with pytest.raises(AuthorizationError):
        gate.acquire("10.60.0.11", "recon")  # 第 501 次，超过 ROE 上限
