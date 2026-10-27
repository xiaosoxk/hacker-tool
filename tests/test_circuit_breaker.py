# -*- coding: utf-8 -*-
"""熔断器测试：三态转换与预算闸门。"""


def test_closed_allows(breaker):
    assert breaker.allow("t1") is True


def test_opens_after_threshold(breaker):
    for _ in range(5):
        breaker.record_failure("t1")
    assert breaker._state("t1")["state"].value == "open"
    assert breaker.allow("t1") is False


def test_other_tools_unaffected(breaker):
    for _ in range(5):
        breaker.record_failure("t1")
    assert breaker.allow("t2") is True  # 单工具熔断不拖垮全局


def test_success_resets(breaker):
    for _ in range(4):
        breaker.record_failure("t1")
    breaker.record_success("t1")
    assert breaker._state("t1")["failures"] == 0


def test_budget_exhaustion():
    from secagent.safety import CircuitBreaker, TokenBudget
    b = CircuitBreaker(budget=TokenBudget(max_tokens=100, max_tool_calls=2))
    assert b.allow("x") is True
    b.budget.charge(tokens=50, tool_calls=1)
    assert b.allow("x") is True
    b.budget.charge(tokens=60, tool_calls=1)   # tokens 超限
    assert b.allow("x") is False
    assert b.budget.exhausted() is True
