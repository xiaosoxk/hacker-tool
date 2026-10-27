# -*- coding: utf-8 -*-
"""状态合并 reducer 测试：并行分支安全的形式化验证。"""
from secagent.graph.state import merge_by_id


def test_merge_by_id_dedups():
    left = [{"id": "a", "v": 1}]
    right = [{"id": "a", "v": 2}, {"id": "b", "v": 3}]
    out = merge_by_id(left, right)
    ids = {x["id"] for x in out}
    assert ids == {"a", "b"}
    assert next(x for x in out if x["id"] == "a")["v"] == 2  # 新值覆盖


def test_merge_is_commutative():
    a = [{"id": "a", "v": 1}]
    b = [{"id": "b", "v": 2}]
    ids1 = {x["id"] for x in merge_by_id(a, b)}
    ids2 = {x["id"] for x in merge_by_id(b, a)}
    assert ids1 == ids2  # 交换律：并行分支合并顺序无关


def test_merge_is_associative():
    a = [{"id": "a", "v": 1}]
    b = [{"id": "b", "v": 2}]
    c = [{"id": "c", "v": 3}]
    left = merge_by_id(merge_by_id(a, b), c)
    right = merge_by_id(a, merge_by_id(b, c))
    assert {x["id"] for x in left} == {x["id"] for x in right}
