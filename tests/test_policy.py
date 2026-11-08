"""规则层（ontology/policy/）：spec 还原、参数类型与元检查反例。

红线是 policy-as-code，所以这里既测"参数读对了"，也测"读错会失败"——
把正则读成单字符、把列表读成字符串，是这类代码最典型的静默错误。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from rdflib import Graph

from checker.checks import check_rule_specs
from checker.loader import load_redlines
from checker.policy import PolicyError, parse_redlines

ROOT = Path(__file__).resolve().parent.parent

PREFIX = """@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
"""


def _parse(body: str):
    graph = Graph().parse(data=PREFIX + body, format="turtle")
    return parse_redlines(graph, "fixture")


def _redline(extra: str = "") -> str:
    return (
        'rcp:RL-001 a rcp:Redline ;\n'
        '    rcp:redlineId "RL-001" ; rcp:slug "x" ; rdfs:label "x" ;\n'
        f'    {extra} .\n'
    )


def test_real_policy_loads_all_redlines():
    redlines = load_redlines(ROOT)
    ids = [c["id"] for c in redlines["constraints"]]
    assert ids == sorted(ids)
    assert {"RL-002", "RL-004", "RL-007"} <= set(ids)
    assert redlines["exceptions"] == []


def test_spec_type_comes_from_rdf_type():
    redlines = load_redlines(ROOT)
    by_id = {c["id"]: c for c in redlines["constraints"]}
    assert by_id["RL-004"]["spec"]["type"] == "file-scan"
    assert by_id["RL-007"]["spec"]["type"] == "upstream-scan"


def test_list_parameters_stay_lists():
    """单值 vs 列表必须由 RDF 结构决定：include 读成字符串会让遍历逐字符匹配。"""
    by_id = {c["id"]: c for c in load_redlines(ROOT)["constraints"]}
    assert by_id["RL-004"]["spec"]["include"] == ["*.sql"]
    assert by_id["RL-005"]["spec"]["deny_values"][0] == "mysql"


def test_regex_escapes_survive_turtle():
    """Turtle 无 raw string，正则里的 \\b 必须写成 \\\\b 才不会被吃掉。"""
    by_id = {c["id"]: c for c in load_redlines(ROOT)["constraints"]}
    pattern = re.compile(by_id["RL-004"]["spec"]["match"], re.I)
    assert pattern.search("CREATE TABLE foo")
    assert not pattern.search("insert into foo values (1)")


def test_exceptions_point_at_declared_redline():
    redlines = load_redlines(ROOT)
    known = {c["id"] for c in redlines["constraints"]}
    assert all(e["redline"] in known for e in redlines["exceptions"])


def test_spec_without_type_is_rejected():
    with pytest.raises(PolicyError) as exc:
        _parse(_redline("rcp:spec [ rcp:match \"x\" ]"))
    assert "类型声明" in str(exc.value)


def test_redline_without_id_is_rejected():
    with pytest.raises(PolicyError) as exc:
        _parse('rcp:RL a rcp:Redline ; rcp:slug "x" .\n')
    assert "redlineId" in str(exc.value)


def test_duplicate_redline_id_is_rejected():
    body = _redline('rcp:spec [ a rcp:RegistryAssert ; rcp:via "x" ]') + _redline(
        'rcp:spec [ a rcp:RegistryAssert ; rcp:via "x" ]'
    ).replace("rcp:RL-001 a", "rcp:RL-001b a")
    with pytest.raises(PolicyError) as exc:
        _parse(body)
    assert "重复" in str(exc.value)


def test_exception_for_unknown_redline_is_rejected():
    """例外指向不存在的红线，等于登记了一个不存在的豁免，必须失败。"""
    body = _redline('rcp:spec [ a rcp:RegistryAssert ; rcp:via "x" ]') + (
        'rcp:exc a rcp:Exception ; rcp:redline rcp:RL-999 .\n'
    )
    with pytest.raises(PolicyError) as exc:
        _parse(body)
    assert "未声明的红线" in str(exc.value)


def test_paper_redline_without_spec_is_e301():
    findings = check_rule_specs({"constraints": [{"id": "RL-999"}], "exceptions": []})
    assert {f.code for f in findings} == {"E301"}
