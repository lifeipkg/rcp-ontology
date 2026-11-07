"""关系层测试：分域正确、声明驱动、每条新规则一条反例。

约定与 test_checks 一致：正向必须闭合，反向只破坏一条约束，确保报告能定位编号。
关系层真源是 ontology/tbox/relations.ttl（手写 TTL），所以这里既测解析结果，也测
「改声明即改判定」这一性质——后者是这一层存在的理由。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from checker import graph as G
from checker.checks import check_dependency_graph, check_relations
from checker.loader import LoadError, load_relations
from checker.relations import (
    kind_class,
    reachability_graphs,
    service_relations,
)
from checker.exporter import build_rdf

ROOT = Path(__file__).resolve().parent.parent

CONCEPTS = {
    "kinds": [
        {"name": "gateway", "must_be_external": True, "is_entry": True,
         "requires_port": True, "requires_contract": True,
         "allowed_depends_on_kinds": ["patrol-line", "data-gateway"]},
        {"name": "patrol-line", "must_be_external": False, "is_entry": False,
         "requires_port": True, "requires_contract": True,
         "allowed_depends_on_kinds": []},
        {"name": "data-gateway", "must_be_external": False, "is_entry": False,
         "requires_port": True, "requires_contract": True,
         "allowed_depends_on_kinds": []},
        {"name": "meta", "must_be_external": False, "is_entry": True,
         "requires_port": False, "requires_contract": False,
         "allowed_depends_on_kinds": []},
    ],
    "capabilities": [],
    "decisions": [],
}


@pytest.fixture(scope="module")
def relations():
    return load_relations(ROOT)


def service(name, kind, relations_map=None, depends_on=None, port=8000, **extra):
    base = {
        "name": name,
        "repo": f"rcp-{name}",
        "kind": kind,
        "port": port,
        "external": kind in ("gateway",),
        "owner": "platform",
        "capabilities": [],
        "contracts": [],
    }
    if relations_map is not None:
        base["relations"] = relations_map
    if depends_on is not None:
        base["depends_on"] = depends_on
    base.update(extra)
    return base


def test_relations_ttl_declares_six_graphs(relations):
    assert set(relations["graphs"]) == {
        "call", "data", "contract", "build", "deploy", "governance"
    }
    assert reachability_graphs(relations) == {"call"}
    assert relations["relations"]["calls"]["status"] == "enforced"


def test_legacy_depends_on_maps_to_calls():
    """旧字段等价于 calls —— 迁移期两种写法必须并存，否则一次改动就断全仓。"""
    assert service_relations({"depends_on": ["a", "b"]}) == {"calls": ["a", "b"]}
    assert service_relations({"relations": {"calls": ["a"]}, "depends_on": ["a", "b"]}) == {
        "calls": ["a", "b"]
    }


def test_graphs_are_separated_by_domain(relations):
    """同一对节点上的不同关系必须落在不同图里，否则可达性会被污染。"""
    registry = {"services": [
        service("gw", "gateway", relations_map={"calls": ["a"], "queries": ["dw"]}),
        service("a", "patrol-line", port=8001),
        service("dw", "data-gateway", port=8090),
    ], "libraries": []}

    call = G.build_graph(registry, relations, "call")
    data = G.build_graph(registry, relations, "data")
    assert call["gw"] == ["a"]
    assert data["gw"] == ["dw"]


def test_non_reachability_edge_does_not_make_node_reachable(relations):
    """数据边的存在不能让一个服务"变得可达"——那正是分域要防的误判。"""
    registry = {"services": [
        service("gw", "gateway", relations_map={"queries": ["dw"]}),
        service("dw", "data-gateway", port=8090),
    ], "libraries": []}

    findings = check_dependency_graph(registry, CONCEPTS, relations)
    assert any(f.code == "E110" and "dw" in f.message for f in findings)


def test_cycle_reported_on_non_call_graph(relations):
    """成环在每张图上都判：构建图的双向引用同样是错误，只是措辞标注图名。"""
    registry = {"services": [
        service("a", "patrol-line", relations_map={"depends_artifact": ["b"]}, port=8001),
        service("b", "patrol-line", relations_map={"depends_artifact": ["a"]}, port=8002),
    ], "libraries": []}

    findings = check_dependency_graph(registry, CONCEPTS, relations)
    cycles = [f for f in findings if f.code == "E108"]
    assert cycles, "构建图成环必须报 E108"
    assert "build" in cycles[0].message


def test_e116_undeclared_relation(relations):
    """登记里出现未声明的关系名 = 那条边绕过了全部关系级判定。"""
    registry = {"services": [
        service("gw", "gateway", relations_map={"phone_home": ["a"]}),
        service("a", "patrol-line", port=8001),
    ], "libraries": []}

    findings = check_relations(registry, relations, CONCEPTS)
    assert [f.code for f in findings if f.code == "E116"] == ["E116"]
    assert "phone_home" in findings[0].message


def test_e117_target_kind_violation(relations):
    """calls 的目标必须是服务；指向库（构建期依赖）是建模错误。"""
    registry = {
        "services": [service("gw", "gateway", relations_map={"calls": ["core"]})],
        "libraries": [{"name": "core", "repo": "rcp-core", "owner": "platform"}],
    }

    findings = check_relations(registry, relations, CONCEPTS)
    assert any(f.code == "E117" and "core" in f.message for f in findings)


def test_e105_only_for_relations_declaring_service_target(relations):
    """表节点不是登记实体：只有声明了 targetKind=Service 的关系才要求目标已登记。

    否则血缘边会被 E105 全量误报——这正是"关系级判据必须由声明驱动"的反面教材。
    """
    registry = {"services": [
        service("a", "patrol-line", relations_map={
            "reads_table": ["job_postings"],
            "queries": ["ghost"],
        }),
    ], "libraries": []}

    e105 = [f for f in check_relations(registry, relations, CONCEPTS) if f.code == "E105"]
    assert len(e105) == 1
    assert "ghost" in e105[0].message


def test_e118_relation_without_graph(relations):
    """关系必须落在某张图上，否则它既不被判也不被算——悬空声明。"""
    broken = {
        "graphs": relations["graphs"],
        "relations": {"floats": {"name": "floats", "graph": None, "status": "declared",
                                 "sub_property_of": [], "source_kinds": [], "target_kinds": []}},
        "source": relations["source"],
    }
    findings = check_relations({"services": [], "libraries": []}, broken, CONCEPTS)
    assert any(f.code == "E118" for f in findings)


def test_w307_enforced_without_instances(relations):
    """声明 enforced 却零实例 = 判定空转，属于该被提醒的纸面声明。"""
    findings = check_relations({"services": [], "libraries": []}, relations, CONCEPTS)
    assert any(f.code == "W307" for f in findings)


def test_s002_when_relations_missing():
    """关系层不可用时要明说未执行，不得静默通过。"""
    findings = check_relations({"services": [], "libraries": []}, None, CONCEPTS)
    assert [f.code for f in findings] == ["S002"]


def test_load_relations_rejects_missing_layer(tmp_path):
    with pytest.raises(LoadError):
        load_relations(tmp_path)


def test_exporter_marks_reachability_with_summary_edge(relations):
    """可达性图上的关系同时产出 typed 边与 dependsOn 汇总边；数据边只出 typed。"""
    registry = {"services": [
        service("gw", "gateway", relations_map={"calls": ["a"], "queries": ["dw"]}),
        service("a", "patrol-line", port=8001),
        service("dw", "data-gateway", port=8090),
    ], "libraries": []}

    g = build_rdf(registry, CONCEPTS, relations)
    from checker.namespaces import RCP

    assert (RCP["gw"], RCP.calls, RCP["a"]) in g
    assert (RCP["gw"], RCP.dependsOn, RCP["a"]) in g
    assert (RCP["gw"], RCP.queries, RCP["dw"]) in g
    assert (RCP["gw"], RCP.dependsOn, RCP["dw"]) not in g


def test_kind_class_normalises_kind_names():
    assert kind_class("patrol-line") == "PatrolLine"
    assert kind_class("meta") == "Meta"
