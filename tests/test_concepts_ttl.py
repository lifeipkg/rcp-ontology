"""TBox 的 TTL 真源：装载、护栏与"单一编辑面"回归。

两类用例：

1. 正向：真实 ``concepts/tbox.ttl`` 能还原成检查层要的字典视图，且与登记里的种类对齐。
2. 反向：每条护栏各一条反例——功能属性多值、kind 不是类、缺行为属性、能力归属多值、
   缺分值、能力名不合规。规则没有反例等于没验证过（同 AGENTS.md 的约定）。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from rcp_ontology.concepts_ttl import ConceptsTTLError, TBOX_FILE, parse_concepts
from rcp_ontology.checks import check_capability_naming
from rcp_ontology.loader import load_concepts
from rcp_ontology.semweb import build_rdf, validate_all

ROOT = Path(__file__).resolve().parent.parent
CONCEPTS_DIR = ROOT / "concepts"
ONTOLOGY_DIR = ROOT / "ontology"

PREFIX = """
@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
"""


def _write(tmp_path: Path, body: str) -> Path:
    path = tmp_path / TBOX_FILE
    path.write_text(PREFIX + body, encoding="utf-8")
    return path


def _gateway(**overrides) -> str:
    props = {
        "mustBeExternal": "true",
        "isEntry": "true",
        "requiresPort": "true",
        "requiresContract": "true",
    }
    props.update(overrides)
    lines = "".join(
        f"    rcp:{pred} {value} ;\n" for pred, value in props.items() if value is not None
    )
    return (
        "rcp:Gateway a owl:Class, rcp:Kind ;\n"
        '    rdfs:label "网关" ;\n'
        f"{lines}"
        "    rcp:definition \"对外入口\" .\n"
    )


def test_real_tbox_loads_three_layers():
    concepts = load_concepts(CONCEPTS_DIR)
    assert len(concepts["kinds"]) == 6
    assert len(concepts["capabilities"]) == 14
    assert len(concepts["decisions"]) == 6


def test_dict_view_matches_tbox_graph():
    """字典是图的视图：kind 的五个行为属性必须与图上三元组逐项一致。"""
    from rdflib.namespace import RDF

    from rcp_ontology.namespaces import RCP
    from rcp_ontology.registry_ttl import kebab

    concepts = load_concepts(CONCEPTS_DIR)
    graph = concepts["tbox_graph"]
    by_class = {kebab(str(s).rsplit("#", 1)[-1]): s for s in graph.subjects(RDF.type, RCP.Kind)}
    for kind in concepts["kinds"]:
        node = by_class[kind["name"]]
        for key, pred in (
            ("must_be_external", RCP.mustBeExternal),
            ("is_entry", RCP.isEntry),
            ("requires_port", RCP.requiresPort),
            ("requires_contract", RCP.requiresContract),
        ):
            values = [v.toPython() for v in graph.objects(node, pred)]
            assert values == [kind[key]], f"{kind['name']}.{key} 与图不一致"
        allowed = sorted(kebab(str(v).rsplit("#", 1)[-1]) for v in graph.objects(node, RCP.allowsDependsOn))
        assert allowed == kind["allowed_depends_on_kinds"]


def test_decisions_sorted_by_score():
    """RL-003 是逐字比对，顺序必须确定：按分值升序，与契约层 enum 顺序一致。"""
    concepts = load_concepts(CONCEPTS_DIR)
    scores = [d["base_score"] for d in concepts["decisions"]]
    assert scores == sorted(scores)
    assert [d["code"] for d in concepts["decisions"]][0] == "PASS"


def test_capabilities_point_at_registered_entities():
    """能力的实现者必须是登记里的实体名——否则 E111 会报，但这里先给出可读的失败。"""
    concepts = load_concepts(CONCEPTS_DIR)
    contracts = Path(
        os.environ.get("RCP_CONTRACTS") or ROOT.parent / "rcp-contracts"
    )
    if not contracts.is_dir():
        pytest.skip("工作区无 rcp-contracts")
    from rcp_ontology.loader import load_registry

    registry = load_registry(contracts)
    names = {s.get("name") for s in registry["services"]} | {
        l.get("name") for l in registry["libraries"]
    }
    assert {c["owner"] for c in concepts["capabilities"]} <= names


def test_every_registered_kind_is_declared():
    """登记用的每个 kind 都必须在 TBox 里声明（E201 的装载层等价检查）。"""
    contracts = Path(os.environ.get("RCP_CONTRACTS") or ROOT.parent / "rcp-contracts")
    if not contracts.is_dir():
        pytest.skip("工作区无 rcp-contracts")
    from rcp_ontology.loader import load_registry

    declared = {k["name"] for k in load_concepts(CONCEPTS_DIR)["kinds"]}
    used = {s.get("kind") for s in load_registry(contracts)["services"]}
    assert used <= declared


def test_tbox_is_the_only_concept_source():
    """单一编辑面：概念目录只有 tbox.ttl，旧的 rcp.ttl 不得复活。"""
    assert sorted(p.name for p in CONCEPTS_DIR.iterdir() if p.is_file()) == [TBOX_FILE]
    assert not (ONTOLOGY_DIR / "rcp.ttl").exists()


def test_functional_boolean_multi_value_rejected(tmp_path):
    body = _gateway(requiresPort="true, false")
    path = _write(tmp_path, body)
    with pytest.raises(ConceptsTTLError, match="只允许一个值"):
        parse_concepts(path)


def test_kind_must_be_owl_class(tmp_path):
    body = (
        "rcp:Gateway a rcp:Kind ;\n"
        '    rdfs:label "网关" ;\n'
        "    rcp:mustBeExternal true ; rcp:isEntry true ;\n"
        "    rcp:requiresPort true ; rcp:requiresContract true .\n"
    )
    path = _write(tmp_path, body)
    with pytest.raises(ConceptsTTLError, match="owl:Class"):
        parse_concepts(path)


def test_missing_behaviour_property_is_none_not_default(tmp_path):
    """缺行为属性必须留 None：补默认会让 E113 永不触发，检查器行为静默退化。"""
    path = _write(tmp_path, _gateway(mustBeExternal=None))
    concepts, _ = parse_concepts(path)
    assert concepts["kinds"][0]["must_be_external"] is None


def test_missing_behaviour_property_triggers_e113(tmp_path):
    path = _write(tmp_path, _gateway(mustBeExternal=None))
    concepts, graph = parse_concepts(path)
    merged = build_rdf({"services": [], "libraries": []}, {**concepts, "tbox_graph": graph})
    conforms, findings = validate_all(merged, ONTOLOGY_DIR / "constraints.ttl", concepts)
    assert conforms is False
    assert any(f.code == "E113" for f in findings)


def test_capability_implementer_multi_value_rejected(tmp_path):
    body = (
        "rcp:patrol.dispatch a rcp:Capability ;\n"
        '    rdfs:label "巡查派发" ;\n'
        "    rcp:implementedBy rcp:api-gateway, rcp:content-patrol .\n"
    )
    path = _write(tmp_path, body)
    with pytest.raises(ConceptsTTLError, match="只允许一个值"):
        parse_concepts(path)


def test_decision_without_score_is_none(tmp_path):
    body = 'rcp:PASS a rcp:Decision ; rdfs:label "放行" .\n'
    path = _write(tmp_path, body)
    concepts, _ = parse_concepts(path)
    assert concepts["decisions"][0]["base_score"] is None


def test_capability_naming_is_enforced_in_python():
    """E114 已随 TBox 迁移移回 Python 轨：名为 IRI local name，图上无字面值可挂 pattern。"""
    findings = check_capability_naming({"capabilities": [{"name": "Patrol_Dispatch"}]})
    assert [f.code for f in findings] == ["E114"]


def test_capability_naming_accepts_dotted_names():
    findings = check_capability_naming({"capabilities": [{"name": "patrol.content.dedup"}]})
    assert findings == []
