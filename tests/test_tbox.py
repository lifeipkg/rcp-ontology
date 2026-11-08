"""TBox 层（ontology/tbox/）：装载、护栏与"单一编辑面"回归。

两类用例：

1. 正向：真实 ``ontology/tbox/`` 能还原成检查层要的字典视图，且与登记里的种类对齐。
2. 反向：每条护栏各一条反例——功能属性多值、kind 不是类、缺行为属性、能力归属多值、
   缺分值、能力名不合规。规则没有反例等于没验证过（同 AGENTS.md 的约定）。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rdflib import Graph

from checker.tbox import TboxError, parse_tbox
from checker.checks import check_capability_naming
from checker.loader import load_concepts
from checker.exporter import build_rdf
from checker.validator import validate_all

ROOT = Path(__file__).resolve().parent.parent
TBOX_DIR = ROOT / "ontology" / "tbox"
TBOX_FILE = "tbox.ttl"
ONTOLOGY_DIR = ROOT / "ontology"

PREFIX = """
@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
"""


def _parse(path: Path):
    """单文件夹具：读成图再解析，与装载器的合并图路径同构。"""
    graph = Graph().parse(path, format="turtle")
    return parse_tbox(graph, path.name), graph


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
    concepts = load_concepts(ROOT)
    assert len(concepts["kinds"]) == 7
    # 16 = 原有 14 项 + 唯一 IAM 的两项能力（iam.auth / iam.users）
    assert len(concepts["capabilities"]) == 16
    assert len(concepts["decisions"]) == 6


def test_dict_view_matches_tbox_graph():
    """字典是图的视图：kind 的五个行为属性必须与图上三元组逐项一致。"""
    from rdflib.namespace import RDF

    from checker.namespaces import RCP
    from checker.abox import kebab

    concepts = load_concepts(ROOT)
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
    concepts = load_concepts(ROOT)
    scores = [d["base_score"] for d in concepts["decisions"]]
    assert scores == sorted(scores)
    assert [d["code"] for d in concepts["decisions"]][0] == "PASS"


def test_capabilities_point_at_registered_entities():
    """能力的实现者必须是登记里的实体名——否则 E111 会报，但这里先给出可读的失败。"""
    concepts = load_concepts(ROOT)
    from checker.loader import load_registry

    registry = load_registry(ROOT)
    names = {s.get("name") for s in registry["services"]} | {
        l.get("name") for l in registry["libraries"]
    }
    assert {c["owner"] for c in concepts["capabilities"]} <= names


def test_every_registered_kind_is_declared():
    """登记用的每个 kind 都必须在 TBox 里声明（E201 的装载层等价检查）。"""
    from checker.loader import load_registry

    declared = {k["name"] for k in load_concepts(ROOT)["kinds"]}
    used = {s.get("kind") for s in load_registry(ROOT)["services"]}
    assert used <= declared


def test_tbox_is_the_only_concept_source():
    """单一编辑面：概念目录只有 tbox.ttl，旧的 rcp.ttl 不得复活。"""
    files = [p.name for p in TBOX_DIR.iterdir() if p.is_file()]
    assert files and all(name.endswith(".ttl") for name in files)
    assert not (ONTOLOGY_DIR / "rcp.ttl").exists()


def test_functional_boolean_multi_value_rejected(tmp_path):
    body = _gateway(requiresPort="true, false")
    path = _write(tmp_path, body)
    with pytest.raises(TboxError, match="只允许一个值"):
        _parse(path)


def test_kind_must_be_owl_class(tmp_path):
    body = (
        "rcp:Gateway a rcp:Kind ;\n"
        '    rdfs:label "网关" ;\n'
        "    rcp:mustBeExternal true ; rcp:isEntry true ;\n"
        "    rcp:requiresPort true ; rcp:requiresContract true .\n"
    )
    path = _write(tmp_path, body)
    with pytest.raises(TboxError, match="owl:Class"):
        _parse(path)


def test_missing_behaviour_property_is_none_not_default(tmp_path):
    """缺行为属性必须留 None：补默认会让 E113 永不触发，检查器行为静默退化。"""
    path = _write(tmp_path, _gateway(mustBeExternal=None))
    concepts, _ = _parse(path)
    assert concepts["kinds"][0]["must_be_external"] is None


def test_missing_behaviour_property_triggers_e113(tmp_path):
    path = _write(tmp_path, _gateway(mustBeExternal=None))
    concepts, graph = _parse(path)
    merged = build_rdf({"services": [], "libraries": []}, {**concepts, "tbox_graph": graph})
    conforms, findings = validate_all(merged, ONTOLOGY_DIR / "shapes" / "core.ttl", concepts)
    assert conforms is False
    assert any(f.code == "E113" for f in findings)


def test_capability_implementer_multi_value_rejected(tmp_path):
    body = (
        "rcp:patrol.dispatch a rcp:Capability ;\n"
        '    rdfs:label "巡查派发" ;\n'
        "    rcp:implementedBy rcp:api-gateway, rcp:content-patrol .\n"
    )
    path = _write(tmp_path, body)
    with pytest.raises(TboxError, match="只允许一个值"):
        _parse(path)


def test_decision_without_score_is_none(tmp_path):
    body = 'rcp:PASS a rcp:Decision ; rdfs:label "放行" .\n'
    path = _write(tmp_path, body)
    concepts, _ = _parse(path)
    assert concepts["decisions"][0]["base_score"] is None


def test_capability_naming_is_enforced_in_python():
    """E114 已随 TBox 迁移移回 Python 轨：名为 IRI local name，图上无字面值可挂 pattern。"""
    findings = check_capability_naming({"capabilities": [{"name": "Patrol_Dispatch"}]})
    assert [f.code for f in findings] == ["E114"]


def test_capability_naming_accepts_dotted_names():
    findings = check_capability_naming({"capabilities": [{"name": "patrol.content.dedup"}]})
    assert findings == []
