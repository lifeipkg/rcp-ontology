"""语义网层测试：OWL 推理 / SPARQL / graph.py 三者交叉验证，SHACL 合规与反例。

核心断言：对同一张依赖图，三种范式给出相同的传递闭包——
    graph.py  reachable_from    手写 BFS
    reasoner  owlrl 物化        推理机推导
    query.py  dependsOn+        SPARQL 图遍历

这三者算出的闭包必须逐字节一致，否则说明其中一种实现的图语义有偏差。
"""

from __future__ import annotations

from pathlib import Path

from rdflib.namespace import RDF

from rcp_ontology import graph as G
from rcp_ontology.semweb import (
    RCP,
    build_rdf,
    infer_transitive,
    inferred_dependents_of,
    sparql_dependents_of,
    validate_all,
)

ONTOLOGY_DIR = Path(__file__).resolve().parent.parent / "ontology"

CONCEPTS = {
    "kinds": [
        {"name": "gateway", "must_be_external": True, "is_entry": True,
         "requires_port": True, "requires_contract": True,
         "allowed_depends_on_kinds": ["patrol-line"]},
        {"name": "patrol-line", "must_be_external": False, "is_entry": False,
         "requires_port": True, "requires_contract": True,
         "allowed_depends_on_kinds": []},
        {"name": "frontend", "must_be_external": True, "is_entry": True,
         "requires_port": True, "requires_contract": False,
         "allowed_depends_on_kinds": ["gateway"]},
        {"name": "meta", "must_be_external": False, "is_entry": True,
         "requires_port": False, "requires_contract": False,
         "allowed_depends_on_kinds": []},
    ],
    "capabilities": [
        {"name": "patrol.dispatch", "owner": "api-gateway"},
        {"name": "patrol.content.dedup", "owner": "content-patrol"},
    ],
    "decisions": [
        {"code": "PASS", "base_score": 0},
        {"code": "INTERCEPT", "base_score": 80},
    ],
}


def _service(name: str, kind: str, port: int | None, depends_on=(), **extra):
    base = {
        "name": name, "repo": f"rcp-{name}", "kind": kind,
        "external": kind in ("gateway", "frontend"), "owner": "platform",
        "capabilities": [], "depends_on": list(depends_on), "contracts": [],
    }
    if port is not None:
        base["port"] = port
    base.update(extra)
    return base


def _transitive_chain():
    """a → b → c：a 传递依赖 c（两跳）。只验图闭包，不涉及红线语义。"""
    return {"services": [
        _service("a", "gateway", 8000, depends_on=["b"]),
        _service("b", "patrol-line", 8001, depends_on=["c"]),
        _service("c", "patrol-line", 8002),
    ], "libraries": []}


def _data_graph(registry, concepts):
    g = build_rdf(registry, concepts)
    g.parse(ONTOLOGY_DIR / "rcp.ttl", format="turtle")
    return g


def test_build_rdf_assigns_kind_class():
    registry = _transitive_chain()
    g = build_rdf(registry, CONCEPTS)
    assert (RCP["a"], RDF.type, RCP.Gateway) in g
    assert (RCP["a"], RDF.type, RCP.Service) in g
    assert (RCP["b"], RDF.type, RCP.PatrolLine) in g
    assert (RCP["a"], RCP.dependsOn, RCP["b"]) in g


def test_meta_is_not_typed_as_service():
    """meta 无端口、不部署，不得挂 rcp:Service，否则 ServiceShape 的 port 必填会误报。"""
    registry = {"services": [_service("contracts", "meta", None)], "libraries": []}
    g = build_rdf(registry, CONCEPTS)
    assert (RCP["contracts"], RDF.type, RCP.Meta) in g
    assert (RCP["contracts"], RDF.type, RCP.Service) not in g


def test_owl_inference_matches_bfs_closure():
    registry = _transitive_chain()
    graph = G.build_graph(registry)
    g = _data_graph(registry, CONCEPTS)
    infer_transitive(g)
    # c 的直接+间接依赖方：b 直接依赖 c，a 经 b 传递依赖 c。
    assert G.dependents_of(graph, "c") == {"a", "b"}
    assert inferred_dependents_of(g, "c") == {"a", "b"}


def test_sparql_matches_bfs_closure():
    registry = _transitive_chain()
    graph = G.build_graph(registry)
    g = build_rdf(registry, CONCEPTS)
    assert sparql_dependents_of(g, "c") == G.dependents_of(graph, "c") == {"a", "b"}


def test_three_paradigms_agree_on_real_registry():
    """集成：用真实登记，三种范式对每个服务的被依赖闭包逐字一致。"""
    import os

    contracts = Path(
        os.environ.get("RCP_CONTRACTS")
        or Path(__file__).resolve().parent.parent.parent / "rcp-contracts"
    )
    if not contracts.is_dir():
        import pytest
        pytest.skip("工作区无 rcp-contracts，跳过集成交叉验证")

    from rcp_ontology.loader import load_concepts, load_registry

    concepts_dir = Path(__file__).resolve().parent.parent / "concepts"
    registry = load_registry(contracts)
    concepts = load_concepts(concepts_dir)

    graph = G.build_graph(registry)
    g = build_rdf(registry, concepts)
    inferred = _data_graph(registry, concepts)
    infer_transitive(inferred)

    for service in graph:
        assert inferred_dependents_of(inferred, service) == G.dependents_of(graph, service)
        assert sparql_dependents_of(g, service) == G.dependents_of(graph, service)


def test_shacl_conforms_on_valid_data():
    registry = {"services": [
        _service("api-gateway", "gateway", 8080, depends_on=["content-patrol"],
                 contracts=["gateway.contract"]),
        _service("content-patrol", "patrol-line", 8081,
                 contracts=["patrol.contract"]),
    ], "libraries": []}
    g = build_rdf(registry, CONCEPTS)
    conforms, findings = validate_all(g, ONTOLOGY_DIR / "constraints.ttl", CONCEPTS)
    assert conforms is True
    assert findings == []


def test_shacl_catches_missing_port():
    registry = {"services": [_service("api-gateway", "gateway", None)], "libraries": []}
    g = build_rdf(registry, CONCEPTS)
    conforms, findings = validate_all(g, ONTOLOGY_DIR / "constraints.ttl", CONCEPTS)
    assert conforms is False
    assert any(f.code == "E001" for f in findings)


def test_shacl_catches_patrol_line_cross_call():
    """RL-001：巡查线不得依赖巡查线。SHACL 的 maxCount 0 捕获该违规。"""
    registry = {"services": [
        _service("a", "patrol-line", 8001, depends_on=["b"]),
        _service("b", "patrol-line", 8002),
    ], "libraries": []}
    g = build_rdf(registry, CONCEPTS)
    conforms, findings = validate_all(g, ONTOLOGY_DIR / "constraints.ttl", CONCEPTS)
    assert conforms is False
    assert any(f.code == "RL-001" for f in findings)
