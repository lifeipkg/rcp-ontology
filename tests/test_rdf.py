"""语义网层测试：SPARQL 与 graph.py 的口径交叉验证，SHACL 合规与反例。

BFS 与 SPARQL 属性路径是两条不同口径（分域 vs 可达性汇总），在可达性图上必须
给出相同的闭包——

    graph.py  reachable_from    手写 BFS，按关系所属图分域
    query.py  dependsOn+        SPARQL 图遍历，只覆盖 exporter 物化了汇总边的图

两者在可达性图上的结论必须一致，否则说明 exporter 的汇总边或 SPARQL 路径写错了。
"""

from __future__ import annotations

from pathlib import Path

from rdflib.namespace import RDF

from checker import graph as G
from checker.exporter import build_rdf
from checker.namespaces import RCP
from checker.query import dependents_of as sparql_dependents_of
from checker.validator import validate_all

ROOT = Path(__file__).resolve().parent.parent
ONTOLOGY_DIR = ROOT / "ontology"

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


def test_sparql_matches_bfs_closure():
    registry = _transitive_chain()
    graph = G.build_graph(registry)
    g = build_rdf(registry, CONCEPTS)
    assert sparql_dependents_of(g, "c") == G.dependents_of(graph, "c") == {"a", "b"}


def test_sparql_matches_bfs_on_real_registry():
    """集成：用真实登记，SPARQL 与 BFS 对每个服务的被依赖闭包逐字一致。

    这是两条口径的交叉校验——BFS 按分域邻接表算，SPARQL 走 exporter 物化的
    dependsOn 汇总边。两者在可达性图上若不相等，说明汇总边或属性路径写错了。
    """
    import os

    root = Path(os.environ.get("RCP_ONTOLOGY") or Path(__file__).resolve().parent.parent)
    if not (root / "ontology" / "abox").is_dir():
        import pytest
        pytest.skip("工作区无本体仓，跳过集成交叉验证")

    from checker.loader import load_concepts, load_registry

    registry = load_registry(root)
    concepts = load_concepts(root)

    graph = G.build_graph(registry)
    g = build_rdf(registry, concepts)

    for service in graph:
        assert sparql_dependents_of(g, service) == G.dependents_of(graph, service)


def test_shacl_conforms_on_valid_data():
    registry = {"services": [
        _service("api-gateway", "gateway", 8080, depends_on=["content-patrol"],
                 contracts=["gateway.contract"]),
        _service("content-patrol", "patrol-line", 8081,
                 contracts=["patrol.contract"]),
    ], "libraries": []}
    g = build_rdf(registry, CONCEPTS)
    conforms, findings = validate_all(g, ONTOLOGY_DIR / "shapes" / "core.ttl", CONCEPTS)
    assert conforms is True
    assert findings == []


def test_shacl_catches_missing_port():
    registry = {"services": [_service("api-gateway", "gateway", None)], "libraries": []}
    g = build_rdf(registry, CONCEPTS)
    conforms, findings = validate_all(g, ONTOLOGY_DIR / "shapes" / "core.ttl", CONCEPTS)
    assert conforms is False
    assert any(f.code == "E001" for f in findings)


def test_shacl_catches_patrol_line_cross_call():
    """RL-001：巡查线不得依赖巡查线。SHACL 的 maxCount 0 捕获该违规。"""
    registry = {"services": [
        _service("a", "patrol-line", 8001, depends_on=["b"]),
        _service("b", "patrol-line", 8002),
    ], "libraries": []}
    g = build_rdf(registry, CONCEPTS)
    conforms, findings = validate_all(g, ONTOLOGY_DIR / "shapes" / "core.ttl", CONCEPTS)
    assert conforms is False
    assert any(f.code == "RL-001" for f in findings)
