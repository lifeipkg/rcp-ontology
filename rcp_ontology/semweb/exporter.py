"""L1 导出：把声明图合成一张可查询的 RDF 图。

ABox（``registry/services.ttl``）与 TBox（``concepts/tbox.ttl``）本来就是图，导出器
不做格式翻译，只做两件事：把关系实例物化成 ``dependsOn`` 汇总边、把两仓的图并成一张。
只有手工构造字典视图的调用方（测试、外部集成）才会走"字典 → 三元组"的合成路径。

三元组形态：
    rcp:content-patrol  rdf:type          rcp:PatrolLine ;
                        rcp:calls         rcp:dataway ;
                        rcp:dependsOn     rcp:dataway ;   # 可达性汇总边
                        rcp:hasCapability rcp:patrol.content.dedup ;
                        rcp:port          8081 .

为什么同时产出 typed 边与 dependsOn 汇总边：
    可达性图上的每条关系都声明了 rdfs:subPropertyOf rcp:dependsOn。这里的汇总边
    等价于 RDFS 推演的结果，导出时一次性物化——避免每个消费者（SHACL、SPARQL、
    推理机、外部工具）各自跑一遍推理才能看到闭包。派生物由单一事实导出，不回写，
    所以不构成第二份真源。非可达性图（数据、构建、部署、治理）只产出 typed 边，
    它们的边不得进入可达性计算，这正是分域的目的。

kind 通过 rdf:type 表达（OWL 的类归属），不另设 kind 数据属性——这正是
SHACL 里 sh:targetClass 能直接命中巡查线实例的前提。
"""

from __future__ import annotations

from typing import Any

from rdflib import BNode, Graph, Literal
from rdflib.namespace import RDF, RDFS, XSD

from ..relations import kind_class, relation_graph, service_relations
from .namespaces import RCP

__all__ = ["build_rdf", "kind_class"]

# 预期状态声明（expected）的字段 → 谓词。与 registry_ttl 的还原表互为逆映射，
# 两边同时改才不会丢字段。
_EXPECTED_PREDICATES = (
    ("no_dependents", RCP.noDependents, True),
    ("unreachable", RCP.unreachable, True),
    ("reason", RCP.reason, False),
    ("owner", RCP.owner, False),
    ("review_by", RCP.reviewBy, False),
)


def _service_node(
    g: Graph,
    name: str,
    service: dict[str, Any],
    relations: dict[str, Any] | None = None,
) -> None:
    node = RCP[name]
    kind = service.get("kind")
    if kind:
        g.add((node, RDF.type, RCP[kind_class(str(kind))]))
        # meta 不是服务：无端口、不部署，只登记仓边界。不挂 rcp:Service，
        # 否则 ServiceShape 的 port 必填会误报它缺端口。
        if kind_class(str(kind)) != "Meta":
            g.add((node, RDF.type, RCP.Service))
    port = service.get("port")
    if isinstance(port, int):
        g.add((node, RCP.port, Literal(port)))
    g.add((node, RCP.external, Literal(bool(service.get("external")), datatype=XSD.boolean)))
    if service.get("owner"):
        g.add((node, RCP.owner, Literal(str(service["owner"]))))
    if service.get("repo"):
        g.add((node, RCP.repo, Literal(str(service["repo"]))))
    g.add((node, RCP.name, Literal(str(name))))
    for rel, targets in service_relations(service).items():
        # 未声明的关系仍原样导出：让 E117 端点约束无从命中，但 E116 能报出这条边，
        # 而不是让它在导出环节被静默丢弃。
        graph_name = relation_graph(relations, rel) if relations else ("call" if rel == "calls" else None)
        for target in targets:
            g.add((node, RCP[rel], RCP[target]))
            if graph_name == "call":
                g.add((node, RCP.dependsOn, RCP[target]))
    for cap in service.get("capabilities") or []:
        g.add((node, RCP.hasCapability, RCP[str(cap)]))
    for rel in service.get("contracts") or []:
        g.add((node, RCP.contract, Literal(str(rel))))
    if service.get("health"):
        g.add((node, RCP.health, Literal(str(service["health"]))))
    expected = service.get("expected")
    if isinstance(expected, dict):
        detail = BNode()
        g.add((node, RCP.expected, detail))
        for key, pred, as_bool in _EXPECTED_PREDICATES:
            value = expected.get(key)
            if value is None:
                continue
            if as_bool:
                g.add((detail, pred, Literal(bool(value), datatype=XSD.boolean)))
            else:
                g.add((detail, pred, Literal(str(value))))


def _library_node(g: Graph, name: str, library: dict[str, Any]) -> None:
    node = RCP[name]
    g.add((node, RDF.type, RCP.Library))
    if library.get("owner"):
        g.add((node, RCP.owner, Literal(str(library["owner"]))))
    if library.get("artifact"):
        g.add((node, RCP.artifact, Literal(str(library["artifact"]))))
    for cap in library.get("capabilities") or []:
        g.add((node, RCP.hasCapability, RCP[str(cap)]))


def _kind_node(g: Graph, kind: dict[str, Any]) -> None:
    """把 TBox 的一个 kind 声明导出为 rcp:Kind 实例。

    kind 类名与 service 的 rdf:type 共用 kind_class 命名（patrol-line -> PatrolLine），
    因此 E201（service 的 kind 类必须是已声明的 rcp:Kind）与 E113（引用悬空）都能
    在图上闭环：未声明的 kind 类不会挂 rcp:Kind 类型。
    """
    name = kind.get("name")
    if not name:
        return
    node = RCP[kind_class(str(name))]
    g.add((node, RDF.type, RCP.Kind))
    g.add((node, RCP.name, Literal(str(name))))
    for prop, attr in (
        ("must_be_external", RCP.mustBeExternal),
        ("is_entry", RCP.isEntry),
        ("requires_port", RCP.requiresPort),
        ("requires_contract", RCP.requiresContract),
    ):
        value = kind.get(prop)
        if isinstance(value, bool):
            g.add((node, attr, Literal(value, datatype=XSD.boolean)))
    for allowed in kind.get("allowed_depends_on_kinds") or []:
        g.add((node, RCP.allowsDependsOn, RCP[kind_class(str(allowed))]))


def _relation_node(
    g: Graph,
    spec: dict[str, Any],
    graphs: dict[str, Any],
) -> None:
    """把关系类型声明导出为图上的 TBox：让导出物自描述，无需回读 relations.ttl。"""
    name = spec.get("name")
    if not name:
        return
    node = RCP[str(name)]
    g.add((node, RDF.type, RCP.RelationKind))
    g.add((node, RCP.name, Literal(str(name))))
    if spec.get("status"):
        g.add((node, RCP.status, Literal(str(spec["status"]))))
    graph_name = spec.get("graph")
    graph_spec = graphs.get(graph_name) if graph_name else None
    if graph_name:
        g.add((node, RCP.graph, Literal(str(graph_name))))
    if graph_spec and graph_spec.get("reachability"):
        g.add((node, RDFS.subPropertyOf, RCP.dependsOn))
    for kind in spec.get("source_kinds") or []:
        g.add((node, RCP.sourceKind, RCP[str(kind)]))
    for kind in spec.get("target_kinds") or []:
        g.add((node, RCP.targetKind, RCP[str(kind)]))


def build_rdf(
    registry: dict[str, Any],
    concepts: dict[str, Any],
    relations: dict[str, Any] | None = None,
) -> Graph:
    """把登记与概念声明翻译成 RDF 图。

    TBox 自带原图（``concepts["tbox_graph"]``，来自 ``concepts/tbox.ttl``）时直接并入，
    不再从字典反向合成种类/能力/决策三元组——同一事实只允许有一条产出路径，否则
    字典与图之间会多出一个可漂移的翻译器。只有手工构造字典的调用方（测试、外部集成）
    才走合成路径。

    不加载 ontology/constraints.ttl 的 shapes——那是校验，不是事实。
    """
    g = Graph()
    g.bind("rcp", RCP)
    g.bind("rdf", RDF)

    for service in registry.get("services", []):
        name = service.get("name")
        if name:
            _service_node(g, str(name), service, relations)

    if relations:
        for spec in relations.get("relations", {}).values():
            _relation_node(g, spec, relations.get("graphs", {}))

    for library in registry.get("libraries", []):
        name = library.get("name")
        if name:
            _library_node(g, str(name), library)

    tbox = concepts.get("tbox_graph")
    if tbox is not None:
        for triple in tbox:
            g.add(triple)
        return g

    for kind in concepts.get("kinds", []):
        _kind_node(g, kind)

    for cap in concepts.get("capabilities", []):
        name = cap.get("name")
        if not name:
            continue
        node = RCP[str(name)]
        g.add((node, RDF.type, RCP.Capability))
        g.add((node, RCP.name, Literal(str(name))))
        if cap.get("owner"):
            g.add((node, RCP.owner, Literal(str(cap["owner"]))))

    for decision in concepts.get("decisions", []):
        code = decision.get("code")
        if not code:
            continue
        node = RCP[str(code)]
        g.add((node, RDF.type, RCP.Decision))
        g.add((node, RCP.name, Literal(str(code))))
        score = decision.get("base_score")
        if isinstance(score, int):
            g.add((node, RCP.baseScore, Literal(score)))

    return g
