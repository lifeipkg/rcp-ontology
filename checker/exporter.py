"""L1 导出：把声明图合成一张可查询的 RDF 图。

本模块接收的是装载层解析出的**字典视图**（``abox.py`` / ``tbox.py`` 的输出），
把它们重新合成三元组。因此当前数据流是一个往返：

    原始 TTL ──rdflib──> Graph ──装载层──> 字典 ──本模块──> Graph

原始图在装载后本可保留，却先降级为字典、再在此处重建。生产路径全部走这条往返——
``check_shacl``、``export``、``shacl``、``sparql`` 四个命令都调用 ``build_rdf``，
不只是测试与外部集成。

暂不消除的原因：``checks.py`` 的判定逻辑按字典形态编写且体量较大（883 行），
直接改为查询 Graph 是一次独立重构，不属于本次收敛范围。在此之前必须注意：
本模块的谓词映射与 ``abox.py`` 的还原映射**互为逆映射**，两边同时改才不会丢字段。

一处例外：**架构层实例**（团队、契约、表、存储、工作负载、环境、命名空间、边界、
流水线、门禁）不属于 services / libraries，字典视图不承载它们。这部分直接从
``registry["abox_graph"]``（abox/ 的合并原图）并入，跳过已登记的服务主体——同一事实
不建第二条产出路径。没有这条并入，``shapes/core.ttl`` 里针对架构资产的 E210–E213
会全部空转。

三元组形态：
    rcp:dataway         rdf:type          rcp:DataGateway ;
                        rcp:calls         rcp:api-gateway ;
                        rcp:dependsOn     rcp:api-gateway ;   # 可达性汇总边
                        rcp:hasCapability rcp:data.query ;
                        rcp:port          8090 .

为什么同时产出 typed 边与 dependsOn 汇总边：
    可达性图上的每条关系都声明了 rdfs:subPropertyOf rcp:dependsOn。这里的汇总边
    等价于 RDFS 推演的结果，导出时一次性物化——避免每个消费者（SHACL、SPARQL、
    推理机、外部工具）各自跑一遍推理才能看到闭包。派生物由单一事实导出，不回写，
    所以不构成第二份真源。非可达性图（数据、构建、部署、治理）只产出 typed 边，
    它们的边不得进入可达性计算，这正是分域的目的。

kind 通过 rdf:type 表达（OWL 的类归属），不另设 kind 数据属性——这正是
SHACL 里 sh:targetClass 能直接命中服务实例的前提。
"""

from __future__ import annotations

from typing import Any

from rdflib import BNode, Graph, Literal
from rdflib.namespace import RDF, RDFS, XSD

from .namespaces import RCP
from .relations import kind_class, relation_graph, service_relations

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

    kind 类名与 service 的 rdf:type 共用 kind_class 命名（worker -> Worker），
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

    TBox 自带原图（``concepts["tbox_graph"]``，来自 tbox/ 的合并图）时直接并入，
    不再从字典反向合成种类/能力/决策三元组——同一事实只允许有一条产出路径，否则
    字典与图之间会多出一个可漂移的翻译器。只有手工构造字典的调用方（测试、外部集成）
    才走合成路径。

    不加载 shapes/core.ttl 的 shapes——那是校验，不是事实。
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

    # 架构层实例（团队、契约、表、存储、工作负载、环境、命名空间、边界、流水线、门禁）
    # 不在 services/libraries 字典里，只能从 ABox 原图并入。已登记的服务/库主体跳过：
    # 那部分已由上面的字典路径产出，同一事实不建第二条产出路径。
    abox = registry.get("abox_graph")
    if abox is not None:
        covered = {
            RCP[str(entry["name"])]
            for entry in list(registry.get("services") or []) + list(registry.get("libraries") or [])
            if entry.get("name")
        }
        for subject, predicate, obj in abox:
            if subject not in covered:
                g.add((subject, predicate, obj))

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

    return g
