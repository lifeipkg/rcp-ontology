"""L1 导出层：把 YAML 声明（registry + concepts）单向翻译成 RDF 图。

这是语义网层的入口。ABox（services/libraries）与 TBox（kinds/capabilities/decisions）
被转成 RDF 三元组。方向是单向导出——YAML 仍是"真源"，RDF 是它的图形态，
不反向写回 YAML。

三元组形态：
    rcp:content-patrol  rdf:type          rcp:PatrolLine ;
                        rcp:dependsOn     rcp:dataway ;
                        rcp:hasCapability rcp:patrol.content.dedup ;
                        rcp:port          8081 .

kind 通过 rdf:type 表达（OWL 的类归属），不另设 kind 数据属性——这正是
SHACL 里 sh:targetClass 能直接命中巡查线实例的前提。
"""

from __future__ import annotations

from typing import Any

from rdflib import Graph, Literal
from rdflib.namespace import RDF, XSD

from .namespaces import RCP


def kind_class(kind: str) -> str:
    """把 kind 名转成 OWL 类名：patrol-line -> PatrolLine。"""
    return "".join(part.capitalize() for part in kind.split("-"))


def _service_node(g: Graph, name: str, service: dict[str, Any]) -> None:
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
    for dep in service.get("depends_on") or []:
        g.add((node, RCP.dependsOn, RCP[str(dep)]))
    for cap in service.get("capabilities") or []:
        g.add((node, RCP.hasCapability, RCP[str(cap)]))


def _library_node(g: Graph, name: str, library: dict[str, Any]) -> None:
    node = RCP[name]
    g.add((node, RDF.type, RCP.Library))
    if library.get("owner"):
        g.add((node, RCP.owner, Literal(str(library["owner"]))))
    if library.get("artifact"):
        g.add((node, RCP.artifact, Literal(str(library["artifact"]))))
    for cap in library.get("capabilities") or []:
        g.add((node, RCP.hasCapability, RCP[str(cap)]))


def build_rdf(registry: dict[str, Any], concepts: dict[str, Any]) -> Graph:
    """把登记与概念声明翻译成 RDF 图。

    不加载 ontology/rcp.ttl 的本体公理——那由 reasoner 在需要推理时合并。
    这里只产出"实例层"事实；类与属性定义在 ontology/rcp.ttl。
    """
    g = Graph()
    g.bind("rcp", RCP)
    g.bind("rdf", RDF)

    for service in registry.get("services", []):
        name = service.get("name")
        if name:
            _service_node(g, str(name), service)

    for library in registry.get("libraries", []):
        name = library.get("name")
        if name:
            _library_node(g, str(name), library)

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
