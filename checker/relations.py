"""关系层：关系类型与公理在 tbox/relations.ttl，实例边从 ABox 读取并规范化。

分工是"断言"与"事实"的分工：

- ``tbox/relations.ttl``：有哪些关系、属于哪张图、该图是否参与可达性、端点种类约束、
  是否已启用判定。这些是「关于关系的断言」，无法从任何 key: value 属性推导，
  只能写成语义三元组。
- ``abox/services.ttl``：谁对谁有这条边，是可评审的事实。

所以真源不是「某一种格式」，而是「每一层只有一个目录」。关系有 N 条时，加一条关系
只改 relations.ttl，不改本文件、不改 checks、不改 shapes。

旧字段 ``depends_on`` 等价于 ``calls``：作为兼容别名保留，供外部集成把旧的字典视图
喂进来（磁盘上已经没有 YAML 了，这条只影响内存视图）。
"""

from __future__ import annotations

from typing import Any

from rdflib import Graph
from rdflib.namespace import RDF, RDFS

from .namespaces import RCP

# 登记里的旧字段 → 关系名。新增关系不要往这里加：加进 relations.ttl。
LEGACY_FIELD_ALIASES = {"depends_on": "calls"}

# 关系实例在登记里的两种写法：关系映射，或旧的 depends_on 列表。
RELATIONS_FIELD = "relations"


def _local(node: Any) -> str:
    text = str(node)
    return text.rsplit("#", 1)[-1] if "#" in text else text


def kind_class(kind: str) -> str:
    """把 kind 名转成 OWL 类名：data-gateway -> DataGateway。

    关系端点约束在 TTL 里写的是 OWL 类（rcp:Service / rcp:Iam），登记里写的是
    kind 名（service / iam），两侧比对必须先归一。
    """
    return "".join(part.capitalize() for part in str(kind).split("-"))


def parse_relations(graph: Graph, source: str) -> dict[str, Any]:
    """从 TBox 合并图里提取图与关系的声明视图。

    返回::

        {
          "graphs": {"call": {"name", "label", "reachability"}},
          "relations": {"calls": {"name", "graph", "status", "sub_property_of",
                                  "source_kinds", "target_kinds"}},
          "source": "kinds.ttl, relations.ttl, schema.ttl",
        }

    图名与关系名一律取 ``rcp:name`` 的字面值（不是 IRI local name），
    这样 kebab / snake 命名不受 RDF 谓词写法限制。

    只筛选**已声明**的关系与图：schema.ttl 里的 owl:ObjectProperty 不带 rcp:name，
    因此不会混进来。
    """
    graphs: dict[str, dict[str, Any]] = {}
    for node in graph.subjects(RDF.type, RCP.RelationGraph):
        name = graph.value(node, RCP.name)
        if not name:
            continue
        graphs[str(name)] = {
            "name": str(name),
            "label": str(graph.value(node, RDFS.label) or ""),
            "reachability": bool(graph.value(node, RCP.reachability)),
        }

    relations: dict[str, dict[str, Any]] = {}
    for node in graph.subjects(RDF.type, RCP.RelationKind):
        name = graph.value(node, RCP.name)
        if not name:
            continue
        graph_node = graph.value(node, RCP.graph)
        graph_name = ""
        if graph_node is not None:
            raw = graph.value(graph_node, RCP.name)
            graph_name = str(raw) if raw is not None else _local(graph_node)
        relations[str(name)] = {
            "name": str(name),
            "graph": graph_name,
            "status": str(graph.value(node, RCP.status) or "declared"),
            "sub_property_of": [
                _local(o) for o in graph.objects(node, RDFS.subPropertyOf)
            ],
            "source_kinds": [_local(v) for v in graph.objects(node, RCP.sourceKind)],
            "target_kinds": [_local(v) for v in graph.objects(node, RCP.targetKind)],
        }

    if not relations:
        raise ValueError(f"{source} 里没有任何关系声明（缺 `a rcp:RelationKind`）")
    return {"graphs": graphs, "relations": relations, "source": source}


def relation_graph(relations: dict[str, Any], name: str) -> str | None:
    """某条关系所属的图名；未声明返回 None。"""
    spec = relations.get("relations", {}).get(name)
    return spec.get("graph") if spec else None


def reachability_graphs(relations: dict[str, Any]) -> set[str]:
    """参与可达性计算的图名集合（在这些图上算环、入度与不可达）。"""
    return {n for n, g in relations.get("graphs", {}).items() if g.get("reachability")}


def service_relations(service: dict[str, Any]) -> dict[str, list[str]]:
    """把一条登记规范化成「关系名 → 目标列表」。

    支持两种写法混用::

        relations:
          calls: [dataway]
          queries: [dataway]
        depends_on: [dataway]      # 等价于 relations.calls
    """
    out: dict[str, list[str]] = {}
    declared = service.get(RELATIONS_FIELD)
    if isinstance(declared, dict):
        for rel, targets in declared.items():
            if isinstance(targets, str):
                targets = [targets]
            if isinstance(targets, list) and targets:
                out[str(rel)] = [str(t) for t in targets]

    for field, rel in LEGACY_FIELD_ALIASES.items():
        legacy = service.get(field)
        if isinstance(legacy, list) and legacy:
            merged = out.setdefault(rel, [])
            merged.extend(str(t) for t in legacy if str(t) not in merged)
    return out


def iter_edges(
    registry: dict[str, Any],
) -> list[tuple[str, str, str]]:
    """展开全部边：(源服务, 关系名, 目标)。只含已登记 name 的服务。"""
    edges: list[tuple[str, str, str]] = []
    for service in registry.get("services", []):
        source = service.get("name")
        if not source:
            continue
        for rel, targets in service_relations(service).items():
            for target in targets:
                edges.append((str(source), rel, target))
    return edges


def declared_names(relations: dict[str, Any]) -> set[str]:
    return set(relations.get("relations", {}))
