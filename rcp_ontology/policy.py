"""规则层解析：把 ``ontology/policy/redlines.ttl`` 还原成检查层使用的字典视图。

红线的规格（spec）是 policy-as-code：一个空白节点上的谓词即执行参数。因此这里
只写一条**通用**的图 → 字典规则，不为每种 spec 类型写专门解析：

- 空白节点 → 字典（递归）；
- RDF 列表 ``( "a" "b" )`` → Python list；
- 字面量 → Python 值（布尔、整数、日期按 xsd 类型还原）；
- IRI → local name 字符串；
- 谓词 local name → snake_case 字典键（allowPrefixes → allow_prefixes）。

唯一的特例是 spec 的 ``rdf:type``：类名转 kebab 即 spec.type（FileScan → file-scan），
执行器据此分派。这是"规则即数据"的锚点 —— 新增一种 spec 类型 = 新增一个类 + 一个
执行器，不需要在解析层登记键名白名单。

复数参数在 TTL 里写成列表 ``rcp:include ( "*.sql" )``，单数写成字面量。这样"单值还是
列表"由**图结构**决定，不靠 Python 里的键名猜测 —— 猜错会让 ``include`` 变成字符串，
遍历时逐字符匹配，是那种不会报错但永远不命中的错。
"""

from __future__ import annotations

from typing import Any

from rdflib import BNode, Graph, Literal, URIRef
from rdflib.namespace import RDF, RDFS

from .abox import kebab, snake
from .namespaces import RCP

__all__ = ["PolicyError", "parse_redlines"]


class PolicyError(ValueError):
    """规则层图不合法（红线缺 id、spec 不是结构、例外缺必填字段）。"""


_IGNORED = {RDFS.label, RDFS.comment, RDFS.seeAlso, RDF.type}


def _local(node: Any) -> str:
    text = str(node)
    return text.rsplit("#", 1)[-1] if "#" in text else text.rsplit("/", 1)[-1]


def _is_list(g: Graph, node: Any) -> bool:
    return node == RDF.nil or (isinstance(node, BNode) and g.value(node, RDF.first) is not None)


def _rdf_list(g: Graph, head: Any) -> list[Any]:
    items: list[Any] = []
    node = head
    while node != RDF.nil:
        first = g.value(node, RDF.first)
        if first is None:
            break
        items.append(_value(g, first))
        node = g.value(node, RDF.rest)
        if node is None:
            break
    return items


def _value(g: Graph, node: Any) -> Any:
    """把一个 RDF 节点还原成 Python 值。"""
    if isinstance(node, Literal):
        return node.toPython()
    if isinstance(node, URIRef):
        return _local(node)
    if _is_list(g, node):
        return _rdf_list(g, node)
    return _node_dict(g, node)


def _node_dict(g: Graph, node: Any) -> dict[str, Any]:
    """空白节点 → 字典。谓词 local name 转 snake_case；多值即列表。"""
    out: dict[str, Any] = {}
    for pred in set(g.predicates(node, None)):
        if pred in _IGNORED:
            continue
        key = snake(_local(pred))
        values = [_value(g, obj) for obj in g.objects(node, pred)]
        out[key] = values[0] if len(values) == 1 else values
    return out


def _spec_of(g: Graph, node: Any, where: str) -> dict[str, Any] | None:
    """解析一条红线的 spec：rdf:type 的 kebab 即 spec.type。"""
    if node is None:
        return None
    if not isinstance(node, BNode):
        raise PolicyError(f"{where} 的 spec 必须是空白节点（[ ... ]）")
    spec = _node_dict(g, node)
    types = [kebab(_local(t)) for t in g.objects(node, RDF.type) if str(t).startswith(str(RCP))]
    if len(types) > 1:
        raise PolicyError(f"{where} 的 spec 声明了多个类型（{', '.join(types)}）")
    if not types:
        raise PolicyError(f"{where} 的 spec 缺少 `a rcp:XXX` 类型声明，执行器无法分派")
    spec = {"type": types[0], **spec}
    return dict(sorted(spec.items()))


def _redline_entry(g: Graph, node: URIRef) -> dict[str, Any]:
    where = f"redline {_local(node)}"
    redline_id = g.value(node, RCP.redlineId)
    if not redline_id:
        raise PolicyError(f"{where} 缺 rcp:redlineId")
    entry: dict[str, Any] = {
        "id": str(redline_id),
        "name": str(g.value(node, RCP.slug) or ""),
        "zh": str(g.value(node, RDFS.label) or ""),
        "rationale": str(g.value(node, RCP.rationale) or ""),
        "rule": str(g.value(node, RCP.rule) or ""),
        "spec": _spec_of(g, g.value(node, RCP.spec), where),
    }
    return entry


def _exception_entry(g: Graph, node: URIRef) -> dict[str, Any]:
    where = f"exception {_local(node)}"
    redline = g.value(node, RCP.redline)
    if not redline:
        raise PolicyError(f"{where} 未指向任何红线（缺 rcp:redline）")
    target = g.value(redline, RCP.redlineId)
    entry: dict[str, Any] = {
        "id": _local(node),
        "redline": str(target) if target else _local(redline),
        "scope": str(g.value(node, RCP.scope) or ""),
        "match": str(g.value(node, RCP.match) or ""),
        "reason": str(g.value(node, RCP.reason) or ""),
        "owner": str(g.value(node, RCP.owner) or ""),
        "review_by": str(g.value(node, RCP.reviewBy) or ""),
    }
    return entry


def parse_redlines(graph: Graph, source: str) -> dict[str, Any]:
    """解析规则层合并图，返回 {"constraints": [...], "exceptions": [...]}。"""
    constraints = [
        _redline_entry(graph, node)
        for node in sorted(graph.subjects(RDF.type, RCP.Redline), key=str)
    ]
    seen: set[str] = set()
    for item in constraints:
        if item["id"] in seen:
            raise PolicyError(f"红线编号重复: {item['id']}")
        seen.add(item["id"])

    exceptions = [
        _exception_entry(graph, node)
        for node in sorted(graph.subjects(RDF.type, RCP.Exception), key=str)
    ]
    for item in exceptions:
        if item["redline"] not in seen:
            raise PolicyError(
                f"例外 {item['id']} 指向未声明的红线 {item['redline']}（登记了不存在的东西）"
            )

    if not constraints:
        raise PolicyError(f"{source} 里没有任何红线声明（缺 `a rcp:Redline`）")
    return {"constraints": constraints, "exceptions": exceptions}
