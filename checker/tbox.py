"""TBox 解析：把 ``ontology/tbox/`` 的合并图还原成检查层使用的字典视图。

与 ``abox`` 同构：真源是三元组，检查逻辑仍跑在"实体 → 属性"的字典上。
字典是**内存视图**，没有对应的磁盘文件，因此不构成第二份真源。

还原规则（与 tbox/ 各文件顶部的书写约定一一对应）：

- 条目标识取 IRI local name：kind 再转 kebab（PatrolLine → patrol-line，与登记里的
  kind 字面值同一套归一规则），能力与决策直接用 local name，术语保留下划线；
- 种类行为属性取 ``rcp:mustBeExternal`` / ``rcp:isEntry`` / ``rcp:requiresPort`` /
  ``rcp:requiresContract``，**缺省留 None 而不是补默认值** —— 补默认会让 E113
  （"种类缺布尔属性"）永远不触发，检查器的行为在无声中退化；
- 能力归属取 ``rcp:implementedBy`` 的目标 local name（服务或库的实例 IRI）；
- 决策按 ``rcp:baseScore`` 升序返回，使 RL-003 的逐字比对有确定顺序。

功能属性（四个布尔、baseScore、implementedBy）多值即解析失败：RDF 允许多值，
这条必须显式判，它是原 YAML 严格重复键检查在 TTL 上的等价物。
"""

from __future__ import annotations

from typing import Any

from rdflib import Graph, Literal, URIRef
from rdflib.namespace import OWL, RDF, RDFS

from .abox import kebab
from .namespaces import RCP

__all__ = ["TboxError", "parse_tbox"]

# 种类行为属性：字典键 → 谓词。缺一个即 E113（由 SHACL 判，故此处不补默认值）。
_KIND_BOOLS = (
    ("must_be_external", RCP.mustBeExternal),
    ("is_entry", RCP.isEntry),
    ("requires_port", RCP.requiresPort),
    ("requires_contract", RCP.requiresContract),
)


class TboxError(ValueError):
    """TBox 图不合法（缺 owl:Class、功能属性多值、布尔或分值类型错误）。"""


def _local(node: Any) -> str:
    text = str(node)
    return text.rsplit("#", 1)[-1] if "#" in text else text.rsplit("/", 1)[-1]


def _single(g: Graph, node: URIRef, pred: URIRef, where: str) -> Any | None:
    """取功能属性的唯一值；多值即失败（等价于 YAML 的重复键）。"""
    values = list(g.objects(node, pred))
    if not values:
        return None
    if len(values) > 1:
        shown = ", ".join(str(v) for v in values)
        raise TboxError(
            f"{where} 的 {_local(pred)} 有 {len(values)} 个值（{shown}）；功能属性只允许一个值"
        )
    return values[0]


def _bool(g: Graph, node: URIRef, pred: URIRef, where: str) -> bool | None:
    raw = _single(g, node, pred, where)
    if raw is None:
        return None
    parsed = raw.toPython() if isinstance(raw, Literal) else raw
    if isinstance(parsed, bool):
        return parsed
    raise TboxError(f"{where} 的 {_local(pred)} 不是布尔值: {raw!r}")


def _text(g: Graph, node: URIRef, pred: URIRef, where: str) -> str:
    raw = _single(g, node, pred, where)
    return str(raw) if raw is not None else ""


def _int(g: Graph, node: URIRef, pred: URIRef, where: str) -> int | None:
    raw = _single(g, node, pred, where)
    if raw is None:
        return None
    try:
        return int(raw.toPython() if isinstance(raw, Literal) else raw)
    except (TypeError, ValueError):
        raise TboxError(f"{where} 的 {_local(pred)} 不是整数: {raw!r}") from None


def _kind_entries(g: Graph) -> list[dict[str, Any]]:
    kinds: list[dict[str, Any]] = []
    for node in sorted(g.subjects(RDF.type, RCP.Kind), key=str):
        where = f"kind {_local(node)}"
        # kind 同时必须是 owl:Class：登记里的种类用 rdf:type 表达，类没声明就无法归类。
        if (node, RDF.type, OWL.Class) not in g:
            raise TboxError(
                f"{where} 不是 owl:Class；种类必须同时是类（登记用 rdf:type 归类）"
            )
        entry: dict[str, Any] = {
            "name": kebab(_local(node)),
            "zh": _text(g, node, RDFS.label, where),
            "definition": _text(g, node, RCP.definition, where),
        }
        for key, pred in _KIND_BOOLS:
            entry[key] = _bool(g, node, pred, where)
        entry["allowed_depends_on_kinds"] = sorted(
            kebab(_local(target)) for target in g.objects(node, RCP.allowsDependsOn)
        )
        kinds.append(entry)
    return kinds


def _capability_entries(g: Graph) -> list[dict[str, Any]]:
    caps: list[dict[str, Any]] = []
    for node in sorted(g.subjects(RDF.type, RCP.Capability), key=str):
        where = f"capability {_local(node)}"
        implementer = _single(g, node, RCP.implementedBy, where)
        caps.append(
            {
                "name": _local(node),
                "zh": _text(g, node, RDFS.label, where),
                "definition": _text(g, node, RCP.definition, where),
                "owner": _local(implementer) if implementer is not None else "",
            }
        )
    return caps


def _decision_entries(g: Graph) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for node in g.subjects(RDF.type, RCP.Decision):
        where = f"decision {_local(node)}"
        entries.append(
            {
                "code": _local(node),
                "zh": _text(g, node, RDFS.label, where),
                "base_score": _int(g, node, RCP.baseScore, where),
                "meaning": _text(g, node, RCP.meaning, where),
            }
        )
    # 按分值升序：枚举顺序即分值顺序，RL-003 的逐字比对依赖这一确定顺序。
    # 缺分值的条目排到末尾，交给 RL-003 报"分值不一致"，而不是在这里静默排序。
    entries.sort(key=lambda d: (d["base_score"] is None, d["base_score"] or 0, d["code"]))
    return entries


def _term_entries(g: Graph) -> list[dict[str, Any]]:
    terms: list[dict[str, Any]] = []
    for node in sorted(g.subjects(RDF.type, RCP.Term), key=str):
        where = f"term {_local(node)}"
        terms.append(
            {
                "term": _local(node),
                "zh": _text(g, node, RDFS.label, where),
                "definition": _text(g, node, RCP.definition, where),
                "owner": _text(g, node, RCP.owner, where),
                "covers": sorted(kebab(_local(k)) for k in g.objects(node, RCP.covers)),
            }
        )
    return terms


def parse_tbox(graph: Graph, source: str) -> dict[str, list[dict[str, Any]]]:
    """解析 TBox 合并图，返回字典视图。"""
    data: dict[str, list[dict[str, Any]]] = {
        "kinds": _kind_entries(graph),
        "capabilities": _capability_entries(graph),
        "decisions": _decision_entries(graph),
        "terms": _term_entries(graph),
    }
    # 只判"一个概念都没认出来"：这通常意味着路径指错或层里混进了别的东西。
    # 至于 kind/decision 够不够用，由 E201/RL-003 这类具体检查判，装载器不下这个结论。
    if not any(data.values()):
        raise TboxError(
            f"{source} 里没有可识别的概念声明（kind / capability / decision / term 全空）"
        )
    return data
