"""ABox 解析：把 ``ontology/abox/`` 的合并图还原成检查层使用的字典视图。

为什么要有这一层：检查逻辑（必填字段、端口冲突、图算法、渲染）全部建立在
"服务 → 属性"的字典上，而真源是三元组。两种做法可选：

1. 改掉全部检查，让它们直接查图 —— 改动面是全部 check 函数与图算法，风险最大；
2. 只在装载处做一次"图 → 视图"的还原，检查层一行不改。

选 2。字典是**内存视图**，没有对应的磁盘文件，所以不构成第二份真源。

还原规则（与 abox/services.ttl 顶部四条书写约定一一对应）：

- 实例的 local name 即服务名（不读 rcp:name，避免同一事实两个位置）；
- 种类取 ``rdf:type`` 中除 rcp:Service / rcp:Library 之外的 rcp 类，再转回 kebab；
- 边取"属性谓词之外、且目标为 IRI"的谓词，谓词名即关系名（calls / queries …）；
- ``port`` / ``repo`` / ``owner`` / ``external`` / ``health`` / ``artifact`` 是功能属性，
  多值即解析失败 —— RDF 允许多值，所以这条必须显式判。

本模块不认识"哪些谓词是关系"：只要不在属性白名单里，就当关系边。这样新增关系
不需要改这里，与 tbox/relations.ttl 的扩展方式保持一致。代价是谓词拼错不会静默 ——
目标不是 IRI 的未知谓词会直接报错，拼成另一个名字则由 E116 报"未声明关系"。
"""

from __future__ import annotations

import re
from typing import Any

from rdflib import BNode, Graph, Literal, URIRef
from rdflib.namespace import RDF, RDFS

from .namespaces import RCP


class AboxError(ValueError):
    """登记图不合法（功能属性多值、种类缺失、目标不是实例 IRI 等）。"""


# 实体上的属性谓词。不在此集合内、且目标为 IRI 的谓词，一律视为关系边。
_ATTRIBUTE_PREDICATES = {
    RCP.repo,
    RCP.port,
    RCP.external,
    RCP.owner,
    RCP.health,
    RCP.hasCapability,
    RCP.contract,
    RCP.artifact,
    RCP.expected,
}

# expected 空白节点的字段映射：谓词 → 字典键。
_EXPECTED = {
    RCP.noDependents: "no_dependents",
    RCP.unreachable: "unreachable",
    RCP.reason: "reason",
    RCP.owner: "owner",
    RCP.reviewBy: "review_by",
}

# 平台配置的嵌套结构：谓词 → 字典键。展开为普通映射，检查层用扁平键取。
_PLATFORM_NESTED = {
    RCP.stack: "baseline_stack",
    RCP.discovery: "discovery",
}

# 允许出现但不参与还原的谓词（注释类），其余未知谓词按错误处理。
_IGNORED = {RDFS.label, RDFS.comment, RDFS.seeAlso}


def _local(node: Any) -> str:
    text = str(node)
    return text.rsplit("#", 1)[-1] if "#" in text else text.rsplit("/", 1)[-1]


def kebab(class_name: str) -> str:
    """OWL 类名转 kind 名：DataGateway -> data-gateway，DbOps -> db-ops。"""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", class_name).lower()


def snake(name: str) -> str:
    """谓词 local name 转字典键：springBoot -> spring_boot。"""
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def _single(g: Graph, node: URIRef, pred: URIRef, where: str) -> Any | None:
    """取功能属性的唯一值；多值即失败（RDF 层面等价于 YAML 的重复键）。"""
    values = list(g.objects(node, pred))
    if not values:
        return None
    if len(values) > 1:
        shown = ", ".join(str(v) for v in values)
        raise AboxError(
            f"{where} 的 {_local(pred)} 有 {len(values)} 个值（{shown}）；功能属性只允许一个值"
        )
    return values[0]


def _literal_bool(value: Any, where: str) -> bool:
    parsed = value.toPython() if isinstance(value, Literal) else value
    if isinstance(parsed, bool):
        return parsed
    text = str(value).strip().lower()
    if text in {"true", "1"}:
        return True
    if text in {"false", "0"}:
        return False
    raise AboxError(f"{where} 的 external 不是布尔值: {value!r}")


def _entity_kind(g: Graph, node: URIRef) -> tuple[str, list[str]]:
    """返回 (实体类别, 种类名列表)。

    实体类别：``library`` / ``service``。种类名列表是 rdf:type 里除 rcp:Service、
    rcp:Library 之外的 rcp 类，转成 kebab 后返回。
    """
    classes = [c for c in g.objects(node, RDF.type) if isinstance(c, URIRef)]
    locals_ = [_local(c) for c in classes if str(c).startswith(str(RCP))]
    if "Library" in locals_:
        return "library", []
    kinds = [kebab(name) for name in locals_ if name != "Service"]
    return "service", kinds


def _relations_of(g: Graph, node: URIRef, where: str) -> dict[str, list[str]]:
    """把实体上的非属性谓词读成「关系名 → 目标列表」。"""
    out: dict[str, list[str]] = {}
    for pred in set(g.predicates(node, None)):
        if pred in _ATTRIBUTE_PREDICATES or pred in _IGNORED:
            continue
        if not str(pred).startswith(str(RCP)):
            continue
        targets: list[str] = []
        for obj in g.objects(node, pred):
            if not isinstance(obj, URIRef):
                raise AboxError(
                    f"{where} 的 {_local(pred)} 目标不是实例 IRI: {obj!r}"
                    "（关系边必须指向另一实体，不能写字面量）"
                )
            targets.append(_local(obj))
        if targets:
            out[_local(pred)] = sorted(set(targets))
    return dict(sorted(out.items()))


def _expected_of(g: Graph, node: URIRef, where: str) -> dict[str, Any]:
    value = _single(g, node, RCP.expected, where)
    if value is None:
        return {}
    if not isinstance(value, BNode):
        raise AboxError(f"{where} 的 expected 必须是空白节点（[ ... ]）")
    out: dict[str, Any] = {}
    for pred, key in _EXPECTED.items():
        raw = g.value(value, pred)
        if raw is None:
            continue
        if key in {"no_dependents", "unreachable"}:
            out[key] = _literal_bool(raw, f"{where}.expected")
        else:
            out[key] = str(raw)
    return out


def _nested_of(g: Graph, node: URIRef, pred: URIRef, where: str) -> dict[str, Any]:
    """读一个内嵌结构（空白节点）为扁平映射：谓词 local name 转 snake_case。"""
    value = _single(g, node, pred, where)
    if value is None:
        return {}
    if not isinstance(value, BNode):
        raise AboxError(f"{where} 的 {_local(pred)} 必须是空白节点（[ ... ]）")
    out: dict[str, Any] = {}
    for sub_pred in set(g.predicates(value, None)):
        if sub_pred in _IGNORED or sub_pred == RDF.type:
            continue
        raw_values = list(g.objects(value, sub_pred))
        key = snake(_local(sub_pred))
        parsed = [v.toPython() if isinstance(v, Literal) else str(v) for v in raw_values]
        out[key] = parsed[0] if len(parsed) == 1 else parsed
    return dict(sorted(out.items()))


def _service_entry(g: Graph, node: URIRef, kind: str) -> dict[str, Any]:
    name = _local(node)
    entry: dict[str, Any] = {"name": name, "kind": kind}

    repo = _single(g, node, RCP.repo, name)
    if repo is not None:
        entry["repo"] = str(repo)
    port = _single(g, node, RCP.port, name)
    if port is not None:
        try:
            entry["port"] = int(str(port.toPython() if isinstance(port, Literal) else port))
        except (TypeError, ValueError):
            raise AboxError(f"{name} 的 port 不是整数: {port!r}") from None
    external = _single(g, node, RCP.external, name)
    if external is not None:
        entry["external"] = _literal_bool(external, name)
    owner = _single(g, node, RCP.owner, name)
    if owner is not None:
        entry["owner"] = str(owner)
    health = _single(g, node, RCP.health, name)
    if health is not None:
        entry["health"] = str(health)

    # 空列表是合法声明，所以这两个键总是出现，E001 仍能判"repo/kind/owner 漏写"。
    entry["capabilities"] = sorted(_local(c) for c in g.objects(node, RCP.hasCapability))
    entry["contracts"] = sorted(str(c) for c in g.objects(node, RCP.contract))
    entry["relations"] = _relations_of(g, node, name)
    expected = _expected_of(g, node, name)
    if expected:
        entry["expected"] = expected
    return entry


def _library_entry(g: Graph, node: URIRef) -> dict[str, Any]:
    name = _local(node)
    entry: dict[str, Any] = {"name": name}
    repo = _single(g, node, RCP.repo, name)
    if repo is not None:
        entry["repo"] = str(repo)
    artifact = _single(g, node, RCP.artifact, name)
    if artifact is not None:
        entry["artifact"] = str(artifact)
    owner = _single(g, node, RCP.owner, name)
    if owner is not None:
        entry["owner"] = str(owner)
    entry["capabilities"] = sorted(_local(c) for c in g.objects(node, RCP.hasCapability))
    return entry


def _platform_of(g: Graph) -> dict[str, Any]:
    """平台标识与配置：平台头 + 版本钉 + 服务发现。"""
    node = next(iter(g.subjects(RDF.type, RCP.Platform)), None)
    if node is None:
        raise AboxError("abox/ 缺少平台标识：需 `rcp:platform a rcp:Platform`")
    data: dict[str, Any] = {}
    for pred, key in (
        (RCP.registrySchema, "schema"),
        (RCP.platformName, "platform"),
        (RCP.updated, "updated"),
    ):
        value = _single(g, node, pred, "platform")
        if value is not None:
            data[key] = str(value)
    for pred, key in _PLATFORM_NESTED.items():
        nested = _nested_of(g, node, pred, "platform")
        if nested:
            data[key] = nested
    return data


def parse_abox(graph: Graph, source: str) -> dict[str, Any]:
    """解析 ABox 合并图，返回字典视图。"""
    data: dict[str, Any] = _platform_of(graph)

    services: list[dict[str, Any]] = []
    libraries: list[dict[str, Any]] = []
    for node in sorted(set(graph.subjects(RCP.repo, None)), key=str):
        where = _local(node)
        category, kinds = _entity_kind(graph, node)
        if category == "library":
            libraries.append(_library_entry(graph, node))
            continue
        if not kinds:
            raise AboxError(f"{where} 未声明种类：需形如 `a rcp:Service` 的 rdf:type")
        if len(kinds) > 1:
            raise AboxError(
                f"{where} 声明了多个种类（{', '.join(kinds)}）；一个实体只能属于一个 kind"
            )
        services.append(_service_entry(graph, node, kinds[0]))

    if not services and not libraries:
        raise AboxError(f"{source} 里没有任何登记实体（缺 rcp:repo）")

    data["services"] = sorted(services, key=lambda s: str(s.get("name")))
    data["libraries"] = sorted(libraries, key=lambda s: str(s.get("name")))
    return data
