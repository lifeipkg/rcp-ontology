"""TTL 登记源解析：把 ``registry/services.ttl`` 还原成检查层使用的字典视图。

为什么要有这一层：检查逻辑（必填字段、端口冲突、图算法、渲染）全部建立在
"服务 → 属性"的字典上，而真源变成了三元组。两种做法可选：

1. 改掉全部检查，让它们直接查图 —— 改动面是全部 check 函数与图算法，风险最大；
2. 只在装载处做一次"图 → 视图"的还原，检查层一行不改。

选 2。字典是**内存视图**，不再有对应的磁盘文件，所以不构成第二份真源。

还原规则（与 services.ttl 顶部四条书写约定一一对应）：

- 实例的 local name 即服务名（不读 rcp:name，避免同一事实两个位置）；
- 种类取 ``rdf:type`` 中除 rcp:Service / rcp:Library 之外的 rcp 类，再转回 kebab；
- 边取"属性谓词之外、且目标为 IRI"的谓词，谓词名即关系名（calls / queries …）；
- ``port`` / ``repo`` / ``owner`` / ``external`` / ``health`` / ``artifact`` 是功能属性，
  多值即解析失败 —— RDF 允许多值，所以这条必须显式判，它是原 YAML 严格重复键
  检查的等价物。

本模块不认识"哪些谓词是关系"：只要不在属性白名单里，就当关系边。这样新增关系
不需要改这里，与 relations.ttl 的扩展方式保持一致。代价是谓词拼错不会静默 ——
目标不是 IRI 的未知谓词会直接报错，拼成另一个名字则由 E116 报"未声明关系"。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from rdflib import BNode, Graph, Literal, URIRef
from rdflib.namespace import RDF, RDFS

from .namespaces import RCP


class RegistryTTLError(ValueError):
    """登记图不合法（功能属性多值、种类缺失、目标不是实例 IRI 等）。"""


# 实体上的属性谓词。不在此集合内、且目标为 IRI 的谓词，一律视为关系边。
_ATTRIBUTE_PREDICATES = {
    RCP.name,
    RCP.repo,
    RCP.port,
    RCP.external,
    RCP.owner,
    RCP.health,
    RCP.hasCapability,
    RCP.contract,
    RCP.artifact,
    RCP.expected,
    RCP.registrySchema,
    RCP.platformName,
    RCP.updated,
}

# 功能属性：一个实体上只能有一个值。键为谓词，值为报告用的字段名。
_FUNCTIONAL = {
    RCP.repo: "repo",
    RCP.port: "port",
    RCP.external: "external",
    RCP.owner: "owner",
    RCP.health: "health",
    RCP.artifact: "artifact",
}

# expected 空白节点的字段映射：谓词 → 字典键。
_EXPECTED = {
    RCP.noDependents: "no_dependents",
    RCP.unreachable: "unreachable",
    RCP.reason: "reason",
    RCP.owner: "owner",
    RCP.reviewBy: "review_by",
}

# 允许出现但不参与还原的谓词（注释类），其余未知谓词按错误处理。
_IGNORED = {RDFS.label, RDFS.comment, RDFS.seeAlso}


def _local(node: Any) -> str:
    text = str(node)
    return text.rsplit("#", 1)[-1] if "#" in text else text.rsplit("/", 1)[-1]


def kebab(class_name: str) -> str:
    """OWL 类名转 kind 名：PatrolLine -> patrol-line，DbOps -> db-ops。"""
    return re.sub(r"(?<!^)(?=[A-Z])", "-", class_name).lower()


def _single(g: Graph, node: URIRef, pred: URIRef, where: str) -> Any | None:
    """取功能属性的唯一值；多值即失败（RDF 层面等价于 YAML 的重复键）。"""
    values = list(g.objects(node, pred))
    if not values:
        return None
    if len(values) > 1:
        shown = ", ".join(str(v) for v in values)
        raise RegistryTTLError(
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
    raise RegistryTTLError(f"{where} 的 external 不是布尔值: {value!r}")


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
                raise RegistryTTLError(
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
        raise RegistryTTLError(f"{where} 的 expected 必须是空白节点（[ ... ]）")
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
            raise RegistryTTLError(f"{name} 的 port 不是整数: {port!r}") from None
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


def parse_registry(path: Path) -> dict[str, Any]:
    """解析 services.ttl，返回与 YAML 登记等价的字典视图。"""
    graph = Graph()
    try:
        graph.parse(path, format="turtle")
    except Exception as exc:  # noqa: BLE001 - 语法错误即声明不可用
        raise RegistryTTLError(f"{path} 解析失败: {exc}") from exc

    data: dict[str, Any] = {}
    platform = next(iter(graph.subjects(RDF.type, RCP.Platform)), None)
    if platform is not None:
        schema = _single(graph, platform, RCP.registrySchema, "platform")
        if schema is not None:
            data["schema"] = str(schema)
        name = _single(graph, platform, RCP.platformName, "platform")
        if name is not None:
            data["platform"] = str(name)
        updated = _single(graph, platform, RCP.updated, "platform")
        if updated is not None:
            data["updated"] = str(updated)

    services: list[dict[str, Any]] = []
    libraries: list[dict[str, Any]] = []
    for node in sorted(set(graph.subjects(RCP.repo, None)), key=str):
        where = _local(node)
        category, kinds = _entity_kind(graph, node)
        if category == "library":
            libraries.append(_library_entry(graph, node))
            continue
        if not kinds:
            raise RegistryTTLError(f"{where} 未声明种类：需形如 `a rcp:PatrolLine` 的 rdf:type")
        if len(kinds) > 1:
            raise RegistryTTLError(
                f"{where} 声明了多个种类（{', '.join(kinds)}）；一个实体只能属于一个 kind"
            )
        services.append(_service_entry(graph, node, kinds[0]))

    data["services"] = sorted(services, key=lambda s: str(s.get("name")))
    data["libraries"] = sorted(libraries, key=lambda s: str(s.get("name")))
    return data
