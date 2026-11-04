"""L3 动态 shapes：把 TBox（concepts/tbox.ttl）里的「数据驱动约束」编译成 SHACL shapes。

静态的「固定结构约束」（E105 依赖未登记、E201 种类未声明、E202 能力未声明、
E113 布尔属性与引用悬空、E114 命名）写在 ontology/constraints.ttl，因为它们不随
TBox 的内容变化。而本模块生成的四类约束，其参数（白名单、external 方向、
port/contract 是否必填）都来自 TBox 的每个 kind，属于「规则即数据」——
TBox 改了，shapes 随之变，无需改本文件。

生成的四类 shapes（每个 kind 一个 NodeShape，targetClass 到该 kind 的 OWL 类）：

1. E106/RL-001 依赖白名单  —— allowed_depends_on_kinds；空列表=零依赖
2. RL-002 external 方向    —— must_be_external
3. E001  port 必填         —— requires_port
4. RL-006 contract 必填    —— requires_contract

message 前缀用「编号: 」约定，validator 据此把 SHACL 违规映射回 checks.Finding
的 code，保证编号与 checks.py 的定位语义一致（机械可复核的锚点不变）。
"""

from __future__ import annotations

from typing import Any

from rdflib import BNode, Graph, Literal
from rdflib.namespace import RDF, SH, XSD

from .exporter import kind_class
from .namespaces import RCP


def _rdf_list(g: Graph, items: list) -> object:
    """构建一个 RDF 列表（rdf:List），用于 sh:or 的分支集合。"""
    if not items:
        return RDF.nil
    head = BNode()
    cur = head
    for i, item in enumerate(items):
        g.add((cur, RDF.first, item))
        rest = BNode() if i < len(items) - 1 else RDF.nil
        g.add((cur, RDF.rest, rest))
        cur = rest
    return head


def _add_class_or(g: Graph, prop: object, classes: list[object]) -> None:
    """给 property shape 加「值节点必须是这些类之一」约束。

   单个类直接用 sh:class；多个类必须用 sh:or——因为 pyshacl 对同一 shape 上的
   多个 sh:class 按「同时满足（AND）」处理，而非 SHACL 的并集语义，会误报。
    """
    if len(classes) == 1:
        g.add((prop, SH["class"], classes[0]))
        return
    branches = []
    for cls in classes:
        branch = BNode()
        g.add((branch, SH["class"], cls))
        branches.append(branch)
    g.add((prop, SH["or"], _rdf_list(g, branches)))


def _add_depends_on_shapes(g: Graph, concepts: dict[str, Any]) -> None:
    """E106（依赖种类越界）+ RL-001（巡查线互调，patrol-line 专属）。

    统一用「sh:qualifiedValueShape + sh:qualifiedMinCount 1」表达「存在违规依赖」，
    用 sh:not 排除白名单内/由其它编号负责的依赖。违规值定义为「已登记服务（rcp:Service）
    且不在本 kind 白名单内」——未登记依赖不满足「rcp:Service」，交给 E105 报告，避免
    一条依赖同时命中 E105 与 E106（与 checks.py 的 E105 continue 短路语义一致）。
    """
    kinds = {k["name"] for k in concepts["kinds"]}
    for kind in concepts["kinds"]:
        name = kind["name"]
        cls = kind_class(name)
        allowed = [kind_class(a) for a in kind.get("allowed_depends_on_kinds") or []]

        # RL-001：巡查线不得依赖巡查线（专门的架构红线编号）。
        if name == "patrol-line":
            shape = RCP[f"Shape_RL001_{cls}"]
            g.add((shape, RDF.type, SH.NodeShape))
            g.add((shape, SH.targetClass, RCP[cls]))
            prop = BNode()
            g.add((shape, SH.property, prop))
            g.add((prop, SH.path, RCP.dependsOn))
            vs = BNode()
            g.add((vs, SH["class"], RCP["PatrolLine"]))
            g.add((prop, SH.qualifiedValueShape, vs))
            g.add((prop, SH.qualifiedMaxCount, Literal(0)))
            g.add((prop, SH.message, Literal("RL-001: 巡查线不得互相调用")))

        # E106：依赖种类必须在白名单内。
        shape = RCP[f"Shape_E106_{cls}"]
        g.add((shape, RDF.type, SH.NodeShape))
        g.add((shape, SH.targetClass, RCP[cls]))
        prop = BNode()
        g.add((shape, SH.property, prop))
        g.add((prop, SH.path, RCP.dependsOn))
        # 违规值：已登记服务（rcp:Service）且不在白名单内。
        vs = BNode()
        g.add((vs, SH["class"], RCP.Service))
        if allowed:
            not_shape = BNode()
            _add_class_or(g, not_shape, [RCP[a] for a in allowed])
            g.add((vs, SH["not"], not_shape))
        elif name == "patrol-line":
            # 互调已由 RL-001 负责，E106 只查「依赖非 patrol-line 的已登记服务」。
            not_shape = BNode()
            g.add((not_shape, SH["class"], RCP["PatrolLine"]))
            g.add((vs, SH["not"], not_shape))
        # else：allowed 空的非 patrol-line，违规值即「任何已登记依赖」。
        g.add((prop, SH.qualifiedValueShape, vs))
        g.add((prop, SH.qualifiedMaxCount, Literal(0)))
        g.add((prop, SH.message, Literal(f"E106: {name}({cls}) 依赖种类越界")))


def _add_external_shapes(g: Graph, concepts: dict[str, Any]) -> None:
    """RL-002：must_be_external 决定该种类必须/不得 external=true。"""
    for kind in concepts["kinds"]:
        name = kind["name"]
        cls = kind_class(name)
        must_external = bool(kind.get("must_be_external"))
        shape = RCP[f"Shape_RL002_{cls}"]
        g.add((shape, RDF.type, SH.NodeShape))
        g.add((shape, SH.targetClass, RCP[cls]))
        prop = BNode()
        g.add((shape, SH.property, prop))
        g.add((prop, SH.path, RCP.external))
        g.add((prop, SH.hasValue, Literal(must_external, datatype=XSD.boolean)))
        verb = "必须 external=true" if must_external else "不得 external=true"
        g.add((prop, SH.message, Literal(f"RL-002: {name}({cls}) {verb}")))


def _add_port_shapes(g: Graph, concepts: dict[str, Any]) -> None:
    """E001（port 部分）：requires_port 的种类必须有 port。"""
    for kind in concepts["kinds"]:
        if not kind.get("requires_port"):
            continue
        cls = kind_class(kind["name"])
        shape = RCP[f"Shape_Port_{cls}"]
        g.add((shape, RDF.type, SH.NodeShape))
        g.add((shape, SH.targetClass, RCP[cls]))
        prop = BNode()
        g.add((shape, SH.property, prop))
        g.add((prop, SH.path, RCP.port))
        g.add((prop, SH.minCount, Literal(1)))
        g.add((prop, SH.message, Literal("E001: 该种类服务必须有 port")))


def _add_contract_shapes(g: Graph, concepts: dict[str, Any]) -> None:
    """RL-006（挂契约部分）：requires_contract 的种类必须有 contract。"""
    for kind in concepts["kinds"]:
        if not kind.get("requires_contract"):
            continue
        cls = kind_class(kind["name"])
        shape = RCP[f"Shape_Contract_{cls}"]
        g.add((shape, RDF.type, SH.NodeShape))
        g.add((shape, SH.targetClass, RCP[cls]))
        prop = BNode()
        g.add((shape, SH.property, prop))
        g.add((prop, SH.path, RCP.contract))
        g.add((prop, SH.minCount, Literal(1)))
        g.add((prop, SH.message, Literal("RL-006: 该种类服务必须挂契约")))


def build_shapes_graph(concepts: dict[str, Any]) -> Graph:
    """把 concepts（TBox 字典视图）编译成数据驱动的 SHACL shapes 图。"""
    g = Graph()
    g.bind("sh", SH)
    g.bind("rcp", RCP)
    _add_depends_on_shapes(g, concepts)
    _add_external_shapes(g, concepts)
    _add_port_shapes(g, concepts)
    _add_contract_shapes(g, concepts)
    return g
