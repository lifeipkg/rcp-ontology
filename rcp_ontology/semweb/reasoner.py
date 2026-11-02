"""L2 OWL 推理：对 RDF 图做 OWL-RL 闭包，物化传递依赖。

ontology/rcp.ttl 声明 rcp:dependsOn 为 owl:TransitiveProperty。owlrl 的 OWL-RL
推理会把间接依赖物化成显式三元组（A→B、B→C 推出 A→C），等价于 graph.py 手写的
BFS 闭包。两者在测试里交叉验证，保证"推理机算的"与"手写算法算的"一致。

关键认知：这一步用"一条 owl:TransitiveProperty 声明 + 推理机"取代了
graph.py 里 reachable_from / dependents_of 的手写 BFS——这正是 OWL 的
"从已知推导未知"。
"""

from __future__ import annotations

from rdflib import Graph

from .namespaces import RCP


def local_name(node) -> str:
    """取 URIRef 的 local name（去掉命名空间前缀）。"""
    s = str(node)
    return s.rsplit("#", 1)[-1] if "#" in s else s.rsplit("/", 1)[-1]


def infer_transitive(graph: Graph) -> Graph:
    """原地扩展 OWL-RL 闭包（含传递属性物化），返回原图。"""
    from owlrl import DeductiveClosure, OWLRL_Semantics

    DeductiveClosure(OWLRL_Semantics).expand(graph)
    return graph


def dependents_of(graph: Graph, service: str) -> set[str]:
    """推理后，所有（直接或间接）依赖 service 的节点名。"""
    return {local_name(s) for s in graph.subjects(RCP.dependsOn, RCP[service])}


def dependencies_of(graph: Graph, service: str) -> set[str]:
    """推理后，service（直接或间接）依赖的所有节点名。"""
    return {local_name(o) for o in graph.objects(RCP[service], RCP.dependsOn)}
