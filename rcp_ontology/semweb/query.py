"""L4 SPARQL：属性路径查询，替代手写 BFS。

rdflib 内建 SPARQL 引擎支持属性路径（dependsOn+ / dependsOn*），一步到闭包，
无需推理机。与 reasoner 物化、graph.py BFS 三者对同一结论交叉验证：

    graph.py 的 reachable_from   —— 手写 BFS
    reasoner 的 owlrl 物化       —— 推理机推导
    query.py 的属性路径 dependsOn+ —— SPARQL 图遍历

三者应给出相同的传递闭包。
"""

from __future__ import annotations

from rdflib import Graph

from .namespaces import RCP


def _local(s: str) -> str:
    return s.rsplit("#", 1)[-1] if "#" in s else s.rsplit("/", 1)[-1]


def dependents_of(graph: Graph, service: str) -> set[str]:
    """谁（直接或间接）依赖 service。SPARQL 属性路径 + = 一跳或多跳。"""
    q = f"""
        SELECT DISTINCT ?s WHERE {{
            ?s <{RCP}dependsOn>+ <{RCP}{service}> .
        }}
    """
    return {_local(str(row.s)) for row in graph.query(q)}


def dependencies_of(graph: Graph, service: str) -> set[str]:
    """service（直接或间接）依赖谁。"""
    q = f"""
        SELECT DISTINCT ?o WHERE {{
            <{RCP}{service}> <{RCP}dependsOn>+ ?o .
        }}
    """
    return {_local(str(row.o)) for row in graph.query(q)}
