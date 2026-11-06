"""L4 SPARQL：属性路径查询。

rdflib 内建 SPARQL 引擎支持属性路径（dependsOn+ / dependsOn*），一步到闭包，
无需推理机。

与 graph.py 的 BFS 是两条不同口径，都要留：

    graph.py 的 reachable_from   —— 按关系所属图分域算，支持 impact --graph <域>
    本模块的 dependsOn+          —— 只覆盖 exporter 物化了汇总边的可达性图

差别来源：exporter 只为可达性图产出 dependsOn 汇总边，非可达性图（数据、构建、
部署、治理）按设计只产出 typed 边，它们的边不得进入可达性计算。因此两者**在可达性
图上必须给出相同闭包**，由 tests/test_rdf.py 对真实登记逐服务校验；出了可达性图，
本模块不适用，这不是缺陷而是分域语义的必然结果。
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
