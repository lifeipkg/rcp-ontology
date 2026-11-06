"""分域依赖图算法。

边不再是单一 ``depends_on``：登记可以写 ``relations: {calls: [...], queries: [...]}``，
每条关系所属的图由 ``ontology/relations.ttl`` 声明（关系层真源）。本模块按图名分别
构造邻接表，环检测与可达性只在参与可达性的图上计算。

为什么必须分域：把部署共置、数据血缘、构建依赖混进调用图，E108 会把"合法的双向
引用"判成环，E110 会把"不参与调用的基座"判成不可达。分域不是洁癖，是判据正确性前提。

libraries 不入图：它们被编译期依赖，不参与运行时探活与降级。

本模块是纯函数集合，不读文件、不做判定、不产生 Finding——判定与措辞留在
checks 层，这里只回答图上的事实问题（谁依赖谁、有没有环、谁不可达）。
"""

from __future__ import annotations

from collections import deque
from typing import Any, Iterable

from .relations import service_relations

# 缺省图名。旧调用 ``build_graph(registry)`` 等价于只看调用图（原语义）。
CALL_GRAPH = "call"


def _graph_of_edge(relations: dict[str, Any] | None, name: str) -> str | None:
    """一条边属于哪张图。未声明的关系返回 None（由 E116 报告，不进任何图）。"""
    if relations is None:
        return CALL_GRAPH if name == "calls" else None
    spec = relations.get("relations", {}).get(name)
    return spec.get("graph") if spec else None


def build_graph(
    registry: dict[str, Any],
    relations: dict[str, Any] | None = None,
    graph_name: str = CALL_GRAPH,
) -> dict[str, list[str]]:
    """构造某一域图的邻接表。

    graph_name 决定收哪些边：只有该图上的关系进邻接表。指向未登记节点的边被丢弃
    （由 E105 单独报），避免图算法对悬空引用做二次判定。
    """
    services = [s for s in registry.get("services", []) if s.get("name")]
    known = {s["name"] for s in services}
    graph: dict[str, list[str]] = {name: [] for name in known}
    for service in services:
        for rel, targets in service_relations(service).items():
            if _graph_of_edge(relations, rel) != graph_name:
                continue
            for target in targets:
                if target in known and target not in graph[service["name"]]:
                    graph[service["name"]].append(target)
    return graph


def build_graphs(
    registry: dict[str, Any],
    relations: dict[str, Any] | None = None,
) -> dict[str, dict[str, list[str]]]:
    """按声明构造全部图。未在 relations.ttl 声明的关系不产生图。"""
    names = (
        set(relations.get("graphs", {}))
        if relations
        else {CALL_GRAPH}
    )
    return {name: build_graph(registry, relations, name) for name in sorted(names)}


def in_degrees(graph: dict[str, list[str]]) -> dict[str, int]:
    """统计入度：有多少个服务依赖它。"""
    degrees = {name: 0 for name in graph}
    for deps in graph.values():
        for dep in deps:
            degrees[dep] = degrees.get(dep, 0) + 1
    return degrees


def reachable_from(graph: dict[str, list[str]], start: str) -> set[str]:
    """从 start 出发可达的所有节点（不含 start 自身，除非成环回到它）。"""
    if start not in graph:
        return set()
    seen: set[str] = set()
    queue = deque(graph[start])
    while queue:
        node = queue.popleft()
        if node in seen:
            continue
        seen.add(node)
        queue.extend(graph.get(node, []))
    return seen


def dependencies_of(graph: dict[str, list[str]], name: str) -> set[str]:
    """正向闭包：它（间接）依赖谁。"""
    return reachable_from(graph, name)


def dependents_of(graph: dict[str, list[str]], name: str) -> set[str]:
    """反向闭包：谁（间接）依赖它。改它的契约会波及这些人。"""
    reverse: dict[str, list[str]] = {n: [] for n in graph}
    for src, deps in graph.items():
        for dep in deps:
            reverse.setdefault(dep, []).append(src)
    return reachable_from(reverse, name)


def find_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """三色 DFS 找环，返回去重后的环列表。

    每个环表示为一串节点，隐含"末节点指回首节点"；旋转到字典序最小的起点后去重，
    保证同一环只报一次。
    """
    WHITE, GREY, BLACK = 0, 1, 2
    color = {node: WHITE for node in graph}
    stack: list[str] = []
    found: list[list[str]] = []

    def visit(node: str) -> None:
        color[node] = GREY
        stack.append(node)
        for nxt in graph.get(node, []):
            if nxt not in color:
                continue
            if color[nxt] == GREY:
                index = stack.index(nxt)
                found.append(_canonical(stack[index:]))
            elif color[nxt] == WHITE:
                visit(nxt)
        stack.pop()
        color[node] = BLACK

    for node in sorted(graph):
        if color[node] == WHITE:
            visit(node)

    unique: list[list[str]] = []
    for cycle in found:
        if cycle not in unique:
            unique.append(cycle)
    return sorted(unique)


def _canonical(cycle: list[str]) -> list[str]:
    """把环旋转到最小节点开头，便于去重。"""
    if not cycle:
        return cycle
    pivot = cycle.index(min(cycle))
    return cycle[pivot:] + cycle[:pivot]


def unreachable_from(graph: dict[str, list[str]], entries: Iterable[str]) -> set[str]:
    """从任一入口出发都到不了的节点。"""
    reachable: set[str] = set()
    for entry in entries:
        if entry in graph:
            reachable.add(entry)
            reachable |= reachable_from(graph, entry)
    return set(graph) - reachable
