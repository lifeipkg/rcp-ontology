"""依赖图算法。

依赖图只由 ``services`` 的 ``depends_on`` 构成，边方向为"调用方 → 被调方"。
libraries 不入图：它们被编译期依赖，不参与运行时探活与降级。

本模块是纯函数集合，不读文件、不做判定、不产生 Finding——判定与措辞留在
checks 层，这里只回答图上的事实问题（谁依赖谁、有没有环、谁不可达）。
"""

from __future__ import annotations

from collections import deque
from typing import Any, Iterable


def build_graph(registry: dict[str, Any]) -> dict[str, list[str]]:
    """构造邻接表。指向未登记服务的边被丢弃（由 E105 单独报）。"""
    services = [s for s in registry.get("services", []) if s.get("name")]
    known = {s["name"] for s in services}
    graph: dict[str, list[str]] = {name: [] for name in known}
    for service in services:
        for dep in service.get("depends_on") or []:
            if dep in known:
                graph[service["name"]].append(dep)
    return graph


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
