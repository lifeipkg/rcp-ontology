"""L3 SHACL 验证：用 shapes 检查 RDF 数据图。

只覆盖"能表达为图形状约束"的红线（必填、依赖白名单、命名规范），与 checks.py
形成对照而非替代。文件扫描类红线（RL-004 DDL / RL-005 JDBC / RL-007 上游地址）
不在 SHACL 能力内，仍由 checks.py 承担。分工边界见 README「语义网层」。

SHACL 是闭世界验证：shape 说"缺了/多了/越界了"，报告的就是违规，与 checks.py
同属"找违规"这一类工作，只是用 W3C 标准语言表达而非 Python。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rdflib import Graph
from rdflib.namespace import RDF, SH


@dataclass(frozen=True)
class ShaclFinding:
    """一条 SHACL 违规：违规发生在哪条路径、message 是什么。"""

    path: str
    message: str


def _findings_from_report(report: Graph) -> list[ShaclFinding]:
    out: list[ShaclFinding] = []
    for result in report.subjects(RDF.type, SH.ValidationResult):
        path = report.value(result, SH.resultPath)
        message = report.value(result, SH.resultMessage)
        out.append(
            ShaclFinding(
                path=str(path).rsplit("#", 1)[-1] if path else "",
                message=str(message) if message else "",
            )
        )
    return out


def validate(data_graph: Graph, shapes_path: Path) -> tuple[bool, list[ShaclFinding]]:
    """对数据图跑 SHACL，返回 (是否合规, 违规列表)。"""
    from pyshacl import validate as _validate

    shapes_graph = Graph()
    shapes_graph.parse(shapes_path, format="turtle")
    conforms, report, _ = _validate(data_graph, shacl_graph=shapes_graph)
    return bool(conforms), _findings_from_report(report)
