"""L3 SHACL 验证：用 shapes 检查 RDF 数据图。

承担「能表达为图形状约束」的检查（依赖登记/种类声明/能力立名/依赖白名单/
external 方向/命名规范/TBox 自洽/port、contract 必填），这些已从 checks.py
迁移到本层，SHACL 是它们的唯一实现。文件扫描类红线（RL-004 DDL / RL-005 JDBC /
RL-007 上游地址）、跨源比对（RL-003）、键存在性、唯一键、能力归属、图连通性
不在 SHACL 能力内，仍由 checks.py 承担。

SHACL 是闭世界验证：shape 说「缺了/多了/越界了」，报告的就是违规，与 checks.py
同属「找违规」这一类工作，只是用 W3C 标准语言表达而非 Python。

shapes 分静态（ontology/constraints.ttl）与动态（shapes.py 从 kinds.yaml 编译）
两类，validate_all 合并二者做完整验证。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rdflib import Graph
from rdflib.namespace import RDF, SH

from .shapes import build_shapes_graph

# message 前缀「编号: 」的提取：E106 / RL-001 两类编号形态。
_CODE_RE = re.compile(r"^([A-Z]+-?\d+):\s*(.*)$", re.S)


@dataclass(frozen=True)
class ShaclFinding:
    """一条 SHACL 违规：编号（与 checks.py 对齐）、违规节点、说明。"""

    code: str
    focus: str
    message: str


def _local(iri: Any) -> str:
    """把 focusNode 的 IRI 转成平台内的短名（RCP 命名空间 local name）。"""
    if iri is None:
        return ""
    text = str(iri)
    return text.rsplit("#", 1)[-1] if "#" in text else text


def _findings_from_report(report: Graph) -> list[ShaclFinding]:
    out: list[ShaclFinding] = []
    for result in report.subjects(RDF.type, SH.ValidationResult):
        focus = report.value(result, SH.focusNode)
        message = report.value(result, SH.resultMessage)
        text = str(message) if message else ""
        match = _CODE_RE.match(text)
        out.append(
            ShaclFinding(
                code=match.group(1) if match else "?",
                focus=_local(focus),
                message=match.group(2).strip() if match else text,
            )
        )
    return out


def validate_all(
    data_graph: Graph,
    shapes_path: Path,
    concepts: dict[str, Any],
) -> tuple[bool, list[ShaclFinding]]:
    """静态 shapes + 动态 shapes（来自 concepts）合并后的完整验证。"""
    from pyshacl import validate as _validate

    shapes_graph = Graph()
    shapes_graph.parse(shapes_path, format="turtle")
    shapes_graph += build_shapes_graph(concepts)
    conforms, report, _ = _validate(data_graph, shacl_graph=shapes_graph)
    return bool(conforms), _findings_from_report(report)
