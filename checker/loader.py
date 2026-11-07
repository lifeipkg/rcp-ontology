"""本体装载：目录即层，一个目录一个编辑面，全部是 TTL。

本仓没有"唯一一种格式"，只有"每一层只有一个目录"：

    ontology/tbox/     概念 —— 存在什么（种类、能力、决策、关系、术语）
    ontology/abox/     实例 —— 本平台登记了什么（服务、库、边、平台配置）
    ontology/policy/   规则 —— 什么算违规（红线与例外）
    ontology/shapes/   约束 —— 图形状（SHACL）

装载器把一层目录下的全部 .ttl 合并成一张图（按文件名排序，保证确定性），再把图
还原成检查层使用的字典视图。视图只在内存中存在，没有对应磁盘文件，所以不构成
第二份真源。

为什么仍然保留字典视图：检查逻辑（必填字段、图算法、渲染）建立在"实体 → 属性"上。
让它们直接查图，改动面是全部 check 函数与图算法；只在这一层做一次"图 → 视图"
的还原，检查层一行不改。

严格性：RDF 允许一个属性多值，所以功能属性（port/repo/owner/external/health/
artifact、kind 的四个布尔、决策分值、能力归属）的多值由 ``abox`` / ``tbox`` 在
装载期显式报错 —— 这是原 YAML "重复键即失败"的等价护栏，不能因为换格式就丢掉。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rdflib import DCTERMS, OWL, RDF, RDFS, Graph

__version__ = "2.0.0"

# 各层的目录名（相对本体仓根的 ontology/）。
ONTOLOGY_DIR = "ontology"
TBOX_DIR = "tbox"
ABOX_DIR = "abox"
POLICY_DIR = "policy"
SHAPES_DIR = "shapes"

# 本体头声明在 tbox/schema.ttl 里，属于本体图本身，不单独成文件。
# 读取时合并整个 tbox 层，所以 header 若被写进两个文件会被多值护栏抓到。

# Finding 的作用域：
#   declaration —— 只读单仓声明即可判定，任何环境都能跑
#   workspace   —— 需要多仓同处一个工作区才能判定，单仓 CI 中不可用
SCOPE_DECLARATION = "declaration"
SCOPE_WORKSPACE = "workspace"


class LoadError(RuntimeError):
    """声明不可用（文件缺失、TTL 语法错误、功能属性多值、顶层结构不符）。"""


@dataclass(frozen=True)
class Finding:
    """一条检查结论。code 对应红线编号或内置校验编号。"""

    level: str
    code: str
    message: str
    scope: str = SCOPE_DECLARATION

    def as_dict(self) -> dict[str, str]:
        return {
            "level": self.level,
            "code": self.code,
            "message": self.message,
            "scope": self.scope,
        }


@dataclass
class Ontology:
    """本体仓的装载结果（一份只读快照）。"""

    root: Path
    graph: dict[str, Graph] = field(default_factory=dict)


def ontology_root(root: Path) -> Path:
    """接受本体仓根或 ontology/ 目录本身，统一成 ontology/ 目录。"""
    root = Path(root)
    if (root / ONTOLOGY_DIR).is_dir():
        return root / ONTOLOGY_DIR
    return root


def layer_dir(root: Path, layer: str) -> Path:
    """取某一层的目录；缺失即声明不可用（不静默回退到别的层）。"""
    path = ontology_root(root) / layer
    if not path.is_dir():
        raise LoadError(f"缺少本体层目录: {path}")
    return path


def parse_layer(root: Path, layer: str) -> tuple[Graph, list[Path]]:
    """把一层的全部 .ttl 合并成一张图。

    合并顺序为文件名字典序 —— RDF 图无序，但解析顺序影响错误报告与空白节点编号，
    固定下来才能让同一份声明每次产出相同结论。
    """
    directory = layer_dir(root, layer)
    files = sorted(directory.glob("*.ttl"))
    if not files:
        raise LoadError(f"{directory} 下没有任何 .ttl 声明")
    graph = Graph()
    for path in files:
        try:
            graph.parse(path, format="turtle")
        except Exception as exc:  # noqa: BLE001 - 语法错误即声明不可用
            raise LoadError(f"{path} TTL 解析失败: {exc}") from exc
    return graph, files


def load_registry(root: Path) -> dict[str, Any]:
    """读 ABox 层（abox/）：服务、库、边、预期状态、平台配置。

    返回值是检查层使用的字典视图：``services`` / ``libraries`` 两个列表，
    外加平台配置的扁平键（``platform`` / ``schema`` / ``updated`` /
    ``baseline_stack`` / ``discovery``）。
    """
    from .abox import AboxError, parse_abox

    graph, files = parse_layer(root, ABOX_DIR)
    try:
        data = parse_abox(graph, ", ".join(p.name for p in files))
    except AboxError as exc:
        raise LoadError(str(exc)) from exc
    data.setdefault("services", [])
    data.setdefault("libraries", [])
    return data


def load_concepts(root: Path) -> dict[str, Any]:
    """读 TBox 层（tbox/）：种类、能力、决策、术语，并附上原图。

    原图一并返回，是因为导出与 SHACL 验证需要 TBox 的三元组本身（类声明、行为属性、
    能力与决策个体）—— 有了它，导出器不必再从字典反向合成一遍同样的三元组。
    """
    from .tbox import TboxError, parse_tbox

    graph, files = parse_layer(root, TBOX_DIR)
    try:
        data = parse_tbox(graph, ", ".join(p.name for p in files))
    except TboxError as exc:
        raise LoadError(str(exc)) from exc
    data["tbox_graph"] = graph
    return data


def load_relations(root: Path) -> dict[str, Any]:
    """读关系层（tbox/relations.ttl 的三元组）。

    关系声明与概念同层，所以走同一张合并图；本函数只做筛选，不重复解析文件。
    """
    from .relations import parse_relations

    graph, files = parse_layer(root, TBOX_DIR)
    try:
        return parse_relations(graph, ", ".join(p.name for p in files))
    except ValueError as exc:
        # 关系层不可用不是加载致命错误：调用方据此降级并输出 S002，
        # 而不是让 impact/relations 这类命令直接崩掉。
        raise LoadError(str(exc)) from exc


def load_redlines(root: Path) -> dict[str, Any]:
    """读规则层（policy/）：红线与例外。"""
    from .policy import PolicyError, parse_redlines

    graph, files = parse_layer(root, POLICY_DIR)
    try:
        data = parse_redlines(graph, ", ".join(p.name for p in files))
    except PolicyError as exc:
        raise LoadError(str(exc)) from exc
    data.setdefault("constraints", [])
    data.setdefault("exceptions", [])
    return data


def load_header(root: Path) -> dict[str, Any]:
    """读本体头（ontology header）：身份（IRI / 版本）与组成部分清单。

    header 在本体图里，声明于 tbox/schema.ttl；这里合并整个 tbox 层再读，所以若有人
    把 header 写进第二个 tbox 文件，功能属性的多值护栏会立刻报错——这正是它比"单独
    一个文件"更强的地方：跨文件的重复声明也能抓到。

    ``owl:Ontology`` 只能有一个身份；``versionInfo`` / ``versionIRI`` / ``label``
    是功能属性，多值即报错（与 abox / tbox 同一口径，不因换文件就放松）。

    返回值：``iri`` / ``version_info`` / ``version_iri`` / ``label`` 四个字符串（缺省
    None），以及 ``parts`` —— ``dcterms:hasPart`` 声明的仓内相对路径（已排序）。
    没有 header 时返回全 None 的空结构，由调用方判 E119（不在这里 raise，因为"没写"
    是缺陷而非加载失败，报错文案要能说清缺什么）。
    """
    graph, files = parse_layer(root, TBOX_DIR)
    source = ", ".join(p.name for p in files)

    subjects = sorted(graph.subjects(RDF.type, OWL.Ontology))
    if not subjects:
        return {"iri": None, "label": None, "version_info": None, "version_iri": None, "parts": []}
    if len(subjects) > 1:
        names = ", ".join(str(s) for s in subjects)
        raise LoadError(f"{source} 声明了 {len(subjects)} 个 owl:Ontology（{names}），本体只能有一个身份")
    iri = subjects[0]

    def _single(predicate, field_name: str) -> str | None:
        values = list(graph.objects(iri, predicate))
        if len(values) > 1:
            raise LoadError(f"{source} 的 {field_name} 有 {len(values)} 个值（功能属性只允许一个）")
        return str(values[0]) if values else None

    return {
        "iri": str(iri),
        "label": _single(RDFS.label, "rdfs:label"),
        "version_info": _single(OWL.versionInfo, "owl:versionInfo"),
        "version_iri": _single(OWL.versionIRI, "owl:versionIRI"),
        "parts": sorted(str(part) for part in graph.objects(iri, DCTERMS.hasPart)),
    }
