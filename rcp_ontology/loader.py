"""本体仓：概念装载与结果类型。

TBox（概念/种类/能力/决策语义）在 ``concepts/tbox.ttl``，ABox（具体服务实例）在契约仓
``registry/services.ttl``。本包只读，不写任何声明文件。

两支都是 TTL，所以"声明 → 图"不再有翻译步骤；这里仍提供字典视图，是因为检查逻辑
（必填字段、图算法、渲染）建立在"实体 → 属性"上，改判会放大风险。视图在内存里生成，
没有对应磁盘文件，不构成第二份真源。

两种序列化各用各的严格性：

- YAML（只剩 platform.yaml / redlines.yaml 这类非图配置）：重复键视为解析失败，而不是
  静默取后者。多人同时编辑同一份声明时，重复键会让"文件里写了什么"与"程序读到什么"
  不一致，这类错误必须显式失败。
- TTL：RDF 允许多值，所以功能属性（port/repo/owner/external/health、kind 的四个布尔、
  决策分值、能力归属）的多值由 ``registry_ttl`` / ``concepts_ttl`` 在装载期报错——
  这是同一条护栏在另一种格式上的等价实现。

``services.yaml`` 仍可读（兼容回退），``concepts/*.yaml`` 已随 TBox 迁移删除。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

__version__ = "1.1.0"

# Finding 的作用域：
#   declaration —— 只读单仓声明即可判定，任何环境都能跑
#   workspace   —— 需要多仓同处一个工作区才能判定，单仓 CI 中不可用
SCOPE_DECLARATION = "declaration"
SCOPE_WORKSPACE = "workspace"


class LoadError(RuntimeError):
    """声明文件缺失或不可解析（含重复键）。"""


class _StrictSafeLoader(yaml.SafeLoader):
    """在 SafeLoader 上增加重复键检测。"""

    def construct_mapping(self, node, deep=False):  # type: ignore[override]
        if isinstance(node, yaml.MappingNode):
            self.flatten_mapping(node)
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError:  # 不可哈希的键交给后续构造去报错
                continue
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"重复键 {key!r}",
                    key_node.start_mark,
                )
        return super().construct_mapping(node, deep=deep)


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


def read_yaml(path: Path) -> Any:
    if not path.is_file():
        raise LoadError(f"文件不存在: {path}")
    try:
        with path.open(encoding="utf-8") as handle:
            return yaml.load(handle, Loader=_StrictSafeLoader)
    except yaml.MarkedYAMLError as exc:
        where = ""
        if exc.problem_mark is not None:
            where = f"（第 {exc.problem_mark.line + 1} 行）"
        raise LoadError(f"{path} YAML 解析失败{where}: {exc.problem}") from exc
    except yaml.YAMLError as exc:
        raise LoadError(f"{path} YAML 解析失败: {exc}") from exc


REGISTRY_TTL = Path("registry") / "services.ttl"
REGISTRY_YAML = Path("registry") / "services.yaml"
PLATFORM_YAML = Path("registry") / "platform.yaml"


def load_registry(contracts_root: Path) -> dict[str, Any]:
    """读契约仓的服务登记。

    优先 ``services.ttl``（真源），其次 ``services.yaml``（兼容回退）。
    与图无关的平台配置（版本钉、服务发现）在 ``platform.yaml``，合并进同一视图——
    它们本来就不参与推理，没必要为了"单一格式"把版本号写成字面量三元组。
    """
    ttl_path = contracts_root / REGISTRY_TTL
    if ttl_path.is_file():
        from .registry_ttl import RegistryTTLError, parse_registry

        try:
            data = parse_registry(ttl_path)
        except RegistryTTLError as exc:
            raise LoadError(str(exc)) from exc
        platform_path = contracts_root / PLATFORM_YAML
        if platform_path.is_file():
            config = read_yaml(platform_path) or {}
            if isinstance(config, dict):
                for key, value in config.items():
                    if key != "schema":  # schema 以登记图自身的声明为准
                        data.setdefault(key, value)
        data.setdefault("services", [])
        data.setdefault("libraries", [])
        return data

    yaml_path = contracts_root / REGISTRY_YAML
    data = read_yaml(yaml_path)
    if not isinstance(data, dict):
        raise LoadError(f"{REGISTRY_YAML} 顶层不是映射")
    data.setdefault("services", [])
    data.setdefault("libraries", [])
    return data


def load_concepts(concepts_dir: Path) -> dict[str, Any]:
    """读 TBox（``concepts/tbox.ttl``）。

    返回的字典是内存视图：除三个列表外还带 ``tbox_graph``（原图），供导出与 SHACL
    验证直接使用，避免再从字典反向合成一遍相同的三元组。
    """
    from .concepts_ttl import TBOX_FILE, ConceptsTTLError, parse_concepts

    path = concepts_dir / TBOX_FILE
    if not path.is_file():
        raise LoadError(f"TBox 文件不存在: {path}")
    try:
        data, graph = parse_concepts(path)
    except ConceptsTTLError as exc:
        raise LoadError(str(exc)) from exc
    data["tbox_graph"] = graph
    return data


def load_redlines(contracts_root: Path) -> dict[str, Any]:
    """读契约仓的架构红线与例外登记。"""
    data = read_yaml(contracts_root / "ontology" / "constraints" / "redlines.yaml")
    if not isinstance(data, dict):
        raise LoadError("ontology/constraints/redlines.yaml 顶层不是映射")
    data.setdefault("constraints", [])
    data.setdefault("exceptions", [])
    return data


def load_decision_schema(contracts_root: Path, field: str = "enum") -> list[str]:
    """读契约层的决策枚举（真源之一）。字段名可参数化（缺省 enum）。"""
    data = read_yaml(contracts_root / "contracts" / "schemas" / "decision.yaml") or {}
    return list(data.get(field, []))
