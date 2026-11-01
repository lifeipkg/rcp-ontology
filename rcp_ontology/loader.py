"""本体仓：概念装载与结果类型。

TBox（概念/种类/能力/决策语义）在 concepts/，ABox（具体服务实例）在契约仓
registry/services.yaml。本包只读，不写任何声明文件。

YAML 一律用严格装载：重复键视为解析失败，而不是静默取后者。多人同时编辑同一份
声明时，重复键会让"文件里写了什么"与"程序读到什么"不一致，这类错误必须显式失败。
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


def load_registry(contracts_root: Path) -> dict[str, Any]:
    """读契约仓的服务登记。"""
    data = read_yaml(contracts_root / "registry" / "services.yaml")
    if not isinstance(data, dict):
        raise LoadError("registry/services.yaml 顶层不是映射")
    data.setdefault("services", [])
    data.setdefault("libraries", [])
    return data


def load_concepts(concepts_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """读 TBox 三份概念文件。"""
    kinds = read_yaml(concepts_dir / "kinds.yaml") or {}
    caps = read_yaml(concepts_dir / "capabilities.yaml") or {}
    decisions = read_yaml(concepts_dir / "decisions.yaml") or {}
    return {
        "kinds": kinds.get("concepts", []),
        "capabilities": caps.get("concepts", []),
        "decisions": decisions.get("enum", []),
    }


def load_redlines(contracts_root: Path) -> dict[str, Any]:
    """读契约仓的架构红线与例外登记。"""
    data = read_yaml(contracts_root / "ontology" / "constraints" / "redlines.yaml")
    if not isinstance(data, dict):
        raise LoadError("ontology/constraints/redlines.yaml 顶层不是映射")
    data.setdefault("constraints", [])
    data.setdefault("exceptions", [])
    return data


def load_terms(contracts_root: Path) -> list[dict[str, Any]]:
    """读平台立名词汇表。缺文件不算错——词汇表是可选声明。"""
    path = contracts_root / "vocabulary" / "terms.yaml"
    if not path.is_file():
        return []
    data = read_yaml(path) or {}
    return list(data.get("terms", []))


def load_decision_schema(contracts_root: Path) -> list[str]:
    """读契约层的决策枚举（真源之一）。"""
    data = read_yaml(contracts_root / "contracts" / "schemas" / "decision.yaml") or {}
    return list(data.get("enum", []))
