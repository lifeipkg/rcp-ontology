"""本体仓：概念装载与结果类型。

TBox（概念/种类/能力/决策语义）在 concepts/，ABox（具体服务实例）在契约仓
registry/services.yaml。本包只读，不写任何声明文件。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

__version__ = "1.0.0"


class LoadError(RuntimeError):
    """声明文件缺失或不可解析。"""


@dataclass(frozen=True)
class Finding:
    """一条检查结论。code 对应红线编号或内置校验编号。"""

    level: str
    code: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"level": self.level, "code": self.code, "message": self.message}


def read_yaml(path: Path) -> Any:
    if not path.is_file():
        raise LoadError(f"文件不存在: {path}")
    try:
        with path.open(encoding="utf-8") as handle:
            return yaml.safe_load(handle)
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


def load_decision_schema(contracts_root: Path) -> list[str]:
    """读契约层的决策枚举（真源之一）。"""
    data = read_yaml(contracts_root / "contracts" / "schemas" / "decision.yaml") or {}
    return list(data.get("enum", []))
