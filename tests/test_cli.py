"""CLI 测试：--baseline/--checker-ref 架构熵基线对比（历史检查器看历史数据）。"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from rcp_ontology.cli import ONTOLOGY_ROOT, _run_historical_check


def _minimal_contracts(tmp_path: Path) -> Path:
    """构造一个最小契约仓，含一个声明层违规（未立名能力 E202）。"""
    (tmp_path / "registry").mkdir()
    (tmp_path / "registry" / "services.yaml").write_text(
        yaml.safe_dump({
            "services": [{
                "name": "ghost", "repo": "rcp-ghost", "kind": "patrol-line",
                "port": 8099, "external": False, "owner": "platform",
                "capabilities": ["patrol.ghost"],
                "depends_on": [], "contracts": [],
            }],
            "libraries": [],
        }),
        encoding="utf-8",
    )
    (tmp_path / "ontology" / "constraints").mkdir(parents=True)
    (tmp_path / "ontology" / "constraints" / "redlines.yaml").write_text(
        "constraints: []\nexceptions: []\n", encoding="utf-8"
    )
    return tmp_path


def test_run_historical_check_reports_declaration_errors(tmp_path: Path):
    """历史检查器（本仓自身）经独立进程跑最小契约仓，能产出声明层结论（E202）。"""
    contracts = _minimal_contracts(tmp_path)
    findings = _run_historical_check(ONTOLOGY_ROOT, contracts)
    codes = {f.code for f in findings}
    assert "E202" in codes


def test_run_historical_check_fails_on_missing_checker(tmp_path: Path):
    """检查器目录不可用时报错，而非静默返回空结论。"""
    contracts = _minimal_contracts(tmp_path)
    with pytest.raises(RuntimeError):
        _run_historical_check(tmp_path / "no-such-checker", contracts)
