"""CLI 测试：命令契约、历史检查器隔离、生成物可复现。"""

from __future__ import annotations

from pathlib import Path

import pytest

from checker.cli import ONTOLOGY_ROOT, _run_historical_check, main

TBOX = """@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

rcp:PatrolLine a owl:Class, rcp:Kind ;
    rdfs:subClassOf rcp:Service ;
    rdfs:label "巡查线" ;
    rcp:mustBeExternal false ; rcp:isEntry false ;
    rcp:requiresPort true ; rcp:requiresContract true .

rcp:PASS a rcp:Decision ; rdfs:label "放行" ; rcp:baseScore 0 .
rcp:INTERCEPT a rcp:Decision ; rdfs:label "拦截" ; rcp:baseScore 80 .
"""

ABOX_PLATFORM = """@prefix rcp: <https://risk-control.platform/ontology#> .
rcp:platform a rcp:Platform ;
    rcp:registrySchema "rcp.registry/v2" ;
    rcp:platformName "t" .
"""

ABOX_SERVICES = """@prefix rcp: <https://risk-control.platform/ontology#> .
rcp:ghost a rcp:PatrolLine, rcp:Service ;
    rcp:repo "rcp-ghost" ; rcp:port 8099 ;
    rcp:external false ; rcp:owner "platform" ;
    rcp:hasCapability rcp:patrol.ghost .
"""

POLICY = """@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
rcp:RL-001 a rcp:Redline ;
    rcp:redlineId "RL-001" ; rcp:slug "x" ; rdfs:label "x" ;
    rcp:spec [ a rcp:RegistryAssert ; rcp:via "kinds.allowedDependsOn" ] .
"""


def _minimal_ontology(tmp_path: Path) -> Path:
    """构造一个最小本体仓，含一个声明层违规（未立名能力 E202）。"""
    for layer in ("tbox", "abox", "policy"):
        (tmp_path / "ontology" / layer).mkdir(parents=True)
    (tmp_path / "ontology" / "tbox" / "tbox.ttl").write_text(TBOX, encoding="utf-8")
    (tmp_path / "ontology" / "abox" / "platform.ttl").write_text(ABOX_PLATFORM, encoding="utf-8")
    (tmp_path / "ontology" / "abox" / "services.ttl").write_text(ABOX_SERVICES, encoding="utf-8")
    (tmp_path / "ontology" / "policy" / "redlines.ttl").write_text(POLICY, encoding="utf-8")
    return tmp_path


def test_run_historical_check_reports_declaration_errors(tmp_path: Path):
    """历史检查器（本仓自身）经独立进程跑最小本体仓，能产出声明层结论（E202）。"""
    ontology = _minimal_ontology(tmp_path)
    findings = _run_historical_check(ONTOLOGY_ROOT, ontology)
    assert "E202" in {f.code for f in findings}


def test_run_historical_check_fails_on_missing_checker(tmp_path: Path):
    """检查器目录不可用时报错，而非静默返回空结论。"""
    ontology = _minimal_ontology(tmp_path)
    with pytest.raises(RuntimeError):
        _run_historical_check(tmp_path / "no-such-checker", ontology)


def test_check_without_contracts_reports_skip(tmp_path: Path, capsys):
    """不给 --contracts 时，RL-006 的磁盘判据必须明说跳过（S004），而不是静默通过。"""
    ontology = _minimal_ontology(tmp_path)
    main(["check", "--ontology", str(ontology), "-w", str(tmp_path)])
    out = capsys.readouterr().out
    assert "S004" in out


def test_render_schema_is_reproducible(tmp_path: Path):
    """生成物只随真源变化：同一份 decisions.ttl 必须产出逐字节相同的 YAML。"""
    ontology = _minimal_ontology(tmp_path)
    target = tmp_path / "decision.yaml"
    assert main(["render-schema", "--ontology", str(ontology), "--out", str(target)]) == 0
    first = target.read_text(encoding="utf-8")
    assert main(["render-schema", "--ontology", str(ontology), "--out", str(target)]) == 0
    assert target.read_text(encoding="utf-8") == first
    assert "INTERCEPT" in first and "x-base-score" in first


def test_impact_reports_unknown_service(tmp_path: Path, capsys):
    ontology = _minimal_ontology(tmp_path)
    assert main(["impact", "--ontology", str(ontology), "--service", "nope"]) == 2
    assert "未登记的服务" in capsys.readouterr().err
