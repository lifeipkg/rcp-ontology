"""检查器测试：正向必须闭合，反向必须报错。

每个反例只破坏一条约束，确保报告能定位到具体红线编号。
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from rcp_ontology.checks import (
    check_contracts_exist,
    check_decision_alignment,
    check_redlines,
    check_registry_shape,
    check_tbox_abox,
)

CONCEPTS = {
    "kinds": [
        {"name": "gateway", "must_be_external": True,
         "allowed_depends_on_kinds": ["patrol-line"]},
        {"name": "patrol-line", "must_be_external": False, "allowed_depends_on_kinds": []},
        {"name": "frontend", "must_be_external": True, "allowed_depends_on_kinds": ["gateway"]},
    ],
    "capabilities": [
        {"name": "patrol.dispatch"},
        {"name": "patrol.content.dedup"},
    ],
    "decisions": [
        {"code": "PASS", "base_score": 0},
        {"code": "INTERCEPT", "base_score": 80},
    ],
}


def service(**overrides):
    base = {
        "name": "content-patrol",
        "repo": "rcp-content-patrol",
        "kind": "patrol-line",
        "port": 8081,
        "external": False,
        "owner": "risk-content",
        "capabilities": ["patrol.content.dedup"],
        "depends_on": [],
        "contracts": ["contracts/openapi/content-patrol.yaml"],
    }
    base.update(overrides)
    return base


def gateway(**overrides):
    base = {
        "name": "api-gateway",
        "repo": "rcp-api-gateway",
        "kind": "gateway",
        "port": 8080,
        "external": True,
        "owner": "platform",
        "capabilities": ["patrol.dispatch"],
        "depends_on": ["content-patrol"],
        "contracts": ["contracts/openapi/api-gateway.yaml"],
    }
    base.update(overrides)
    return base


def codes(findings, level="error"):
    return {f.code for f in findings if f.level == level}


def test_clean_registry_has_no_errors():
    registry = {"services": [gateway(), service()], "libraries": []}
    assert check_registry_shape(registry) == []
    assert check_redlines(registry, CONCEPTS) == []
    assert check_tbox_abox(registry, CONCEPTS) == []


def test_patrol_line_cannot_depend_on_patrol_line():
    other = service(name="message-patrol", port=8082, depends_on=["content-patrol"])
    findings = check_redlines({"services": [service(), other]}, CONCEPTS)
    assert "RL-001" in codes(findings)


def test_patrol_line_must_not_be_external():
    findings = check_redlines({"services": [service(external=True)]}, CONCEPTS)
    assert "RL-002" in codes(findings)


def test_gateway_must_be_external():
    findings = check_redlines({"services": [gateway(external=False)]}, CONCEPTS)
    assert "RL-002" in codes(findings)


def test_frontend_may_depend_on_gateway_only():
    web = {
        "name": "web", "repo": "rcp-web", "kind": "frontend", "port": 5173,
        "external": True, "owner": "platform", "capabilities": [],
        "depends_on": ["content-patrol"], "contracts": [],
    }
    findings = check_redlines({"services": [gateway(), service(), web]}, CONCEPTS)
    assert "RL-001" in codes(findings)


def test_dependency_on_unregistered_service_is_error():
    findings = check_redlines({"services": [gateway(depends_on=["ghost"])]}, CONCEPTS)
    assert "E105" in codes(findings)


def test_duplicate_name_and_port():
    registry = {"services": [gateway(), gateway(port=8099)]}
    assert "E002" in codes(check_registry_shape(registry))


def test_missing_required_field():
    broken = service()
    del broken["owner"]
    assert "E001" in codes(check_registry_shape({"services": [broken]}))


def test_undeclared_kind_and_capability():
    findings = check_tbox_abox({"services": [service(kind="unknown", capabilities=["x.y"])]}, CONCEPTS)
    assert {"E201", "E202"} <= codes(findings)


def test_unused_capability_is_warning():
    findings = check_tbox_abox({"services": [service()]}, CONCEPTS)
    assert "W301" in codes(findings, level="warn")


def test_missing_contract_file(tmp_path: Path):
    registry = {"services": [service(contracts=["contracts/openapi/nope.yaml"])]}
    findings = check_contracts_exist(tmp_path, registry)
    assert "RL-006" in codes(findings)


def test_frontend_without_contracts_is_fine(tmp_path: Path):
    web = {"name": "web", "kind": "frontend", "contracts": []}
    assert check_contracts_exist(tmp_path, {"services": [web]}) == []


def test_decision_enum_drift_detected(tmp_path: Path):
    schemas = tmp_path / "contracts" / "schemas"
    schemas.mkdir(parents=True)
    (schemas / "decision.yaml").write_text(
        yaml.safe_dump({"enum": ["PASS", "WARN", "INTERCEPT"]}), encoding="utf-8"
    )
    findings = check_decision_alignment(tmp_path, CONCEPTS)
    assert "RL-003" in codes(findings)


def test_decision_enum_aligned(tmp_path: Path):
    schemas = tmp_path / "contracts" / "schemas"
    schemas.mkdir(parents=True)
    (schemas / "decision.yaml").write_text(
        yaml.safe_dump({"enum": ["PASS", "INTERCEPT"]}), encoding="utf-8"
    )
    assert check_decision_alignment(tmp_path, CONCEPTS) == []


def test_real_contracts_repo_is_closed():
    contracts = Path(__file__).resolve().parent.parent.parent / "rcp-contracts"
    concepts = Path(__file__).resolve().parent.parent / "concepts"
    if not contracts.is_dir():
        pytest.skip("工作区无 rcp-contracts，跳过集成检查")
    from rcp_ontology.checks import check_all

    assert [f for f in check_all(contracts, concepts) if f.level == "error"] == []
