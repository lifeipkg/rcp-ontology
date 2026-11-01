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
    check_redline_coverage,
    check_redlines,
    check_registry_shape,
    check_tbox_abox,
)
from rcp_ontology.layout import (
    check_ddl_location,
    check_hardcoded_upstream,
    check_jdbc_in_business,
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
    # 非巡查线互调，走内置编号；RL-001 只留给 patrol-line ↔ patrol-line。
    assert "E106" in codes(findings)
    assert "RL-001" not in codes(findings)


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


DATAWAY = {
    "name": "dataway", "repo": "rcp-dataway", "kind": "data-gateway", "port": 8090,
    "external": False, "owner": "platform", "capabilities": [],
    "depends_on": [], "contracts": ["contracts/openapi/dataway.yaml"],
}


def _pom_with(group: str, artifact: str) -> str:
    return (
        "<project><dependencies><dependency>"
        f"<groupId>{group}</groupId><artifactId>{artifact}</artifactId>"
        "</dependency></dependencies></project>"
    )


def test_declared_redline_without_implementation_is_paper_redline():
    redlines = {"constraints": [{"id": "RL-001"}, {"id": "RL-999"}], "exceptions": []}
    findings = check_redline_coverage(redlines)
    assert "E301" in codes(findings)


def test_implemented_redline_not_declared_is_warning():
    findings = check_redline_coverage({"constraints": [{"id": "RL-001"}], "exceptions": []})
    assert "W302" in codes(findings, level="warn")


def test_ddl_outside_migrations_is_error(tmp_path: Path):
    repo = tmp_path / "rcp-content-patrol"
    repo.mkdir()
    (repo / "schema.sql").write_text("CREATE TABLE t (id INT);", encoding="utf-8")
    assert "RL-004" in codes(check_ddl_location(tmp_path))


def test_ddl_inside_migrations_is_allowed(tmp_path: Path):
    migrations = tmp_path / "rcp-ops" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "V1.0.0__init.sql").write_text("CREATE TABLE t (id INT);", encoding="utf-8")
    assert check_ddl_location(tmp_path) == []


def test_ddl_in_detached_migrations_repo_is_allowed(tmp_path: Path):
    """rcp-ops 被单独检出（worktree / 独立 clone）时，根下 migrations/ 同样放行。"""
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "V1.0.0__init.sql").write_text("CREATE TABLE t (id INT);", encoding="utf-8")
    assert check_ddl_location(tmp_path) == []


def test_ddl_in_business_repo_migrations_dir_is_still_error(tmp_path: Path):
    """业务仓自建 migrations/ 不能绕过 RL-004。"""
    sneaky = tmp_path / "rcp-content-patrol" / "migrations"
    sneaky.mkdir(parents=True)
    (sneaky / "V9.9.9__hack.sql").write_text("ALTER TABLE t ADD c INT;", encoding="utf-8")
    assert "RL-004" in codes(check_ddl_location(tmp_path))


def test_jdbc_driver_in_business_service_is_error(tmp_path: Path):
    repo = tmp_path / "rcp-content-patrol"
    repo.mkdir()
    (repo / "pom.xml").write_text(_pom_with("com.mysql", "mysql-connector-j"), encoding="utf-8")
    registry = {"services": [service(), DATAWAY], "libraries": []}
    assert "RL-005" in codes(check_jdbc_in_business(tmp_path, registry))


def test_jdbc_driver_in_data_gateway_is_allowed(tmp_path: Path):
    repo = tmp_path / "rcp-dataway"
    repo.mkdir()
    (repo / "pom.xml").write_text(_pom_with("com.mysql", "mysql-connector-j"), encoding="utf-8")
    assert check_jdbc_in_business(tmp_path, {"services": [DATAWAY], "libraries": []}) == []


def _compose(tmp_path: Path, line: str) -> Path:
    ops = tmp_path / "rcp-ops"
    ops.mkdir()
    target = ops / "docker-compose.yml"
    target.write_text(line + "\n", encoding="utf-8")
    return target


UPSTREAM_LINE = "      PATROL_ROUTES_ENDPOINTS_CONTENT: http://content-patrol:8081"
EXCEPTION = {
    "redline": "RL-007",
    "scope": "rcp-ops/**",
    "match": "http://content-patrol:\\d+",
    "reason": "服务发现未接入",
    "owner": "platform",
    "review_by": "2099-01-01",
}


def test_hardcoded_upstream_is_error(tmp_path: Path):
    _compose(tmp_path, UPSTREAM_LINE)
    findings = check_hardcoded_upstream(tmp_path, {"services": [service()]})
    assert "RL-007" in codes(findings)


def test_external_service_address_is_not_checked(tmp_path: Path):
    _compose(tmp_path, "      WEB_URL: http://web:5173")
    assert check_hardcoded_upstream(tmp_path, {"services": [service()]}) == []


def test_registered_exception_downgrades_to_warning(tmp_path: Path):
    _compose(tmp_path, UPSTREAM_LINE)
    findings = check_hardcoded_upstream(tmp_path, {"services": [service()]}, [EXCEPTION])
    assert not codes(findings)
    assert "RL-007" in codes(findings, level="warn")


def test_exception_without_scope_match_still_errors(tmp_path: Path):
    _compose(tmp_path, "      X: http://message-patrol:8082")
    findings = check_hardcoded_upstream(tmp_path, {"services": [service(name="message-patrol", port=8082)]}, [EXCEPTION])
    assert "RL-007" in codes(findings)


def test_expired_exception_is_error(tmp_path: Path):
    _compose(tmp_path, UPSTREAM_LINE)
    expired = {**EXCEPTION, "review_by": "2020-01-01"}
    findings = check_hardcoded_upstream(tmp_path, {"services": [service()]}, [expired])
    assert "RL-007" in codes(findings)


def test_real_contracts_repo_is_closed():
    """集成检查：真实契约仓必须闭合。

    环境变量 RCP_WORKSPACE / RCP_CONTRACTS 用于在 worktree 里验证未合并的改动。
    """
    import os

    contracts = Path(os.environ.get("RCP_CONTRACTS")
                     or Path(__file__).resolve().parent.parent.parent / "rcp-contracts")
    workspace = Path(os.environ.get("RCP_WORKSPACE") or contracts.parent)
    concepts = Path(__file__).resolve().parent.parent / "concepts"
    if not contracts.is_dir():
        pytest.skip("工作区无 rcp-contracts，跳过集成检查")
    from rcp_ontology.checks import check_all

    errors = [f for f in check_all(contracts, concepts, workspace) if f.level == "error"]
    assert errors == []
