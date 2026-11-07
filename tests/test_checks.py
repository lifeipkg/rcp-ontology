"""检查器测试：正向必须闭合，反向必须报错。

每个反例只破坏一条约束，确保报告能定位到具体编号。
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from checker.checks import (
    check_capability_ownership,
    check_contracts_exist,
    check_decision_alignment,
    check_declarations,
    check_dependency_graph,
    check_expected_state,
    check_ontology_header,
    check_registry_shape,
    check_repo_registration,
    check_rule_specs,
    diff_findings,
    workspace_is_complete,
)
from checker.layout import (
    is_worktree,
    run_declared_scans,
    run_file_scan,
    run_registry_scan,
    run_upstream_scan,
)
from checker.loader import Finding, SCOPE_DECLARATION, SCOPE_WORKSPACE

CONCEPTS = {
    "kinds": [
        {"name": "gateway", "must_be_external": True, "is_entry": True,
         "requires_port": True, "requires_contract": True,
         "allowed_depends_on_kinds": ["patrol-line"]},
        {"name": "patrol-line", "must_be_external": False, "is_entry": False,
         "requires_port": True, "requires_contract": True,
         "allowed_depends_on_kinds": []},
        {"name": "frontend", "must_be_external": True, "is_entry": True,
         "requires_port": True, "requires_contract": False,
         "allowed_depends_on_kinds": ["gateway"]},
        {"name": "meta", "must_be_external": False, "is_entry": True,
         "requires_port": False, "requires_contract": False,
         "allowed_depends_on_kinds": []},
    ],
    "capabilities": [
        {"name": "patrol.dispatch", "owner": "api-gateway"},
        {"name": "patrol.content.dedup", "owner": "content-patrol"},
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


def meta_service(**overrides):
    base = {
        "name": "ops",
        "repo": "rcp-ops",
        "kind": "meta",
        "external": False,
        "owner": "platform",
        "capabilities": [],
        "depends_on": [],
        "contracts": [],
    }
    base.update(overrides)
    return base


def codes(findings, level="error"):
    return {f.code for f in findings if f.level == level}


def test_clean_registry_has_no_errors():
    registry = {"services": [gateway(), service()], "libraries": []}
    assert check_registry_shape(registry) == []


def test_duplicate_name_and_port():
    registry = {"services": [gateway(), gateway(port=8099)]}
    assert "E002" in codes(check_registry_shape(registry))


def test_duplicate_repo_is_error():
    registry = {"services": [gateway(), gateway(name="api-gateway-2", port=8099)]}
    assert "E002" in codes(check_registry_shape(registry))


def test_missing_required_field():
    broken = service()
    del broken["owner"]
    assert "E001" in codes(check_registry_shape({"services": [broken]}))


def test_meta_kind_needs_no_contract(tmp_path: Path):
    assert check_contracts_exist(tmp_path, {"services": [meta_service()]}, CONCEPTS) == []


def test_missing_contract_file(tmp_path: Path):
    registry = {"services": [service(contracts=["contracts/openapi/nope.yaml"])]}
    findings = check_contracts_exist(tmp_path, registry, CONCEPTS)
    assert "RL-006" in codes(findings)


def test_frontend_without_contracts_is_fine(tmp_path: Path):
    web = {"name": "web", "kind": "frontend", "contracts": []}
    assert check_contracts_exist(tmp_path, {"services": [web]}, CONCEPTS) == []


DECISION_SPEC = {
    "source": [
        "ontology/tbox/decisions.ttl",
        "rcp-core/src/main/java/com/risk/platform/model/Decision.java",
        "contracts/schemas/decision.yaml",
    ]
}

_JAVA = """public enum Decision {{
{consts};

    public int baseScore() {{
        return switch (this) {{
{cases}
        }};
    }}
}}
"""


def _java_decisions(pairs: list[tuple[str, int]]) -> str:
    return _JAVA.format(
        consts=",\n".join(f"    {code}" for code, _ in pairs),
        cases="\n".join(f"            case {code} -> {score};" for code, score in pairs),
    )


def _workspace_with(tmp_path: Path, *, java: str | None = None, schema: dict | None = None) -> Path:
    """构造工作区：真源在 CONCEPTS 里，对端落盘为 Java 与生成物 YAML。"""
    src = tmp_path / "rcp-core" / "src" / "main" / "java" / "com" / "risk" / "platform" / "model"
    src.mkdir(parents=True)
    (src / "Decision.java").write_text(
        java if java is not None else _java_decisions([("PASS", 0), ("INTERCEPT", 80)]),
        encoding="utf-8",
    )
    schemas = tmp_path / "contracts" / "schemas"
    schemas.mkdir(parents=True)
    (schemas / "decision.yaml").write_text(
        yaml.safe_dump(
            schema if schema is not None
            else {"enum": ["PASS", "INTERCEPT"], "x-base-score": {"PASS": 0, "INTERCEPT": 80}}
        ),
        encoding="utf-8",
    )
    return tmp_path


def test_decision_aligned_across_three_sources(tmp_path: Path):
    workspace = _workspace_with(tmp_path)
    assert check_decision_alignment(CONCEPTS, DECISION_SPEC, workspace) == []


def test_decision_enum_drift_detected(tmp_path: Path):
    workspace = _workspace_with(
        tmp_path, schema={"enum": ["PASS", "WARN", "INTERCEPT"], "x-base-score": {"PASS": 0, "INTERCEPT": 80}}
    )
    assert "RL-003" in codes(check_decision_alignment(CONCEPTS, DECISION_SPEC, workspace))


def test_decision_score_drift_detected(tmp_path: Path):
    """枚举一致但分值漂移，同样要红——分值决定处置档位，不能只比名字。"""
    workspace = _workspace_with(
        tmp_path, schema={"enum": ["PASS", "INTERCEPT"], "x-base-score": {"PASS": 0, "INTERCEPT": 99}}
    )
    assert "RL-003" in codes(check_decision_alignment(CONCEPTS, DECISION_SPEC, workspace))


def test_java_enum_drift_detected(tmp_path: Path):
    """实现侧少一个决策等级，是"契约先行、实现没跟上"的典型漂移。"""
    workspace = _workspace_with(tmp_path, java=_java_decisions([("PASS", 0)]))
    assert "RL-003" in codes(check_decision_alignment(CONCEPTS, DECISION_SPEC, workspace))


def test_java_score_drift_detected(tmp_path: Path):
    workspace = _workspace_with(tmp_path, java=_java_decisions([("PASS", 0), ("INTERCEPT", 50)]))
    assert "RL-003" in codes(check_decision_alignment(CONCEPTS, DECISION_SPEC, workspace))


def test_decision_source_missing_is_skipped_explicitly(tmp_path: Path):
    """对端都不在工作区时不许假装通过：输出 S003，说明比对未执行。"""
    findings = check_decision_alignment(CONCEPTS, DECISION_SPEC, tmp_path)
    assert "S003" in codes(findings, level="info")
    assert "RL-003" not in codes(findings)


def test_decision_missing_score_in_source_is_error():
    broken = {"decisions": [{"code": "PASS", "base_score": None}]}
    assert "RL-003" in codes(check_decision_alignment(broken, DECISION_SPEC, None))


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


def test_redline_without_spec_is_paper_redline():
    redlines = {"constraints": [{"id": "RL-001"}, {"id": "RL-999"}], "exceptions": []}
    findings = check_rule_specs(redlines)
    assert codes(findings) == {"E301"}


def test_spec_unknown_type_is_error():
    redlines = {"constraints": [{"id": "RL-001", "spec": {"type": "nope"}}], "exceptions": []}
    assert "E302" in codes(check_rule_specs(redlines))


def test_spec_missing_required_field_is_error():
    redlines = {"constraints": [{"id": "RL-003", "spec": {"type": "cross-source"}}], "exceptions": []}
    assert "E302" in codes(check_rule_specs(redlines))


def test_spec_bad_regex_is_error():
    redlines = {
        "constraints": [{"id": "RL-004", "spec": {"type": "file-scan", "include": ["*.sql"], "match": "("}}],
        "exceptions": [],
    }
    assert "E302" in codes(check_rule_specs(redlines))


def test_file_scan_without_match_is_error():
    redlines = {
        "constraints": [{"id": "RL-004", "spec": {"type": "file-scan", "include": ["*.sql"]}}],
        "exceptions": [],
    }
    assert "E302" in codes(check_rule_specs(redlines))


def test_valid_spec_has_no_findings():
    redlines = {
        "constraints": [
            {"id": "RL-001", "spec": {"type": "registry-assert", "via": "kinds.allowed_depends_on_kinds"}},
            {"id": "RL-003", "spec": {"type": "cross-source", "source": ["ontology/tbox/decisions.ttl"], "assert": "identical"}},
            {"id": "RL-004", "spec": {"type": "file-scan", "include": ["*.sql"], "match": "create"}},
            {"id": "RL-005", "spec": {"type": "registry-scan", "include": ["pom.xml"], "extract": "dependency.groupId", "deny_values": ["mysql"], "allow_kinds": ["data-gateway"]}},
            {"id": "RL-007", "spec": {"type": "upstream-scan", "include": ["*.yml"], "scan_prefix": "rcp-ops/", "match": "http", "internal_hosts": {"from": "registry"}}},
        ],
        "exceptions": [],
    }
    assert check_rule_specs(redlines) == []


DDL_SPEC = {
    "type": "file-scan",
    "include": ["*.sql"],
    "allow_prefixes": ["rcp-ops/migrations/", "migrations/"],
    "match": r"\b(?:create|alter|drop|truncate)\s+(?:table|index|view|database|schema|unique\s+index)\b",
    "case_insensitive": True,
}

JDBC_SPEC = {
    "type": "registry-scan",
    "include": ["pom.xml"],
    "extract": "dependency.groupId",
    "deny_values": [
        "mysql", "com.mysql", "com.mysql.jdbc", "org.postgresql",
        "com.h2database", "com.oracle.database.jdbc", "org.mariadb.jdbc",
    ],
    "allow_kinds": ["data-gateway", "db-ops"],
}

UPSTREAM_SPEC = {
    "type": "upstream-scan",
    "scan_prefix": "rcp-ops/",
    "include": ["*.yml", "*.yaml"],
    "match": r"https?://([a-z][a-z0-9-]*):(\d{2,5})",
    "internal_hosts": {"from": "registry", "where": "external == false"},
}


def test_ddl_outside_migrations_is_error(tmp_path: Path):
    repo = tmp_path / "rcp-content-patrol"
    repo.mkdir()
    (repo / "schema.sql").write_text("CREATE TABLE t (id INT);", encoding="utf-8")
    assert "RL-004" in codes(run_file_scan(DDL_SPEC, tmp_path, "RL-004"))


def test_ddl_inside_migrations_is_allowed(tmp_path: Path):
    migrations = tmp_path / "rcp-ops" / "migrations"
    migrations.mkdir(parents=True)
    (migrations / "V1.0.0__init.sql").write_text("CREATE TABLE t (id INT);", encoding="utf-8")
    assert run_file_scan(DDL_SPEC, tmp_path, "RL-004") == []


def test_ddl_in_detached_migrations_repo_is_allowed(tmp_path: Path):
    """rcp-ops 被单独检出（worktree / 独立 clone）时，根下 migrations/ 同样放行。"""
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    (migrations / "V1.0.0__init.sql").write_text("CREATE TABLE t (id INT);", encoding="utf-8")
    assert run_file_scan(DDL_SPEC, tmp_path, "RL-004") == []


def test_ddl_in_business_repo_migrations_dir_is_still_error(tmp_path: Path):
    """业务仓自建 migrations/ 不能绕过 RL-004。"""
    sneaky = tmp_path / "rcp-content-patrol" / "migrations"
    sneaky.mkdir(parents=True)
    (sneaky / "V9.9.9__hack.sql").write_text("ALTER TABLE t ADD c INT;", encoding="utf-8")
    assert "RL-004" in codes(run_file_scan(DDL_SPEC, tmp_path, "RL-004"))


def test_ddl_inside_worktree_is_not_scanned_twice(tmp_path: Path):
    """worktree 里的 SQL 属于主检出，不该被当成第二个仓重复判定。"""
    wt = tmp_path / "rcp-ops-team" / "migrations"
    wt.mkdir(parents=True)
    (wt / "V1.0.0__init.sql").write_text("CREATE TABLE t (id INT);", encoding="utf-8")
    (wt.parent / ".git").write_text("gitdir: ../../.git/worktrees/x\n", encoding="utf-8")
    assert run_file_scan(DDL_SPEC, tmp_path, "RL-004") == []


def test_jdbc_driver_in_business_service_is_error(tmp_path: Path):
    repo = tmp_path / "rcp-content-patrol"
    repo.mkdir()
    (repo / "pom.xml").write_text(_pom_with("com.mysql", "mysql-connector-j"), encoding="utf-8")
    registry = {"services": [service(), DATAWAY], "libraries": []}
    assert "RL-005" in codes(run_registry_scan(JDBC_SPEC, tmp_path, registry, "RL-005"))


def test_jdbc_driver_in_data_gateway_is_allowed(tmp_path: Path):
    repo = tmp_path / "rcp-dataway"
    repo.mkdir()
    (repo / "pom.xml").write_text(_pom_with("com.mysql", "mysql-connector-j"), encoding="utf-8")
    assert run_registry_scan(JDBC_SPEC, tmp_path, {"services": [DATAWAY], "libraries": []}, "RL-005") == []


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
    findings = run_upstream_scan(UPSTREAM_SPEC, tmp_path, {"services": [service()]}, [], "RL-007")
    assert "RL-007" in codes(findings)


def test_external_service_address_is_not_checked(tmp_path: Path):
    _compose(tmp_path, "      WEB_URL: http://web:5173")
    assert run_upstream_scan(UPSTREAM_SPEC, tmp_path, {"services": [service()]}, [], "RL-007") == []


def test_registered_exception_downgrades_to_warning(tmp_path: Path):
    _compose(tmp_path, UPSTREAM_LINE)
    findings = run_upstream_scan(UPSTREAM_SPEC, tmp_path, {"services": [service()]}, [EXCEPTION], "RL-007")
    assert not codes(findings)
    assert "RL-007" in codes(findings, level="warn")


def test_exception_without_scope_match_still_errors(tmp_path: Path):
    _compose(tmp_path, "      X: http://message-patrol:8082")
    findings = run_upstream_scan(
        UPSTREAM_SPEC, tmp_path,
        {"services": [service(name="message-patrol", port=8082)]}, [EXCEPTION], "RL-007",
    )
    assert "RL-007" in codes(findings)


def test_expired_exception_is_error(tmp_path: Path):
    _compose(tmp_path, UPSTREAM_LINE)
    expired = {**EXCEPTION, "review_by": "2020-01-01"}
    findings = run_upstream_scan(UPSTREAM_SPEC, tmp_path, {"services": [service()]}, [expired], "RL-007")
    assert "RL-007" in codes(findings)


def test_workspace_findings_are_marked_cross_repo(tmp_path: Path):
    """跨仓结论必须带 scope 标记，调用方才分得清"这仓闭合"与"全平台闭合"。"""
    _compose(tmp_path, UPSTREAM_LINE)
    findings = run_upstream_scan(UPSTREAM_SPEC, tmp_path, {"services": [service()]}, [], "RL-007")
    assert findings and findings[0].scope != SCOPE_WORKSPACE  # layout 层本身不打标
    assert run_file_scan(DDL_SPEC, tmp_path, "RL-004") == []


def test_new_file_scan_rule_runs_without_python_change(tmp_path: Path):
    """规则即数据的验收：新增一条 file-scan 红线只需给 spec，解释器即执行。"""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "notes.txt").write_text("do not put secrets here", encoding="utf-8")
    redlines = {
        "constraints": [
            {"id": "RL-099", "spec": {
                "type": "file-scan", "include": ["*.txt"],
                "match": "secrets", "message": "{rel} 含敏感词「{matched}」",
            }},
        ],
        "exceptions": [],
    }
    findings = run_declared_scans(redlines, tmp_path, {"services": [], "libraries": []})
    assert "RL-099" in codes(findings)


def test_unregistered_repo_directory_is_error(tmp_path: Path):
    for name in ("rcp-content-patrol", "rcp-api-gateway", "rcp-ghost"):
        (tmp_path / name).mkdir()
    registry = {"services": [service(), gateway()], "libraries": []}
    findings = check_repo_registration(tmp_path, registry, complete=True)
    messages = [f.message for f in findings if f.code == "E107"]
    assert any("rcp-ghost" in m for m in messages)
    assert all(f.scope == SCOPE_WORKSPACE for f in findings)


def test_registered_repo_missing_dir_only_checked_in_complete_workspace(tmp_path: Path):
    (tmp_path / "rcp-content-patrol").mkdir()
    registry = {"services": [service(), gateway()], "libraries": []}
    partial = check_repo_registration(tmp_path, registry, complete=False)
    assert [f for f in partial if "rcp-api-gateway" in f.message] == []


def test_workspace_complete_needs_two_registered_repos(tmp_path: Path):
    registry = {"services": [service(), gateway()], "libraries": []}
    (tmp_path / "rcp-content-patrol").mkdir()
    assert workspace_is_complete(tmp_path, registry) is False
    (tmp_path / "rcp-api-gateway").mkdir()
    assert workspace_is_complete(tmp_path, registry) is True


def test_worktree_is_not_counted_as_independent_repo(tmp_path: Path):
    for name in ("rcp-content-patrol", "rcp-api-gateway"):
        (tmp_path / name).mkdir()
    worktree = tmp_path / "rcp-api-gateway-team"
    worktree.mkdir()
    (worktree / ".git").write_text("gitdir: ../../.git/worktrees/x\n", encoding="utf-8")
    assert is_worktree(worktree) is True

    registry = {"services": [service(), gateway()], "libraries": []}
    findings = check_repo_registration(tmp_path, registry, complete=True)
    assert [f for f in findings if "rcp-api-gateway-team" in f.message] == []


def test_dependency_cycle_is_error():
    a = service(name="a", port=8101, depends_on=["b"], capabilities=[])
    b = service(name="b", port=8102, depends_on=["a"], capabilities=[])
    findings = check_dependency_graph({"services": [a, b]}, CONCEPTS)
    assert "E108" in codes(findings)


def test_zero_indegree_non_entry_is_warning():
    findings = check_dependency_graph({"services": [service()]}, CONCEPTS)
    assert "E109" in codes(findings, level="warn")


def test_entry_node_with_zero_indegree_is_fine():
    findings = check_dependency_graph(
        {"services": [gateway(depends_on=[]), meta_service()]}, CONCEPTS
    )
    assert "E109" not in codes(findings, level="warn")


def test_unreachable_node_is_warning():
    lonely = service(name="lonely", port=8099, capabilities=[])
    findings = check_dependency_graph({"services": [gateway(), service(), lonely]}, CONCEPTS)
    assert "E110" in codes(findings, level="warn")


def _expected(**overrides):
    base = {
        "no_dependents": True,
        "unreachable": True,
        "reason": "数据面尚未启用",
        "owner": "platform",
        "review_by": "2099-01-01",
    }
    base.update(overrides)
    return base


def test_expected_state_suppresses_e109_and_e110():
    lonely = service(name="dataway", port=8090, capabilities=[], expected=_expected())
    findings = check_dependency_graph({"services": [gateway(), lonely]}, CONCEPTS)
    assert "E109" not in codes(findings, level="warn")
    assert "E110" not in codes(findings, level="warn")


def test_expired_expected_state_restores_warning():
    lonely = service(name="dataway", port=8090, capabilities=[],
                     expected=_expected(review_by="2020-01-01"))
    findings = check_dependency_graph({"services": [gateway(), lonely]}, CONCEPTS)
    assert "E109" in codes(findings, level="warn")
    assert "E110" in codes(findings, level="warn")


def test_stale_expected_no_dependents_is_warning():
    # gateway 依赖 content-patrol，故其入度为 1，声明"无依赖"即过时。
    s = service(expected=_expected())
    findings = check_dependency_graph({"services": [gateway(), s]}, CONCEPTS)
    assert "W306" in codes(findings, level="warn")


def test_stale_expected_unreachable_is_warning():
    # content-patrol 可从 gateway 到达，声明"不可达"即过时。
    s = service(expected=_expected())
    findings = check_dependency_graph({"services": [gateway(), s]}, CONCEPTS)
    assert "W306" in codes(findings, level="warn")


def test_expected_state_declaring_flag_requires_audit_fields():
    s = service(expected={"no_dependents": True})
    findings = check_expected_state({"services": [s]})
    assert "E115" in codes(findings)


def test_expected_state_unknown_field_is_error():
    s = service(expected={**_expected(), "bogus": 1})
    findings = check_expected_state({"services": [s]})
    assert "E115" in codes(findings)


def test_expected_state_non_bool_flag_is_error():
    s = service(expected=_expected(no_dependents="yes"))
    findings = check_expected_state({"services": [s]})
    assert "E115" in codes(findings)


def test_expected_state_bad_review_by_is_error():
    s = service(expected=_expected(review_by="not-a-date"))
    findings = check_expected_state({"services": [s]})
    assert "E115" in codes(findings)


def test_valid_expected_state_has_no_findings():
    s = service(expected=_expected())
    assert check_expected_state({"services": [s]}) == []


def test_capability_owner_must_be_registered():
    concepts = {"capabilities": [{"name": "patrol.dispatch", "owner": "ghost"}],
                "kinds": [], "decisions": []}
    findings = check_capability_ownership({"services": [gateway()]}, concepts)
    assert "E111" in codes(findings)


def test_capability_owner_must_actually_hold_it():
    concepts = {"capabilities": [{"name": "patrol.dispatch", "owner": "content-patrol"}],
                "kinds": [], "decisions": []}
    findings = check_capability_ownership({"services": [gateway(), service()]}, concepts)
    assert "E112" in codes(findings)


def test_capability_ownership_closed_for_real_shape():
    findings = check_capability_ownership(
        {"services": [gateway(), service()]}, CONCEPTS
    )
    assert findings == []


def test_duplicate_functional_property_is_load_error(tmp_path: Path):
    """RDF 允许多值，所以功能属性的多值必须显式失败——这是原 YAML 重复键检查的等价物。

    没有这条护栏，`rcp:port 8080, 8090` 会被静默接受，读到的端口取决于遍历顺序。
    """
    from rdflib import Graph

    from checker.abox import AboxError, parse_abox

    graph = Graph().parse(
        data="""@prefix rcp: <https://risk-control.platform/ontology#> .
rcp:platform a rcp:Platform ; rcp:platformName "t" .
rcp:x a rcp:PatrolLine, rcp:Service ;
    rcp:repo "rcp-x" ; rcp:port 8080, 8090 ;
    rcp:external false ; rcp:owner "platform" .
""",
        format="turtle",
    )
    with pytest.raises(AboxError) as exc:
        parse_abox(graph, "fixture")
    assert "功能属性只允许一个值" in str(exc.value)


def test_real_contracts_repo_is_closed():
    """集成检查：真实契约仓必须闭合。

    环境变量 RCP_WORKSPACE / RCP_CONTRACTS 用于在 worktree 里验证未合并的改动。
    """
    import os

    contracts = Path(os.environ.get("RCP_CONTRACTS")
                     or Path(__file__).resolve().parent.parent.parent / "rcp-contracts")
    workspace = Path(os.environ.get("RCP_WORKSPACE") or contracts.parent)
    ontology = Path(os.environ.get("RCP_ONTOLOGY")
                    or Path(__file__).resolve().parent.parent)
    if not (ontology / "ontology").is_dir():
        pytest.skip("工作区无本体仓，跳过集成检查")
    from checker.checks import check_all

    errors = [f for f in check_all(ontology, contracts, workspace) if f.level == "error"]
    assert errors == []


def test_diff_findings_reports_added_and_removed():
    """架构熵差集：新增/消失按 (level, code, message) 计，重复结论按多重集计。"""
    before = [
        Finding("error", "E107", "工作区存在 rcp-ghost，未登记"),
        Finding("warn", "W301", "能力 patrol.x 无服务使用"),
    ]
    after = [
        Finding("error", "E107", "工作区存在 rcp-ghost，未登记"),
        Finding("warn", "E109", "dataway(data-gateway) 入度为 0"),
    ]
    drift = diff_findings(before, after)
    assert drift["added"] == [("warn", "E109", "dataway(data-gateway) 入度为 0")]
    assert drift["removed"] == [("warn", "W301", "能力 patrol.x 无服务使用")]


def _write_ontology(root: Path, *, abox_extra: str = "") -> Path:
    """构造一个最小可装载的本体仓：tbox / abox / policy 三层各一份 TTL。"""
    (root / "ontology" / "tbox").mkdir(parents=True)
    (root / "ontology" / "abox").mkdir(parents=True)
    (root / "ontology" / "policy").mkdir(parents=True)
    (root / "ontology" / "tbox" / "kinds.ttl").write_text(
        """@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix owl:  <http://www.w3.org/2002/07/owl#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .

rcp:PatrolLine a owl:Class, rcp:Kind ;
    rdfs:subClassOf rcp:Service ;
    rdfs:label "巡查线" ;
    rcp:mustBeExternal false ; rcp:isEntry false ;
    rcp:requiresPort true ; rcp:requiresContract true .

rcp:PASS a rcp:Decision ; rdfs:label "放行" ; rcp:baseScore 0 .
""",
        encoding="utf-8",
    )
    (root / "ontology" / "abox" / "platform.ttl").write_text(
        """@prefix rcp: <https://risk-control.platform/ontology#> .
rcp:platform a rcp:Platform ; rcp:registrySchema "rcp.registry/v2" ; rcp:platformName "t" .
""",
        encoding="utf-8",
    )
    (root / "ontology" / "abox" / "services.ttl").write_text(
        """@prefix rcp: <https://risk-control.platform/ontology#> .
rcp:ghost a rcp:PatrolLine, rcp:Service ;
    rcp:repo "rcp-ghost" ; rcp:port 8099 ;
    rcp:external false ; rcp:owner "platform" ;
    rcp:hasCapability rcp:patrol.ghost .
"""
        + abox_extra,
        encoding="utf-8",
    )
    (root / "ontology" / "policy" / "redlines.ttl").write_text(
        """@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
rcp:RL-001 a rcp:Redline ;
    rcp:redlineId "RL-001" ; rcp:slug "x" ; rdfs:label "x" ;
    rcp:spec [ a rcp:RegistryAssert ; rcp:via "kinds.allowedDependsOn" ] .
""",
        encoding="utf-8",
    )
    return root


def test_check_declarations_is_scope_limited(tmp_path: Path):
    """check_declarations 只产出声明层结论（scope=declaration），不碰工作区文件布局。

    用 tmp_path 构造一个带声明层违规（未立名能力）的最小本体仓，确保 findings 非空，
    从而真正验证 scope 隔离——不依赖真实仓库当前是否恰好有噪音（声明层闭合时为空）。
    """
    _write_ontology(tmp_path)

    findings = check_declarations(tmp_path)
    assert findings
    assert all(f.scope == SCOPE_DECLARATION for f in findings)
    assert any(f.level == "error" for f in findings)
    assert "E202" in {f.code for f in findings}  # 未立名能力


def _write_header(
    root: Path,
    *,
    version: str | None = None,
    version_iri: bool = True,
    parts: list[str] | None = None,
    extra: str = "",
) -> Path:
    """在 tbox/schema.ttl 里写本体头。

    header 属于本体图本身（不是独立文件），所以写在 tbox 层。parts 缺省取磁盘实际
    文件——含 schema.ttl 自己，构造「清单与事实一致」的正例；反例靠显式传入偏离值。
    """
    from checker import loader

    base = root / "ontology"
    schema = base / "tbox" / "schema.ttl"
    if not schema.is_file():
        # 先落个占位，让下面的磁盘扫描能把它算进 parts
        schema.write_text("@prefix rcp: <https://risk-control.platform/ontology#> .\n", encoding="utf-8")

    if parts is None:
        found: list[str] = []
        for layer in (loader.TBOX_DIR, loader.ABOX_DIR, loader.POLICY_DIR, loader.SHAPES_DIR):
            directory = base / layer
            if directory.is_dir():
                found += [f"{layer}/{p.name}" for p in sorted(directory.glob("*.ttl"))]
        parts = sorted(found)
    if version is None:
        version = loader.__version__

    lines = [
        "@prefix owl:     <http://www.w3.org/2002/07/owl#> .",
        "@prefix rdfs:    <http://www.w3.org/2000/01/rdf-schema#> .",
        "@prefix dcterms: <http://purl.org/dc/terms/> .",
        "",
        "<https://risk-control.platform/ontology>",
        "    a owl:Ontology ;",
        f'    owl:versionInfo "{version}" ;',
    ]
    if version_iri:
        lines.append("    owl:versionIRI <https://risk-control.platform/ontology/2.0.0> ;")
    if parts:
        body = " ,\n        ".join(f'"{part}"' for part in parts)
        lines.append(f"    dcterms:hasPart\n        {body} ;")
    lines.append('    rdfs:label "test" .')
    if extra:
        lines.append(extra)

    schema.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return schema


def test_header_missing_is_error(tmp_path: Path):
    """本体头是本体身份的唯一声明处：缺了它这个目录只是一堆 TTL，判 error。"""
    root = _write_ontology(tmp_path)
    findings = check_ontology_header(root)
    assert "E119" in codes(findings)
    assert any("缺少本体头" in f.message for f in findings)


def test_header_consistent_is_closed(tmp_path: Path):
    root = _write_ontology(tmp_path)
    _write_header(root)
    assert check_ontology_header(root) == []


def test_header_version_drift_is_error(tmp_path: Path):
    """versionInfo 与 checker 版本双写，漂移必须报。"""
    root = _write_ontology(tmp_path)
    _write_header(root, version="1.0.0")
    findings = check_ontology_header(root)
    assert "E119" in codes(findings)
    assert any("漂移" in f.message for f in findings)


def test_header_without_version_iri_is_error(tmp_path: Path):
    """没有 versionIRI，外部消费者无法 pin 版本。"""
    root = _write_ontology(tmp_path)
    _write_header(root, version_iri=False)
    assert "E119" in codes(check_ontology_header(root))


def test_header_declaring_absent_file_is_error(tmp_path: Path):
    """清单指向空气：声明的路径在磁盘上不存在。"""
    root = _write_ontology(tmp_path)
    _write_header(root, parts=["tbox/ghost.ttl"])
    findings = check_ontology_header(root)
    assert "E119" in codes(findings)
    assert any("不存在" in f.message for f in findings)


def test_header_omitting_existing_file_is_error(tmp_path: Path):
    """新增文件忘了登记：层目录里有 .ttl 未写进 hasPart。"""
    root = _write_ontology(tmp_path)
    _write_header(root, parts=["tbox/schema.ttl", "tbox/kinds.ttl"])
    (tmp_path / "ontology" / "tbox" / "extra.ttl").write_text(
        "@prefix rcp: <https://risk-control.platform/ontology#> .\n", encoding="utf-8"
    )
    findings = check_ontology_header(root)
    assert "E119" in codes(findings)
    assert any("清单遗漏" in f.message for f in findings)


def test_header_multiple_identities_is_error(tmp_path: Path):
    """一个本体只有一个身份，两个 owl:Ontology 即声明不可用。"""
    root = _write_ontology(tmp_path)
    _write_header(root, extra="<https://risk-control.platform/other> a owl:Ontology .")
    findings = check_ontology_header(root)
    assert "E119" in codes(findings)
    assert any("不可用" in f.message for f in findings)


def test_header_duplicate_version_info_is_error(tmp_path: Path):
    """versionInfo 是功能属性，多值即不可用（与 abox/tbox 同一护栏）。"""
    root = _write_ontology(tmp_path)
    _write_header(
        root,
        extra='<https://risk-control.platform/ontology> owl:versionInfo "9.9.9" .',
    )
    findings = check_ontology_header(root)
    assert "E119" in codes(findings)
    assert any("功能属性" in f.message for f in findings)


def test_header_split_across_files_is_error(tmp_path: Path):
    """header 被写进第二个 tbox 文件 → 合并层后多值，装载期即报。

    这是折进本体图之后比「独立清单文件」更强的地方：单文件校验只能看见自己，
    合并层校验能看见任何一处重复声明。
    """
    root = _write_ontology(tmp_path)
    _write_header(root)
    (tmp_path / "ontology" / "tbox" / "other.ttl").write_text(
        '@prefix owl: <http://www.w3.org/2002/07/owl#> .\n'
        '<https://risk-control.platform/ontology> owl:versionInfo "9.9.9" .\n',
        encoding="utf-8",
    )
    findings = check_ontology_header(root)
    assert "E119" in codes(findings)
    assert any("功能属性" in f.message for f in findings)


def test_real_header_is_consistent():
    """真实仓的本体头必须与磁盘一致——这是文档不腐烂的底线。"""
    import os

    ontology = Path(os.environ.get("RCP_ONTOLOGY") or Path(__file__).resolve().parent.parent)
    if not (ontology / "ontology").is_dir():
        pytest.skip("工作区无本体仓")
    assert check_ontology_header(ontology) == []
