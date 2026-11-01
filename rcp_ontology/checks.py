"""一致性检查：登记（ABox）↔ 概念（TBox）↔ 契约层 ↔ 仓布局。

只做机械判定：结构完整性、红线约束、枚举逐字一致、DDL 与 JDBC 的落位、上游地址
是否写死。语义充分性由主会话核对原文，不由本检查器宣称"绝对完整"。

编号约定：
- ``RL-00x`` 对应 redlines.yaml 登记的红线
- ``E1xx``/``E2xx`` 登记、概念、契约层的结构错误
- ``E3xx`` 红线自身的元检查（声明但无实现）
- ``W3xx`` 提示，不计入失败
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .layout import (
    check_ddl_location,
    check_hardcoded_upstream,
    check_jdbc_in_business,
)
from .loader import (
    Finding,
    load_concepts,
    load_decision_schema,
    load_redlines,
    load_registry,
)

REQUIRED_SERVICE_FIELDS = ("name", "repo", "kind", "port", "external", "owner", "capabilities")

# 检查器有能力判定的红线编号。新增红线先在实现侧登记，再写进 redlines.yaml；
# 只写 YAML 不写实现会被 E301 判为纸面红线。
IMPLEMENTED_REDLINES = frozenset(
    {"RL-001", "RL-002", "RL-003", "RL-004", "RL-005", "RL-006", "RL-007"}
)


def check_registry_shape(registry: dict[str, Any]) -> list[Finding]:
    """E001 必填字段 / E002 重名与端口冲突。"""
    findings: list[Finding] = []
    names: set[str] = set()
    ports: dict[int, str] = {}
    for service in registry.get("services", []):
        name = service.get("name", "<未命名>")
        missing = [f for f in REQUIRED_SERVICE_FIELDS if f not in service]
        if missing:
            findings.append(Finding("error", "E001", f"{name} 缺少必填字段: {', '.join(missing)}"))
        if name in names:
            findings.append(Finding("error", "E002", f"服务名重复: {name}"))
        names.add(name)
        port = service.get("port")
        if isinstance(port, int):
            if port in ports:
                findings.append(
                    Finding("error", "E002", f"端口 {port} 被 {ports[port]} 与 {name} 同时占用")
                )
            ports[port] = name
    return findings


def check_redlines(registry: dict[str, Any], concepts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
    """RL-001 / RL-002 与种类级依赖约束。"""
    findings: list[Finding] = []
    services = {s.get("name"): s for s in registry.get("services", [])}
    kind_rule = {k["name"]: k for k in concepts["kinds"]}

    for name, service in services.items():
        kind = service.get("kind")
        rule = kind_rule.get(kind)
        if rule is None:
            continue
        depends_on = service.get("depends_on") or []
        allowed = set(rule.get("allowed_depends_on_kinds") or [])
        for dep in depends_on:
            dep_service = services.get(dep)
            if dep_service is None:
                findings.append(
                    Finding("error", "E105", f"{name} 依赖未登记的服务: {dep}")
                )
                continue
            dep_kind = dep_service.get("kind")
            if dep_kind not in allowed:
                # RL-001 专指巡查线互调；其他种类违规归内置编号 E106，避免编号失去定位意义。
                code = "RL-001" if kind == "patrol-line" and dep_kind == "patrol-line" else "E106"
                findings.append(
                    Finding(
                        "error",
                        code,
                        f"{name}({kind}) 不允许依赖 {dep}({dep_kind})；"
                        f"允许的依赖种类: {sorted(allowed) or '无'}",
                    )
                )

        external = bool(service.get("external"))
        must_external = bool(rule.get("must_be_external"))
        if must_external and not external:
            findings.append(
                Finding("error", "RL-002", f"{name}({kind}) 必须 external=true，当前为 false")
            )
        if external and not must_external:
            findings.append(
                Finding("error", "RL-002", f"{name}({kind}) 不得对外暴露，当前 external=true")
            )
    return findings


def check_decision_alignment(contracts_root: Path, concepts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
    """RL-003 决策枚举在契约层与本体层逐字一致，且分值一致。"""
    try:
        contract_enum = load_decision_schema(contracts_root)
    except Exception as exc:  # noqa: BLE001 - 缺文件即红
        return [Finding("error", "RL-003", f"无法读取契约层决策枚举: {exc}")]

    concept_codes = [item.get("code") for item in concepts["decisions"]]
    findings: list[Finding] = []
    if contract_enum != concept_codes:
        findings.append(
            Finding(
                "error",
                "RL-003",
                f"决策枚举不一致：契约={contract_enum} 本体={concept_codes}",
            )
        )
    return findings


def check_tbox_abox(registry: dict[str, Any], concepts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
    """E201 种类未声明 / E202 能力未声明 / W301 能力声明但无人使用。"""
    findings: list[Finding] = []
    kinds = {k["name"] for k in concepts["kinds"]}
    caps = {c["name"] for c in concepts["capabilities"]}
    used_caps: set[str] = set()

    for service in registry.get("services", []):
        name = service.get("name")
        if service.get("kind") not in kinds:
            findings.append(Finding("error", "E201", f"{name} 的 kind={service.get('kind')} 未在 TBox 声明"))
        for cap in service.get("capabilities") or []:
            used_caps.add(cap)
            if cap not in caps:
                findings.append(Finding("error", "E202", f"{name} 使用未立名的能力: {cap}"))

    for library in registry.get("libraries", []):
        for cap in library.get("capabilities") or []:
            used_caps.add(cap)
            if cap not in caps:
                findings.append(Finding("error", "E202", f"{library.get('name')} 使用未立名的能力: {cap}"))

    for cap in sorted(caps - used_caps):
        findings.append(Finding("warn", "W301", f"能力 {cap} 已立名但无服务使用"))
    return findings


def check_contracts_exist(contracts_root: Path, registry: dict[str, Any]) -> list[Finding]:
    """RL-006 每个服务必须挂契约（前端除外），且契约文件真实存在。"""
    findings: list[Finding] = []
    for service in registry.get("services", []):
        name = service.get("name")
        contracts = service.get("contracts") or []
        if service.get("kind") == "frontend":
            if contracts:
                findings.append(Finding("warn", "RL-006", f"前端 {name} 不应挂后端契约"))
            continue
        if not contracts:
            findings.append(Finding("error", "RL-006", f"{name} 未挂契约"))
            continue
        for rel in contracts:
            if not (contracts_root / rel).is_file():
                findings.append(Finding("error", "RL-006", f"{name} 的契约文件不存在: {rel}"))
    return findings


def check_redline_coverage(redlines: dict[str, Any]) -> list[Finding]:
    """E301 声明了但检查器没有实现（纸面红线）/ W302 有实现但未登记。

    这是防"红线只写在 YAML 里、CI 根本判不了"的元检查。新增红线必须先在本文件的
    IMPLEMENTED_REDLINES 登记实现，再写进 redlines.yaml，否则本检查即红。
    """
    findings: list[Finding] = []
    declared = [c.get("id") for c in redlines.get("constraints", [])]
    for redline_id in declared:
        if redline_id not in IMPLEMENTED_REDLINES:
            finding = Finding(
                "error",
                "E301",
                f"{redline_id} 在 redlines.yaml 声明，但检查器没有对应实现（纸面红线）",
            )
            findings.append(finding)
    for redline_id in sorted(IMPLEMENTED_REDLINES - set(declared)):
        findings.append(
            Finding("warn", "W302", f"{redline_id} 有实现，但未在 redlines.yaml 登记")
        )
    return findings


def check_all(
    contracts_root: Path,
    concepts_dir: Path | None = None,
    workspace_root: Path | None = None,
) -> list[Finding]:
    """跑全部检查。

    contracts_root: 契约仓根；concepts_dir: TBox 目录（缺省本仓 concepts/）；
    workspace_root: 多仓工作区根（缺省取契约仓的父目录，用于仓布局级红线）。
    """
    concepts_dir = concepts_dir or Path(__file__).resolve().parent.parent / "concepts"
    workspace_root = workspace_root or contracts_root.parent
    registry = load_registry(contracts_root)
    concepts = load_concepts(concepts_dir)
    redlines = load_redlines(contracts_root)

    findings: list[Finding] = []
    findings += check_redline_coverage(redlines)
    findings += check_registry_shape(registry)
    findings += check_redlines(registry, concepts)
    findings += check_decision_alignment(contracts_root, concepts)
    findings += check_tbox_abox(registry, concepts)
    findings += check_contracts_exist(contracts_root, registry)
    findings += check_ddl_location(workspace_root)
    findings += check_jdbc_in_business(workspace_root, registry)
    findings += check_hardcoded_upstream(workspace_root, registry, redlines.get("exceptions", []))
    return findings
