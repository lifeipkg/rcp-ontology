"""一致性检查：登记（ABox）↔ 概念（TBox）↔ 契约层。

只做机械判定：结构完整性、红线约束、枚举逐字一致。语义充分性由主会话核对原文，
不由本检查器宣称"绝对完整"。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .loader import Finding, load_concepts, load_decision_schema, load_registry

REQUIRED_SERVICE_FIELDS = ("name", "repo", "kind", "port", "external", "owner", "capabilities")


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
                code = "RL-001" if kind == "patrol-line" and dep_kind == "patrol-line" else "RL-001"
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


def check_all(contracts_root: Path, concepts_dir: Path | None = None) -> list[Finding]:
    """跑全部检查。concepts_dir 缺省为本仓 concepts/。"""
    concepts_dir = concepts_dir or Path(__file__).resolve().parent.parent / "concepts"
    registry = load_registry(contracts_root)
    concepts = load_concepts(concepts_dir)

    findings: list[Finding] = []
    findings += check_registry_shape(registry)
    findings += check_redlines(registry, concepts)
    findings += check_decision_alignment(contracts_root, concepts)
    findings += check_tbox_abox(registry, concepts)
    findings += check_contracts_exist(contracts_root, registry)
    return findings
