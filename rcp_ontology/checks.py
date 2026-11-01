"""一致性检查：登记（ABox）↔ 概念（TBox）↔ 契约层 ↔ 仓布局 ↔ 依赖图。

只做机械判定：结构完整性、红线约束、枚举逐字一致、DDL 与 JDBC 的落位、上游地址
是否写死、图的连通性、能力归属。语义充分性由主会话核对原文，不由本检查器宣称
"绝对完整"。

编号约定：
- ``RL-00x``  对应 redlines.yaml 登记的红线
- ``E1xx``    登记与图结构的错误（含仓布局）
- ``E2xx``    概念层（TBox）与归属错误
- ``E3xx``    红线自身的元检查（声明但无实现）
- ``W3xx``    提示，不计入失败
- ``S0xx``    本次检查被跳过的说明，不计入失败

种类相关的判断一律从 TBox 属性取值（requires_port / requires_contract / is_entry），
不在代码里硬编码种类名。新增种类只需改 concepts/kinds.yaml。
"""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path
from typing import Any

from . import graph as G
from .layout import (
    check_ddl_location,
    check_hardcoded_upstream,
    check_jdbc_in_business,
    is_worktree,
)
from .loader import (
    SCOPE_WORKSPACE,
    Finding,
    load_concepts,
    load_decision_schema,
    load_redlines,
    load_registry,
    load_terms,
    read_yaml,
)

REQUIRED_SERVICE_FIELDS = ("name", "repo", "kind", "external", "owner", "capabilities")

# 能力命名：小写点分，至少两段（域.动作）。多人协作时这防"同概念两套叫法"。
CAPABILITY_NAME = re.compile(r"^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)+$")

# TBox 上必须显式声明的布尔属性。缺省推断会让人误判检查器行为，因此要求写全。
KIND_BOOL_PROPS = ("must_be_external", "is_entry", "requires_port", "requires_contract")

# 检查器有能力判定的红线编号。新增红线先在实现侧登记，再写进 redlines.yaml；
# 只写 YAML 不写实现会被 E301 判为纸面红线。
IMPLEMENTED_REDLINES = frozenset(
    {"RL-001", "RL-002", "RL-003", "RL-004", "RL-005", "RL-006", "RL-007"}
)


def _kind_map(concepts: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    return {k["name"]: k for k in concepts["kinds"]}


def _kind_prop(
    concepts: dict[str, list[dict[str, Any]]] | None,
    kind: str | None,
    prop: str,
    default: bool,
) -> bool:
    """读 TBox 上某个 kind 的布尔属性。concepts 缺省时退回 default（兼容旧调用）。"""
    if concepts is None:
        return default
    rule = _kind_map(concepts).get(kind or "")
    if rule is None:
        return default
    return bool(rule.get(prop, default))


def check_registry_shape(
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]] | None = None,
) -> list[Finding]:
    """E001 必填字段 / E002 重名、repo 重复、端口冲突。

    port 是否必填由种类属性 requires_port 决定（元仓不需要端口）。
    """
    findings: list[Finding] = []
    names: set[str] = set()
    repos: dict[str, str] = {}
    ports: dict[int, str] = {}
    for service in registry.get("services", []):
        name = service.get("name", "<未命名>")
        kind = service.get("kind")
        required = list(REQUIRED_SERVICE_FIELDS)
        if _kind_prop(concepts, kind, "requires_port", True):
            required.append("port")
        missing = [f for f in required if f not in service]
        if missing:
            findings.append(Finding("error", "E001", f"{name} 缺少必填字段: {', '.join(missing)}"))

        if name in names:
            findings.append(Finding("error", "E002", f"服务名重复: {name}"))
        names.add(name)

        repo = service.get("repo")
        if repo:
            if repo in repos:
                findings.append(
                    Finding("error", "E002", f"repo 被 {repos[repo]} 与 {name} 重复使用: {repo}")
                )
            repos[repo] = name

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
    kind_rule = _kind_map(concepts)

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


def check_decision_alignment(
    contracts_root: Path,
    concepts: dict[str, list[dict[str, Any]]],
) -> list[Finding]:
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

    scores = _load_contract_scores(contracts_root)
    if scores is not None:
        concept_scores = {i.get("code"): i.get("base_score") for i in concepts["decisions"]}
        mismatch = [
            f"{code}: 契约={score} 本体={concept_scores.get(code)}"
            for code, score in scores.items()
            if score != concept_scores.get(code)
        ]
        if mismatch:
            findings.append(
                Finding("error", "RL-003", "决策分值不一致 —— " + "；".join(mismatch))
            )
    return findings


def _load_contract_scores(contracts_root: Path) -> dict[str, Any] | None:
    """读 decision.yaml 的 x-base-score。没有该段就当未声明分值。"""
    path = contracts_root / "contracts" / "schemas" / "decision.yaml"
    try:
        data = read_yaml(path) or {}
    except Exception:  # noqa: BLE001
        return None
    scores = data.get("x-base-score")
    return scores if isinstance(scores, dict) else None


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


def check_contracts_exist(
    contracts_root: Path,
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]] | None = None,
) -> list[Finding]:
    """RL-006 提供服务必须挂契约；是否豁免由种类属性 requires_contract 决定。"""
    findings: list[Finding] = []
    for service in registry.get("services", []):
        name = service.get("name")
        contracts = service.get("contracts") or []
        if not _kind_prop(concepts, service.get("kind"), "requires_contract", True):
            if contracts:
                findings.append(
                    Finding("warn", "RL-006", f"{name}({service.get('kind')}) 不应挂后端契约")
                )
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
            findings.append(
                Finding(
                    "error",
                    "E301",
                    f"{redline_id} 在 redlines.yaml 声明，但检查器没有对应实现（纸面红线）",
                )
            )
    for redline_id in sorted(IMPLEMENTED_REDLINES - set(declared)):
        findings.append(
            Finding("warn", "W302", f"{redline_id} 有实现，但未在 redlines.yaml 登记")
        )
    return findings


def check_tbox_integrity(concepts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
    """E113 TBox 内部自洽：引用悬空的种类、缺显式布尔属性。

    TBox 是检查器行为的输入。它的属性写错（或漏写）会让所有下游判定静默退化，
    所以这里也要求 must_be_external / is_entry / requires_port / requires_contract
    四个属性显式写全，不靠默认值推断。
    """
    findings: list[Finding] = []
    kinds = {k["name"] for k in concepts["kinds"]}
    for kind in concepts["kinds"]:
        for ref in kind.get("allowed_depends_on_kinds") or []:
            if ref not in kinds:
                findings.append(
                    Finding(
                        "error",
                        "E113",
                        f"kind {kind['name']} 的 allowed_depends_on_kinds 引用了未声明种类: {ref}",
                    )
                )
        for prop in KIND_BOOL_PROPS:
            if not isinstance(kind.get(prop), bool):
                findings.append(
                    Finding(
                        "error",
                        "E113",
                        f"kind {kind['name']} 缺布尔属性 {prop}（决定检查器行为，必须显式声明）",
                    )
                )
    return findings


def check_capability_ownership(
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]],
) -> list[Finding]:
    """E111 能力归属悬空 / E112 归属与实现不符 / W304 多实现未声明。

    owner 是多人协作的责任锚点：改一个能力必须先知道找谁。归属写错等于没有归属。
    """
    findings: list[Finding] = []
    entities = {s.get("name"): s for s in registry.get("services", [])}
    entities.update({l.get("name"): l for l in registry.get("libraries", [])})

    implementers: dict[str, set[str]] = {}
    for name, entity in entities.items():
        for cap in entity.get("capabilities") or []:
            implementers.setdefault(cap, set()).add(name)

    for concept in concepts["capabilities"]:
        cap = concept.get("name")
        owner = concept.get("owner")
        if not owner:
            findings.append(Finding("error", "E111", f"能力 {cap} 未声明 owner"))
            continue
        if owner not in entities:
            findings.append(
                Finding("error", "E111", f"能力 {cap} 的 owner={owner} 未在 services/libraries 登记")
            )
            continue
        holders = implementers.get(cap, set())
        if owner not in holders:
            findings.append(
                Finding(
                    "error",
                    "E112",
                    f"能力 {cap} 声明 owner={owner}，但 {owner} 并未声明持有该能力；"
                    f"实际持有者: {sorted(holders) or '无'}",
                )
            )
        others = holders - {owner}
        if others:
            findings.append(
                Finding(
                    "warn",
                    "W304",
                    f"能力 {cap} 除 owner={owner} 外还由 {sorted(others)} 持有（多实现需在术语层注明）",
                )
            )
    return findings


def check_capability_names(concepts: dict[str, list[dict[str, Any]]]) -> list[Finding]:
    """E114 能力命名不符合点分小写规范。多人协作时命名分裂比缺命名更难治。"""
    findings: list[Finding] = []
    for concept in concepts["capabilities"]:
        name = concept.get("name") or ""
        if not CAPABILITY_NAME.match(name):
            findings.append(
                Finding(
                    "error",
                    "E114",
                    f"能力名 {name!r} 不符合点分小写规范（示例: patrol.content.dedup）",
                )
            )
    return findings


def check_term_coverage(
    concepts: dict[str, list[dict[str, Any]]],
    terms: list[dict[str, Any]],
) -> list[Finding]:
    """W303 种类未在词汇表立名。

    只校验 kinds —— 种类是平台骨架，数量少、变动慢，必须有中文名与定义；
    capability 数量多，改由 E114 的命名规范约束。
    """
    findings: list[Finding] = []
    if not terms:
        findings.append(Finding("warn", "W303", "未找到 vocabulary/terms.yaml，种类未立名"))
        return findings
    covered: set[str] = set()
    for term in terms:
        covered.update(term.get("covers") or [])
    for kind in concepts["kinds"]:
        if kind["name"] not in covered:
            findings.append(
                Finding("warn", "W303", f"种类 {kind['name']} 未在 terms.yaml 立名（covers 缺失）")
            )
    return findings


def check_dependency_graph(
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]],
) -> list[Finding]:
    """E108 依赖成环 / E109 非入口节点无人依赖 / E110 入口不可达。"""
    findings: list[Finding] = []
    graph = G.build_graph(registry)
    kinds = _kind_map(concepts)

    for cycle in G.find_cycles(graph):
        findings.append(
            Finding("error", "E108", "依赖成环: " + " → ".join(cycle + [cycle[0]]))
        )

    degrees = G.in_degrees(graph)
    services = {s.get("name"): s for s in registry.get("services", []) if s.get("name")}
    for name, degree in sorted(degrees.items()):
        kind = services[name].get("kind")
        if degree == 0 and not bool(kinds.get(kind, {}).get("is_entry")):
            findings.append(
                Finding(
                    "warn",
                    "E109",
                    f"{name}({kind}) 入度为 0：没有登记服务依赖它。"
                    f"若是备用通道请在 registry 注明用途；若是新服务则漏登记依赖方",
                )
            )

    entries = [n for n, s in services.items() if bool(kinds.get(s.get("kind"), {}).get("is_entry"))]
    for name in sorted(G.unreachable_from(graph, entries)):
        findings.append(
            Finding(
                "warn",
                "E110",
                f"{name} 从任何对外入口均不可达（入口: {', '.join(sorted(entries)) or '无'}）",
            )
        )
    return findings


def workspace_is_complete(workspace_root: Path, registry: dict[str, Any]) -> bool:
    """判断这是不是一个"多仓同时检出"的工作区。

    判据机械：workspace 下存在 >= 2 个已登记 repo 的目录。单仓 CI 里契约仓被
    checkout 到 .deps/ 下，只会命中 1 个，因此不会被误判为完整。
    """
    return _count_repos(workspace_root, registry) >= 2


def _count_repos(workspace_root: Path, registry: dict[str, Any]) -> int:
    if not workspace_root.is_dir():
        return 0
    repos = {s.get("repo") for s in registry.get("services", [])}
    repos |= {l.get("repo") for l in registry.get("libraries", [])}
    return sum(
        1
        for p in workspace_root.iterdir()
        if p.is_dir() and p.name in repos and not is_worktree(p)
    )


def check_repo_registration(
    workspace_root: Path,
    registry: dict[str, Any],
    complete: bool,
) -> list[Finding]:
    """E107 目录存在但未登记 / 登记了但目录不存在（仅完整工作区判后者）。

    "目录存在但未登记"在任何环境下都成立：出现了承重仓却没有户头，等于绕过契约先行。
    "登记了但目录不存在"只在多仓检出时才有意义，单仓 CI 里必然全缺，不能报。
    """
    findings: list[Finding] = []
    if not workspace_root.is_dir():
        return findings

    repos = {s.get("repo") for s in registry.get("services", [])}
    repos |= {l.get("repo") for l in registry.get("libraries", [])}

    on_disk = {
        p.name
        for p in workspace_root.iterdir()
        if p.is_dir() and p.name.startswith("rcp-") and not is_worktree(p)
    }
    for name in sorted(on_disk - repos):
        findings.append(
            Finding(
                "error",
                "E107",
                f"工作区存在 {name}，但 registry/services.yaml 未登记该仓（先登记再开发）",
                SCOPE_WORKSPACE,
            )
        )
    if complete:
        for name in sorted(repos - on_disk):
            findings.append(
                Finding(
                    "error",
                    "E107",
                    f"registry 登记了 {name}，但工作区没有该目录（仓库改名或未检出）",
                    SCOPE_WORKSPACE,
                )
            )
    return findings


def check_all(
    contracts_root: Path,
    concepts_dir: Path | None = None,
    workspace_root: Path | None = None,
) -> list[Finding]:
    """跑全部检查。

    contracts_root: 契约仓根；concepts_dir: TBox 目录（缺省本仓 concepts/）；
    workspace_root: 多仓工作区根（缺省取契约仓的父目录）。
    """
    concepts_dir = concepts_dir or Path(__file__).resolve().parent.parent / "concepts"
    workspace_root = workspace_root or contracts_root.parent
    registry = load_registry(contracts_root)
    concepts = load_concepts(concepts_dir)
    redlines = load_redlines(contracts_root)
    terms = load_terms(contracts_root)

    complete = workspace_is_complete(workspace_root, registry)

    findings: list[Finding] = []
    findings += check_redline_coverage(redlines)
    findings += check_registry_shape(registry, concepts)
    findings += check_redlines(registry, concepts)
    findings += check_decision_alignment(contracts_root, concepts)
    findings += check_tbox_abox(registry, concepts)
    findings += check_contracts_exist(contracts_root, registry, concepts)
    findings += check_tbox_integrity(concepts)
    findings += check_capability_ownership(registry, concepts)
    findings += check_capability_names(concepts)
    findings += check_term_coverage(concepts, terms)
    findings += check_dependency_graph(registry, concepts)

    workspace_findings: list[Finding] = []
    workspace_findings += [
        replace(f, scope=SCOPE_WORKSPACE) for f in check_ddl_location(workspace_root)
    ]
    workspace_findings += [
        replace(f, scope=SCOPE_WORKSPACE)
        for f in check_jdbc_in_business(workspace_root, registry)
    ]
    workspace_findings += [
        replace(f, scope=SCOPE_WORKSPACE)
        for f in check_hardcoded_upstream(
            workspace_root, registry, redlines.get("exceptions", [])
        )
    ]
    workspace_findings += check_repo_registration(workspace_root, registry, complete)
    findings += workspace_findings

    if not complete:
        emitted = [f for f in workspace_findings if f.level in {"error", "warn"}]
        findings.append(
            Finding(
                "info",
                "S001",
                f"跨仓检查不完整：{workspace_root} 下只有 "
                f"{_count_repos(workspace_root, registry)} 个已登记仓，"
                f"依赖多仓的判定（RL-004/RL-005/RL-007、E107 的缺失方向）视为未执行；"
                f"本次仍产出 {len(emitted)} 条仓内可见结论",
                SCOPE_WORKSPACE,
            )
        )
    return findings
