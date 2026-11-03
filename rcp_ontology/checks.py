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
from collections import Counter
from dataclasses import replace
from datetime import date
from pathlib import Path
from typing import Any

from . import graph as G
from .layout import is_worktree, run_declared_scans
from .loader import (
    SCOPE_WORKSPACE,
    Finding,
    load_concepts,
    load_decision_schema,
    load_redlines,
    load_registry,
    read_yaml,
)
from .relations import (
    declared_names,
    iter_edges,
    kind_class,
    load_relations,
    reachability_graphs,
)

REQUIRED_SERVICE_FIELDS = ("name", "repo", "kind", "external", "owner", "capabilities")

# 规则规格（policy-as-code）已知的执行器类型与必填字段。
# 每条红线的 spec.type 决定执行器，缺必填字段即 E302；无 spec 即 E301（纸面红线）。
# 新增一条已支持类型的红线只需在 redlines.yaml 写 spec，无需改本文件或登记实现清单。
RULE_SPEC_TYPES: dict[str, dict[str, tuple[str, ...]]] = {
    "registry-assert": {"required": ("via",)},
    "cross-source": {"required": ("sources", "assert")},
    "file-scan": {"required": ("include", "match")},
    "registry-scan": {"required": ("include", "extract", "deny_values", "allow_kinds")},
    "upstream-scan": {"required": ("include", "scan_prefix", "match", "internal_hosts")},
}

# 服务 expected 预期状态声明的合法字段。expected 用于区分"有意无下游"与
# "漏登记依赖方"（E109/E110 是启发式，分不清二者），声明真值标志必须配审计三要素。
EXPECTED_KEYS = ("no_dependents", "unreachable", "reason", "owner", "review_by")


def _kind_map(concepts: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    return {k["name"]: k for k in concepts["kinds"]}


def _load_relations_or_none(ontology_dir: Path) -> dict[str, Any] | None:
    """读关系层真源；缺文件返回 None，由 check_relations 输出 S002 明示未执行。"""
    try:
        return load_relations(ontology_dir)
    except Exception:  # noqa: BLE001 - 声明不可用时降级为"未执行"，不伪装通过
        return None


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


def check_registry_shape(registry: dict[str, Any]) -> list[Finding]:
    """E001 必填字段（键存在性）/ E002 重名、repo 重复、端口冲突。

    port 是否必填已由 SHACL（requires_port 动态 shape）承担；这里只查「键是否存在」——
    这是 SHACL 表达不了的信息（capabilities 空列表合法、键缺失与值为空在图里无法区分）。
    """
    findings: list[Finding] = []
    names: set[str] = set()
    repos: dict[str, str] = {}
    ports: dict[int, str] = {}
    for service in registry.get("services", []):
        name = service.get("name", "<未命名>")
        required = list(REQUIRED_SERVICE_FIELDS)
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


def check_decision_alignment(
    contracts_root: Path,
    concepts: dict[str, list[dict[str, Any]]],
    spec: dict[str, Any] | None = None,
) -> list[Finding]:
    """RL-003 决策枚举在契约层与本体层逐字一致，且分值一致。

    字段名（enum / x-base-score / base_score / code）从 redlines.yaml 的 RL-003
    spec 读取；缺省退回既有字段名（兼容直接调用）。
    """
    spec = spec or {}
    sources = spec.get("sources") or []
    enum_field = (sources[0].get("field") if sources else None) or "enum"
    code_key = (sources[1].get("key") if len(sources) > 1 else None) or "code"
    fields = spec.get("fields") or [{"a": "x-base-score", "b": "base_score"}]
    score_a = fields[0].get("a", "x-base-score")
    score_b = fields[0].get("b", "base_score")

    try:
        contract_enum = load_decision_schema(contracts_root, enum_field)
    except Exception as exc:  # noqa: BLE001 - 缺文件即红
        return [Finding("error", "RL-003", f"无法读取契约层决策枚举: {exc}")]

    concept_codes = [item.get(code_key) for item in concepts["decisions"]]
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

    scores = _load_contract_scores(contracts_root, score_a)
    if scores is not None:
        concept_scores = {i.get(code_key): i.get(score_b) for i in concepts["decisions"]}
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


def _load_contract_scores(contracts_root: Path, field: str = "x-base-score") -> dict[str, Any] | None:
    """读 decision.yaml 的分值字段（缺省 x-base-score）。没有该段就当未声明分值。"""
    path = contracts_root / "contracts" / "schemas" / "decision.yaml"
    try:
        data = read_yaml(path) or {}
    except Exception:  # noqa: BLE001
        return None
    scores = data.get(field)
    return scores if isinstance(scores, dict) else None


def check_contracts_exist(
    contracts_root: Path,
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]] | None = None,
) -> list[Finding]:
    """RL-006 契约文件必须存在于磁盘。

    「必须挂契约」（requires_contract 种类缺契约）已由 SHACL（requires_contract
    动态 shape）承担；这里只做 SHACL 做不了的「文件是否真的存在于磁盘」判定。
    """
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
        for rel in contracts:
            if not (contracts_root / rel).is_file():
                findings.append(Finding("error", "RL-006", f"{name} 的契约文件不存在: {rel}"))
    return findings


def check_rule_specs(redlines: dict[str, Any]) -> list[Finding]:
    """E301 纸面红线 / E302 spec 不合法。

    规则即数据后，"是否可执行"由 spec 决定：无 spec 即无执行器（E301 纸面红线）；
    spec.type 未知、缺必填字段、正则无法编译即 E302。新增红线只需给 spec，
    不再需要在本文件登记实现清单——实现清单已退化为 RULE_SPEC_TYPES 的执行器类型。
    """
    findings: list[Finding] = []
    for constraint in redlines.get("constraints", []):
        redline_id = constraint.get("id", "?")
        spec = constraint.get("spec")
        if not isinstance(spec, dict):
            findings.append(
                Finding(
                    "error",
                    "E301",
                    f"{redline_id} 在 redlines.yaml 声明，但无 spec 规格，"
                    f"检查器无法执行（纸面红线）",
                )
            )
            continue

        spec_type = spec.get("type")
        rule = RULE_SPEC_TYPES.get(spec_type)
        if rule is None:
            findings.append(
                Finding(
                    "error",
                    "E302",
                    f"{redline_id} 的 spec.type={spec_type!r} 不是已知类型；"
                    f"已知: {sorted(RULE_SPEC_TYPES)}",
                )
            )
            continue

        missing = [f for f in rule["required"] if f not in spec]
        if missing:
            findings.append(
                Finding(
                    "error",
                    "E302",
                    f"{redline_id}（{spec_type}）缺必填字段: {', '.join(missing)}",
                )
            )

        pattern = spec.get("match")
        if isinstance(pattern, str):
            try:
                re.compile(pattern)
            except re.error as exc:
                findings.append(
                    Finding(
                        "error",
                        "E302",
                        f"{redline_id} 的 match 正则无法编译: {exc}",
                    )
                )
    return findings


def check_capability_ownership(
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]],
) -> list[Finding]:
    """E111 能力归属悬空 / E112 归属与实现不符。

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
    return findings


def _expected_state(service: dict[str, Any]) -> dict[str, Any]:
    """取服务登记的 expected 预期状态声明（缺省空映射）。"""
    exp = service.get("expected")
    return exp if isinstance(exp, dict) else {}


def _expected_expired(expected: dict[str, Any], today: date) -> bool:
    """review_by 过期则声明失效（恢复告警）；无 review_by 或非法日期视为未过期。"""
    raw = expected.get("review_by")
    if not raw:
        return False
    try:
        return date.fromisoformat(str(raw)) < today
    except ValueError:
        return False


def check_expected_state(registry: dict[str, Any]) -> list[Finding]:
    """E115 预期状态声明（expected）形状不合法。

    expected 是服务对"当前图位置"的声明，用于区分有意无下游与漏登记依赖方。
    声明了任一真值标志（no_dependents/unreachable）就必须给出 reason/owner/review_by，
    否则等于把噪音藏起来而不留审计。只做机械判定，不判"声明是否合理"。
    """
    findings: list[Finding] = []
    for service in registry.get("services", []):
        name = service.get("name", "<未命名>")
        if "expected" not in service:
            continue
        expected = service.get("expected")
        if not isinstance(expected, dict):
            findings.append(Finding("error", "E115", f"{name} 的 expected 必须是映射"))
            continue
        unknown = [k for k in expected if k not in EXPECTED_KEYS]
        if unknown:
            findings.append(
                Finding("error", "E115", f"{name} 的 expected 含未知字段: {', '.join(unknown)}")
            )
        for flag in ("no_dependents", "unreachable"):
            if flag in expected and not isinstance(expected[flag], bool):
                findings.append(
                    Finding("error", "E115", f"{name} 的 expected.{flag} 必须是布尔值")
                )
        declares = bool(expected.get("no_dependents")) or bool(expected.get("unreachable"))
        if declares:
            for field in ("reason", "owner", "review_by"):
                if not expected.get(field):
                    findings.append(
                        Finding("error", "E115", f"{name} 声明了预期状态，缺 {field}")
                    )
            if expected.get("review_by"):
                try:
                    date.fromisoformat(str(expected["review_by"]))
                except ValueError:
                    findings.append(
                        Finding(
                            "error",
                            "E115",
                            f"{name} 的 expected.review_by 不是合法日期: {expected['review_by']!r}",
                        )
                    )
    return findings


def check_relations(
    registry: dict[str, Any],
    relations: dict[str, Any] | None,
    concepts: dict[str, list[dict[str, Any]]] | None = None,
) -> list[Finding]:
    """E116 边用了未声明的关系 / E117 端点种类越界 / E118 关系引用未声明的图。

    关系名与图名都是概念层的东西，只能由 relations.ttl 声明。登记里出现未声明的
    关系名意味着有人在"先上车后补票"——那条边既不会被分域，也不会被任何端点约束
    检查，等于静默绕过全部关系级判定。

    E105（目标未登记）在可达性图上已由 SHACL 的 dependsOn 路径承担；非可达性图只产出
    typed 边、没有 dependsOn 汇总边，故这里补判，避免"数据/治理边指向幽灵服务"漏网。
    E117（端点种类）需要取目标节点的 kind，属跨节点比对，SHACL 的 sh:class 能表达
    但无法区分"未登记"与"种类不符"，两类结论会重复报同一件事，故留在 Python 侧。
    """
    findings: list[Finding] = []
    if relations is None:
        findings.append(
            Finding(
                "info",
                "S002",
                "缺少 ontology/relations.ttl，关系级判定（E116/E117/E118）未执行",
            )
        )
        return findings

    declared = declared_names(relations)
    graphs = relations.get("graphs", {})
    reach = set(reachability_graphs(relations))

    for name, spec in sorted(relations.get("relations", {}).items()):
        graph_name = spec.get("graph")
        if not graph_name:
            findings.append(Finding("error", "E118", f"关系 {name} 未声明所属图"))
        elif graph_name not in graphs:
            findings.append(
                Finding("error", "E118", f"关系 {name} 引用了未声明的图: {graph_name}")
            )

    entities = {s.get("name"): s for s in registry.get("services", []) if s.get("name")}
    entities.update({l.get("name"): l for l in registry.get("libraries", []) if l.get("name")})

    unknown: dict[str, list[str]] = {}
    counts: Counter[str] = Counter()
    for source, rel, target in iter_edges(registry):
        counts[rel] += 1
        if rel not in declared:
            unknown.setdefault(rel, []).append(f"{source}→{target}")
            continue

        spec = relations["relations"][rel]
        in_reach = spec.get("graph") in reach
        # 只有把目标声明为服务的关系，才要求目标在 registry 里登记。表、契约、workload
        # 这些目标是词汇对象，不在 services/libraries 里，套用 E105 会全是误报。
        requires_registered = "Service" in (spec.get("target_kinds") or [])
        if target not in entities:
            if requires_registered and not in_reach:
                findings.append(
                    Finding(
                        "error",
                        "E105",
                        f"{source} 的 {rel} 指向未登记的目标: {target}",
                    )
                )
            continue

        allowed = spec.get("target_kinds") or []
        if allowed:
            # 库没有 kind：构建期依赖不是服务。rcp:Service 语义上只覆盖挂了 kind
            # 且非 meta 的已登记服务，否则"calls 指向库"会被误判为合法。
            target_kind = entities[target].get("kind")
            cls = kind_class(str(target_kind)) if target_kind else "Library"
            is_service = target_kind is not None and cls != "Meta"
            ok = cls in allowed or ("Service" in allowed and is_service)
            if not ok:
                findings.append(
                    Finding(
                        "error",
                        "E117",
                        f"{source} 的 {rel} 指向 {target}（kind={target_kind or '库'}），"
                        f"该关系只允许 {', '.join(allowed)}",
                    )
                )

    for rel, uses in sorted(unknown.items()):
        findings.append(
            Finding(
                "error",
                "E116",
                f"关系 {rel} 未在 ontology/relations.ttl 声明，出现在: {', '.join(uses)}",
            )
        )

    for name, spec in sorted(relations.get("relations", {}).items()):
        if spec.get("status") == "enforced" and counts.get(name, 0) == 0:
            findings.append(
                Finding(
                    "warn",
                    "W307",
                    f"关系 {name} 标记 enforced，但登记里没有任何实例，该判定当前空转",
                )
            )
    return findings


def check_dependency_graph(
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]],
    relations: dict[str, Any] | None = None,
) -> list[Finding]:
    """E108 成环（每张有边的图）/ E109 入度为 0 / E110 不可达（仅可达性图）。

    成环在每张图上都判——构建图的双向引用同样是错误。入度与可达性只判可达性图，
    因为这些判据回答的是"运行时还能不能到达"，部署与血缘图上问这个问题没有意义。
    """
    findings: list[Finding] = []
    graphs = G.build_graphs(registry, relations)
    kinds = _kind_map(concepts)

    for graph_name, adjacency in sorted(graphs.items()):
        if not any(adjacency.values()):
            continue
        for cycle in G.find_cycles(adjacency):
            findings.append(
                Finding(
                    "error",
                    "E108",
                    f"依赖成环({graph_name}): " + " → ".join(cycle + [cycle[0]]),
                )
            )

    reach = sorted(reachability_graphs(relations) & set(graphs)) if relations else []
    if reach:
        graph = {name: list(adj) for name, adj in graphs[reach[0]].items()}
        for extra in reach[1:]:
            for name, adj in graphs[extra].items():
                merged = graph.setdefault(name, [])
                merged.extend(t for t in adj if t not in merged)
    else:
        graph = G.build_graph(registry, relations, G.CALL_GRAPH)

    degrees = G.in_degrees(graph)
    services = {s.get("name"): s for s in registry.get("services", []) if s.get("name")}
    entries = [n for n, s in services.items() if bool(kinds.get(s.get("kind"), {}).get("is_entry"))]
    unreachable = G.unreachable_from(graph, entries)
    today = date.today()

    for name, service in sorted(services.items()):
        expected = _expected_state(service)
        degree = degrees.get(name, 0)
        kind = service.get("kind")
        is_entry = bool(kinds.get(kind, {}).get("is_entry"))

        # 声明与事实不符即过时（无论是否过期，过时声明都该移除）：W306。
        if expected.get("no_dependents") and degree > 0:
            findings.append(
                Finding(
                    "warn",
                    "W306",
                    f"{name} 声明 expected.no_dependents（预期无依赖），"
                    f"但已有 {degree} 个依赖方，请移除过时声明",
                )
            )
        if expected.get("unreachable") and name not in unreachable:
            findings.append(
                Finding(
                    "warn",
                    "W306",
                    f"{name} 声明 expected.unreachable（预期不可达），"
                    f"但已可从入口到达，请移除过时声明",
                )
            )

        # E109：非入口且入度为 0。命中"预期无下游"声明且未过期则静默，否则告警。
        if degree == 0 and not is_entry and not (
            expected.get("no_dependents") and not _expected_expired(expected, today)
        ):
            findings.append(
                Finding(
                    "warn",
                    "E109",
                    f"{name}({kind}) 入度为 0：没有登记服务依赖它。"
                    f"若是备用通道请在 registry 注明用途；若是新服务则漏登记依赖方",
                )
            )

        # E110：从任何入口都不可达。命中"预期不可达"声明且未过期则静默，否则告警。
        if name in unreachable and not (
            expected.get("unreachable") and not _expected_expired(expected, today)
        ):
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


def _spec_by_id(redlines: dict[str, Any], redline_id: str) -> dict[str, Any] | None:
    """取某条红线在 redlines.yaml 里声明的 spec（供跨源比对等专用执行器使用）。"""
    for constraint in redlines.get("constraints", []):
        if constraint.get("id") == redline_id:
            spec = constraint.get("spec")
            return spec if isinstance(spec, dict) else None
    return None


def check_shacl(
    registry: dict[str, Any],
    concepts: dict[str, list[dict[str, Any]]],
    relations: dict[str, Any] | None = None,
) -> list[Finding]:
    """用 SHACL（静态 + 动态 shapes）验证导出的 RDF 图，映射回 Finding。

    覆盖从 Python 迁移到声明式约束的检查：E105 依赖未登记、E106/RL-001 依赖
    白名单、RL-002 external 方向、E201 种类声明、E202 能力立名、E113 TBox 自洽、
    E114 命名、RL-006 挂契约、E117 关系端点越界。这些全部是「值/关系约束」，
    在 RDF 图上无损表达；键存在性、跨源比对、文件扫描等不在 SHACL 能力内，
    仍由本文件其它函数承担。
    """
    from rcp_ontology.semweb import build_rdf, validate_all

    shapes_path = Path(__file__).resolve().parent.parent / "ontology" / "constraints.ttl"
    graph = build_rdf(registry, concepts, relations)
    _, findings = validate_all(graph, shapes_path, concepts)
    return [
        Finding("error", f.code, f"{f.focus}: {f.message}" if f.focus else f.message)
        for f in findings
    ]


def check_declarations(
    contracts_root: Path,
    concepts_dir: Path | None = None,
) -> list[Finding]:
    """只跑声明层检查：登记/契约/红线/图/归属/SHACL，不碰工作区文件布局。

    contracts_root: 契约仓根；concepts_dir: TBox 目录（缺省本仓 concepts/）。
    这些检查只依赖声明文件，任何单仓环境都能复算，是架构熵基线对比的范围。

    两轨分工：
      - checks.py 保留：键存在性（E001）、唯一键（E002）、跨源比对（RL-003）、
        契约文件存在（RL-006）、能力归属（E111/E112）、expected 形状（E115）、
        图连通性（E108/E109/E110/W306）、红线元检查（E301/E302）。
      - SHACL 迁移：依赖登记（E105）、依赖白名单（E106/RL-001）、external 方向
        （RL-002）、种类/能力声明（E201/E202）、TBox 自洽（E113）、命名（E114）、
        挂契约（RL-006 的 minCount 部分）。
    """
    concepts_dir = concepts_dir or Path(__file__).resolve().parent.parent / "concepts"
    registry = load_registry(contracts_root)
    concepts = load_concepts(concepts_dir)
    redlines = load_redlines(contracts_root)
    relations = _load_relations_or_none(concepts_dir.parent / "ontology")

    findings: list[Finding] = []
    findings += check_rule_specs(redlines)
    findings += check_relations(registry, relations, concepts)
    findings += check_registry_shape(registry)
    findings += check_expected_state(registry)
    findings += check_decision_alignment(contracts_root, concepts, _spec_by_id(redlines, "RL-003"))
    findings += check_contracts_exist(contracts_root, registry, concepts)
    findings += check_capability_ownership(registry, concepts)
    findings += check_dependency_graph(registry, concepts, relations)
    findings += check_shacl(registry, concepts, relations)
    return findings


def finding_key(finding: Finding) -> tuple[str, str, str]:
    """Finding 的稳定标识，用于跨版本结论差集。"""
    return (finding.level, finding.code, finding.message)


def diff_findings(
    before: list[Finding],
    after: list[Finding],
) -> dict[str, list[tuple[str, str, str]]]:
    """两个 Finding 列表的结构化差集（架构熵）。

    返回 {"added": [...], "removed": [...]}，元素为 (level, code, message) 三元组，
    按字典序排序；重复结论按多重集计数（同一条结论新增两处 = 两次漂移）。
    """
    before_counts = Counter(finding_key(f) for f in before)
    after_counts = Counter(finding_key(f) for f in after)
    return {
        "added": sorted((after_counts - before_counts).elements()),
        "removed": sorted((before_counts - after_counts).elements()),
    }


def check_all(
    contracts_root: Path,
    concepts_dir: Path | None = None,
    workspace_root: Path | None = None,
) -> list[Finding]:
    """跑全部检查（声明层 + 工作区文件布局层）。

    contracts_root: 契约仓根；concepts_dir: TBox 目录（缺省本仓 concepts/）；
    workspace_root: 多仓工作区根（缺省取契约仓的父目录）。
    """
    concepts_dir = concepts_dir or Path(__file__).resolve().parent.parent / "concepts"
    workspace_root = workspace_root or contracts_root.parent
    registry = load_registry(contracts_root)

    findings = check_declarations(contracts_root, concepts_dir)

    complete = workspace_is_complete(workspace_root, registry)

    workspace_findings: list[Finding] = []
    workspace_findings += [
        replace(f, scope=SCOPE_WORKSPACE)
        for f in run_declared_scans(load_redlines(contracts_root), workspace_root, registry)
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
