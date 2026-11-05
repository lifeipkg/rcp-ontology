"""本体检查器 CLI。

真源是本仓 ``ontology/`` 下的 TTL，因此 ``--ontology`` 是主参数（缺省即本仓）。
契约仓只提供 OpenAPI 与生成物，用 ``--contracts`` 定位，且只有 check/render-schema 需要。

用法：
    # 一致性检查（-w 指多仓工作区根；不给则跨仓判定输出 S001 明示跳过）
    python rcp_ontology/cli.py check --contracts ../rcp-contracts -w .. [--json]
    python rcp_ontology/cli.py check --contracts ../rcp-contracts -w .. --baseline origin/main

    # 因改声明而受影响的服务
    python rcp_ontology/cli.py impact --service dataway [--graph data]
    python rcp_ontology/cli.py relations
    python rcp_ontology/cli.py owners --org your-org --out .github/CODEOWNERS
    python rcp_ontology/cli.py render --out SERVICES.md

    # 语义网层（RDF / OWL / SHACL / SPARQL）
    python rcp_ontology/cli.py export --out /tmp/services.ttl
    python rcp_ontology/cli.py shacl
    python rcp_ontology/cli.py sparql --service dataway

    # 派生：由 tbox/decisions.ttl 生成 contracts/schemas/decision.yaml（勿手改生成物）
    python rcp_ontology/cli.py render-schema --contracts ../rcp-contracts --out ../rcp-contracts/contracts/schemas/decision.yaml
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rcp_ontology import graph as G  # noqa: E402
from rcp_ontology.checks import check_all, check_declarations, diff_findings  # noqa: E402
from rcp_ontology.loader import (  # noqa: E402
    SCOPE_DECLARATION,
    SCOPE_WORKSPACE,
    Finding,
    LoadError,
    load_concepts,
    load_registry,
    load_relations,
)
from rcp_ontology.relations import iter_edges, service_relations  # noqa: E402

LEVEL_ORDER = {"error": 0, "warn": 1, "info": 2}

# 本体仓根：cli.py 位于 <repo>/rcp_ontology/cli.py，向上两级即仓根。
ONTOLOGY_ROOT = Path(__file__).resolve().parent.parent


def _fmt(finding) -> str:
    tag = "[跨仓] " if finding.scope == SCOPE_WORKSPACE else ""
    return f"[{finding.level.upper():5}] {tag}{finding.code}: {finding.message}"


def _ontology_root(args: argparse.Namespace) -> Path:
    """本体仓根：--ontology 给出则用它，否则用本仓。"""
    raw = getattr(args, "ontology", None)
    return Path(raw).resolve() if raw else ONTOLOGY_ROOT


def _contracts_root(args: argparse.Namespace) -> Path | None:
    raw = getattr(args, "contracts", None)
    return Path(raw).resolve() if raw else None


def _load_declarations(args: argparse.Namespace):
    """读三层真源：ABox（登记）、TBox（概念）、关系与公理。

    全部来自本仓 ontology/ 目录下的 TTL —— 没有 YAML，也没有第二处真源。

    关系层不可用不致命：返回 None，由检查器输出 S002 明示"关系级判定未执行"，
    而不是让命令直接失败——这与「不可判就明说跳过」的约定一致。
    """
    root = _ontology_root(args)
    registry = load_registry(root)
    concepts = load_concepts(root)
    try:
        relations = load_relations(root)
    except LoadError as exc:
        print(f"[rcp-ontology] 关系层不可用，关系级判定跳过: {exc}", file=sys.stderr)
        relations = None
    return registry, concepts, relations, root


def _extract_repo_at(repo: Path, ref: str) -> Path:
    """把 git 仓 repo 在 ref 处的快照解到临时目录，返回该目录（用于基线/历史规则）。"""
    tmpdir = Path(tempfile.mkdtemp(prefix="rcp-ontology-snapshot-"))
    archive = tmpdir / "snapshot.tar"
    result = subprocess.run(
        ["git", "-C", str(repo), "archive", "--output", str(archive), ref],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise RuntimeError(f"基线 {ref} 不可读: {result.stderr.strip()}")
    with tarfile.open(archive) as tf:
        # filter="data"：只解普通文件与目录，忽略/清洗元数据（Python 3.12+ 防解包攻击）。
        try:
            tf.extractall(tmpdir, filter="data")
        except TypeError:  # Python < 3.12 无 filter 参数
            tf.extractall(tmpdir)
    archive.unlink()
    return tmpdir


def _run_historical_check(checker_dir: Path, ontology_dir: Path) -> list[Finding]:
    """用 checker_dir 里的历史检查器跑 ontology_dir，返回其声明层结论。

    历史检查器作为独立进程运行（subprocess），完全隔离当前代码与历史代码，
    避免模块缓存/依赖串扰。退出码 0（闭合）与 1（有 error）都算成功产出结论。
    """
    cli = checker_dir / "rcp_ontology" / "cli.py"
    result = subprocess.run(
        [sys.executable, str(cli), "check", "--ontology", str(ontology_dir), "--json"],
        capture_output=True,
        text=True,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"历史检查器（{checker_dir.name}）运行失败: {result.stderr.strip() or '未知错误'}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"历史检查器输出不可解析: {exc}") from exc
    findings: list[Finding] = []
    for entry in payload.get("errors", []) + payload.get("warnings", []):
        findings.append(
            Finding(
                entry.get("level", "error"),
                entry.get("code", "?"),
                entry.get("message", ""),
                entry.get("scope", SCOPE_DECLARATION),
            )
        )
    return findings


def _decl_entropy(findings: list) -> list:
    """架构熵只比声明层、可判定的 error/warn；跨仓结论与跳过说明不参与漂移。"""
    return [
        f
        for f in findings
        if f.scope == SCOPE_DECLARATION and f.level in {"error", "warn"}
    ]


def _fmt_drift_line(tag: str, entry: tuple[str, str, str]) -> str:
    level, code, message = entry
    return f"  [{tag}][{level.upper():5}] {code}: {message}"


def cmd_check(args: argparse.Namespace) -> int:
    ontology = _ontology_root(args)
    contracts = _contracts_root(args)
    workspace = Path(args.workspace).resolve() if args.workspace else ontology.parent

    # 先解析基线快照（若给），失败即输入错误，不产出半截结论。
    # 基线的对象是**本体仓**：真源搬了家，历史声明在 git 里也跟着搬。
    baseline_dir: Path | None = None
    checker_dir: Path | None = None
    if args.baseline:
        try:
            baseline_dir = _extract_repo_at(ontology, args.baseline)
            if args.checker_ref:
                checker_dir = _extract_repo_at(ONTOLOGY_ROOT, args.checker_ref)
        except RuntimeError as exc:
            if baseline_dir:
                shutil.rmtree(baseline_dir, ignore_errors=True)
            if checker_dir:
                shutil.rmtree(checker_dir, ignore_errors=True)
            print(f"[rcp-ontology] {exc}", file=sys.stderr)
            return 2

    try:
        findings = check_all(ontology, contracts, workspace)
    except LoadError as exc:
        if baseline_dir:
            shutil.rmtree(baseline_dir, ignore_errors=True)
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    findings.sort(key=lambda f: (LEVEL_ORDER.get(f.level, 9), f.code))
    errors = [f for f in findings if f.level == "error"]
    warns = [f for f in findings if f.level == "warn"]
    infos = [f for f in findings if f.level == "info"]

    # 架构熵漂移（--baseline）：基线声明层结论 vs 当前声明层结论的差集。
    # 缺省用当前规则衡量基线（单一规则视角）；给 --checker-ref 则用该版本历史规则
    # 衡量基线，把"数据变化"与"规则变化"解耦——这是"历史检查器看历史数据"。
    drift = None
    if baseline_dir is not None:
        try:
            if checker_dir is not None:
                baseline_findings = _run_historical_check(checker_dir, baseline_dir)
            else:
                baseline_findings = check_declarations(baseline_dir, contracts, workspace)
            drift = diff_findings(
                _decl_entropy(baseline_findings), _decl_entropy(findings)
            )
        except (LoadError, RuntimeError) as exc:
            print(
                f"[rcp-ontology] 基线声明不可用，跳过漂移对比: {exc}", file=sys.stderr
            )
        finally:
            shutil.rmtree(baseline_dir, ignore_errors=True)
            if checker_dir:
                shutil.rmtree(checker_dir, ignore_errors=True)

    if args.json:
        payload = {
            "ontology": str(ontology),
            "contracts": str(contracts) if contracts else None,
            "workspace": str(workspace),
            "errors": [f.as_dict() for f in errors],
            "warnings": [f.as_dict() for f in warns],
            "skipped": [f.as_dict() for f in infos],
            "closed": not errors,
        }
        if drift is not None:
            payload["drift"] = {
                "baseline": args.baseline,
                "checker": args.checker_ref,
                "scope": SCOPE_DECLARATION,
                "added_count": len(drift["added"]),
                "removed_count": len(drift["removed"]),
                "added": [
                    {"level": l, "code": c, "message": m} for l, c, m in drift["added"]
                ],
                "removed": [
                    {"level": l, "code": c, "message": m} for l, c, m in drift["removed"]
                ],
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for finding in findings:
            print(_fmt(finding))
        print(
            f"\n结论：{len(errors)} 个错误，{len(warns)} 个提示，"
            f"{len(infos)} 条跳过说明 —— {'闭合' if not errors else '未闭合'}"
        )
        if drift is not None:
            added, removed = drift["added"], drift["removed"]
            net = len(added) - len(removed)
            label = f"baseline: {args.baseline}"
            if args.checker_ref:
                label += f"，历史规则 {args.checker_ref}"
            print(f"\n架构熵基线对比（{label}，声明层 error/warn）：")
            print(
                f"  新增 +{len(added)} 条 / 消失 -{len(removed)} 条，"
                f"净漂移 {net:+d} 条"
            )
            for entry in added:
                print(_fmt_drift_line("新增", entry))
            for entry in removed:
                print(_fmt_drift_line("消失", entry))

    if errors:
        return 1
    if args.require_workspace:
        blocked = [f for f in infos if f.code in {"S001", "S003", "S004"}]
        if blocked:
            print(
                "[rcp-ontology] --require-workspace：存在未执行的跨仓/跨源判定，视为失败",
                file=sys.stderr,
            )
            return 2
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    root = _ontology_root(args)
    try:
        registry = load_registry(root)
        concepts = load_concepts(root)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    kind_zh = {k["name"]: k.get("zh", k["name"]) for k in concepts["kinds"]}
    cap_zh = {c["name"]: c.get("zh", c["name"]) for c in concepts["capabilities"]}
    stack = registry.get("baseline_stack") or {}
    stack_text = " / ".join(f"{k} {v}" for k, v in stack.items()) or "未声明"

    lines = ["# 平台服务目录（由 rcp-ontology 渲染，勿手改）", "",
             f"基座版本：{stack_text}", "",
             "## 服务", "",
             "| 服务 | 种类 | 端口 | 对外 | 能力 | 关系 |",
             "|---|---|---|---|---|---|"]
    for service in registry.get("services", []):
        caps = "、".join(cap_zh.get(c, c) for c in service.get("capabilities") or []) or "—"
        edges = [
            f"{rel}→{target}"
            for rel, targets in service_relations(service).items()
            for target in targets
        ]
        deps = "、".join(edges) or "—"
        port = service.get("port", "—")
        lines.append(
            f"| `{service.get('name')}` | {kind_zh.get(service.get('kind'), service.get('kind'))} "
            f"| {port} | {'是' if service.get('external') else '否'} | {caps} | {deps} |"
        )
    lines += ["", "## 库", "", "| 库 | 坐标 | 能力 |", "|---|---|---|"]
    for library in registry.get("libraries", []):
        caps = "、".join(cap_zh.get(c, c) for c in library.get("capabilities") or []) or "—"
        lines.append(f"| `{library.get('name')}` | `{library.get('artifact')}` | {caps} |")

    text = "\n".join(lines) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"已渲染: {args.out}")
    else:
        print(text)
    return 0


def cmd_impact(args: argparse.Namespace) -> int:
    """改一个服务之前，先看它会波及谁。--graph 选择在哪个域上算闭包。"""
    try:
        registry, _concepts, relations, _root = _load_declarations(args)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    graph = G.build_graph(registry, relations, args.graph)
    name = args.service
    if name not in graph:
        print(f"[rcp-ontology] 未登记的服务: {name}", file=sys.stderr)
        return 2

    services = {s.get("name"): s for s in registry.get("services", [])}
    downstream = G.dependents_of(graph, name)
    upstream = G.dependencies_of(graph, name)
    edges = {
        rel: targets
        for rel, targets in service_relations(services[name]).items()
        if relations is None or relations.get("relations", {}).get(rel, {}).get("graph") == args.graph
    }

    if args.json:
        print(json.dumps({
            "service": name,
            "kind": services[name].get("kind"),
            "owner": services[name].get("owner"),
            "graph": args.graph,
            "relations": edges,
            "depends_on": sorted(upstream),
            "depended_by": sorted(downstream),
            "impact_count": len(downstream),
        }, ensure_ascii=False, indent=2))
        return 0

    print(f"服务 {name}（kind={services[name].get('kind')}，owner={services[name].get('owner')}）")
    print(f"  作用域图     : {args.graph}")
    detail = "; ".join(f"{rel}→{', '.join(t)}" for rel, t in sorted(edges.items())) or "无"
    print(f"  出边明细     : {detail}")
    print(f"  间接依赖闭包 : {', '.join(sorted(upstream)) or '无'}")
    print(f"  被谁依赖     : {', '.join(sorted(downstream)) or '无'}")
    print(f"\n改它的契约会波及 {len(downstream)} 个服务"
          + (f"：{', '.join(sorted(downstream))}" if downstream else "（当前无人依赖）"))
    return 0


def cmd_relations(args: argparse.Namespace) -> int:
    """列出关系类型与所属图，以及登记里各关系的实例数。

    回答"我们到底建模了哪些关系、哪些还只是立了名没有实例"，避免把纸面声明当成
    已生效的判定。--json 供外部消费（例如生成架构文档）。
    """
    try:
        registry, _concepts, relations, _root = _load_declarations(args)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2
    if relations is None:
        print("[rcp-ontology] 关系层不可用，无法列出关系", file=sys.stderr)
        return 2

    counts: dict[str, int] = {}
    for _source, rel, _target in iter_edges(registry):
        counts[rel] = counts.get(rel, 0) + 1

    if args.json:
        print(json.dumps({
            "graphs": relations["graphs"],
            "relations": {
                name: {**spec, "instances": counts.get(name, 0)}
                for name, spec in sorted(relations["relations"].items())
            },
        }, ensure_ascii=False, indent=2))
        return 0

    print("图（标 * 参与可达性，环与不可达只在此类图上判）：")
    for name, spec in sorted(relations["graphs"].items()):
        mark = "*" if spec.get("reachability") else " "
        print(f"  {mark} {name:11} {spec.get('label', '')}")
    print("\n关系（status=enforced 参与判定，declared 仅立名）：")
    header = f"  {'关系':14} {'图':11} {'状态':9} {'实例':>4} 允许目标种类"
    print(header)
    for name, spec in sorted(relations["relations"].items()):
        allowed = ", ".join(spec.get("target_kinds") or []) or "—"
        print(f"  {name:14} {spec.get('graph', ''):11} {spec.get('status', ''):9} "
              f"{counts.get(name, 0):>4} {allowed}")
    return 0


def cmd_owners(args: argparse.Namespace) -> int:
    """按 abox 的 owner 生成 CODEOWNERS，让归属真正落到审批上。"""
    try:
        registry = load_registry(_ontology_root(args))
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    by_owner: dict[str, list[str]] = {}
    for service in registry.get("services", []):
        owner, repo = service.get("owner"), service.get("repo")
        if owner and repo:
            by_owner.setdefault(owner, []).append(repo)
    for library in registry.get("libraries", []):
        owner, repo = library.get("owner"), library.get("repo")
        if owner and repo:
            by_owner.setdefault(owner, []).append(repo)

    def handle(owner: str) -> str:
        return f"@{args.org}/{owner}" if args.org else f"@{owner}"

    lines = [
        "# 由 rcp-ontology owners 生成，勿手改 —— 真源是 rcp-ontology/ontology/abox/services.ttl",
        "# 每行 handle 必须是 GitHub 上真实存在的用户或团队 slug。",
        "",
    ]
    for owner in sorted(by_owner):
        lines.append(f"# {owner}")
        for repo in sorted(by_owner[owner]):
            lines.append(f"/{repo}/ {handle(owner)}")
        lines.append("")

    text = "\n".join(lines)
    if args.out:
        target = Path(args.out)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        total = sum(len(v) for v in by_owner.values())
        print(f"已生成: {args.out}（{len(by_owner)} 个 owner，{total} 个仓）")
    else:
        print(text)
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    """L1 导出：声明 → RDF/Turtle。真源仍是 YAML 事实 + TTL 关系公理，RDF 是图形态。"""
    try:
        registry, concepts, relations, _root = _load_declarations(args)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    from rcp_ontology.semweb import build_rdf

    graph = build_rdf(registry, concepts, relations)
    text = graph.serialize(format="turtle")
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"已导出 {len(graph)} 个三元组到: {args.out}")
    else:
        print(text)
    return 0


def cmd_shacl(args: argparse.Namespace) -> int:
    """L3 验证：对导出的 RDF 图跑 SHACL 约束（静态 + 动态 shapes）。"""
    try:
        registry, concepts, relations, _root = _load_declarations(args)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    from rcp_ontology.semweb import build_rdf, validate_all

    graph = build_rdf(registry, concepts, relations)
    shapes = _ontology_root(args) / "ontology" / "shapes" / "core.ttl"
    conforms, findings = validate_all(graph, shapes, concepts)

    if args.json:
        print(json.dumps({
            "conforms": conforms,
            "findings": [
                {"code": f.code, "focus": f.focus, "message": f.message}
                for f in findings
            ],
        }, ensure_ascii=False, indent=2))
    else:
        print(f"SHACL 约束验证（{shapes.name}）：{'合规' if conforms else '不合规'}")
        for f in findings:
            print(f"  - {f.code}: {f.focus}: {f.message}")
    return 0 if conforms else 1


def cmd_sparql(args: argparse.Namespace) -> int:
    """L4 查询：SPARQL 属性路径（dependsOn+）算依赖闭包，对照 impact 命令。"""
    try:
        registry, concepts, relations, _root = _load_declarations(args)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    from rcp_ontology.semweb import (
        build_rdf,
        sparql_dependencies_of,
        sparql_dependents_of,
    )

    graph = build_rdf(registry, concepts, relations)
    name = args.service
    upstream = sparql_dependencies_of(graph, name)
    downstream = sparql_dependents_of(graph, name)

    if args.json:
        print(json.dumps({
            "service": name,
            "depends_on": sorted(upstream),
            "depended_by": sorted(downstream),
        }, ensure_ascii=False, indent=2))
    else:
        print(f"服务 {name}（SPARQL 属性路径 dependsOn+）")
        print(f"  依赖闭包   : {', '.join(sorted(upstream)) or '无'}")
        print(f"  被依赖闭包 : {', '.join(sorted(downstream)) or '无'}")
    return 0


def cmd_render_schema(args: argparse.Namespace) -> int:
    """由 tbox/decisions.ttl 生成 contracts/schemas/decision.yaml。

    生成物不是真源：它是契约层（OpenAPI / 其它 schema）能 $ref 到的机器可读形态，
    真源始终是 decisions.ttl。手工拼串而不是 yaml.safe_dump，是为了让产物稳定可 diff
    —— 生成物的价值在于"改了真源才变"，任何额外波动都会掩盖真正的改动。
    """
    root = _ontology_root(args)
    contracts = _contracts_root(args)
    try:
        concepts = load_concepts(root)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    decisions = concepts.get("decisions") or []
    if not decisions:
        print("[rcp-ontology] decisions.ttl 里没有决策等级", file=sys.stderr)
        return 2

    lines = [
        "schema: rcp.contract.schema/v1",
        "name: Decision",
        "zh: 决策等级",
        "type: string",
        "# 生成物，勿手改：由 rcp-ontology 的 `cli.py render-schema` 从",
        "# rcp-ontology/ontology/tbox/decisions.ttl 产出。改真源后重跑命令。",
        "description: 处置等级枚举，唯一真源为 rcp-ontology/ontology/tbox/decisions.ttl。分值见 rcp:baseScore。",
        "enum:",
    ]
    lines += [f"  - {d['code']}" for d in decisions]
    lines.append("x-base-score:")
    lines += [f"  {d['code']}: {d['base_score']}" for d in decisions]
    text = "\n".join(lines) + "\n"

    target = Path(args.out) if args.out else None
    if target is None:
        if contracts is None:
            print("[rcp-ontology] 需要 --out 或 --contracts 才能确定输出路径", file=sys.stderr)
            return 2
        target = contracts / "contracts" / "schemas" / "decision.yaml"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    print(f"已生成: {target}（{len(decisions)} 个决策等级）")
    return 0


def _add_common(parser: argparse.ArgumentParser, *, contracts: bool = False) -> None:
    """给子命令挂共通参数：--ontology 是主入口，--contracts 只有需要契约文件时才挂。"""
    parser.add_argument(
        "--ontology",
        help="本体仓根或 ontology/ 目录，缺省即本仓（真源所在）",
    )
    if contracts:
        parser.add_argument(
            "--contracts",
            help="契约仓根目录：只用于定位 OpenAPI 与生成物，不给则相关判定输出 S004 跳过",
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rcp-ontology", description="风控平台本体检查器")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="登记/契约/红线/图 一致性检查")
    _add_common(check, contracts=True)
    check.add_argument(
        "-w", "--workspace",
        help="多仓工作区根，用于仓布局级红线（RL-004/005/007）与 E107；缺省取本体仓父目录",
    )
    check.add_argument(
        "--baseline",
        help="本体仓的 git 基线（如 HEAD~1 / origin/main），给出则追加架构熵漂移对比",
    )
    check.add_argument(
        "--checker-ref",
        help="本体仓历史 ref，用该版本规则衡量基线（否则用当前规则）。与 --baseline 配对，"
        "用于把数据漂移与规则漂移解耦",
    )
    check.add_argument(
        "--require-workspace",
        action="store_true",
        help="要求跨仓/跨源判定必须完整执行；有 S001/S003/S004 时退出码 2（CI 用，防假绿灯）",
    )
    check.add_argument("--json", action="store_true", help="输出 JSON")
    check.set_defaults(func=cmd_check)

    render = sub.add_parser("render", help="渲染服务目录 Markdown")
    _add_common(render)
    render.add_argument("--out", help="输出文件，缺省打印")
    render.set_defaults(func=cmd_render)

    impact = sub.add_parser("impact", help="查一个服务的依赖与被依赖闭包")
    _add_common(impact)
    impact.add_argument("--service", required=True, help="服务名（abox 里的实例 local name）")
    impact.add_argument(
        "--graph",
        default="call",
        help="在哪个域图上算闭包（call/data/contract/build/deploy/governance），缺省 call",
    )
    impact.add_argument("--json", action="store_true", help="输出 JSON")
    impact.set_defaults(func=cmd_impact)

    relations = sub.add_parser("relations", help="列出关系类型、所属图与实例数")
    _add_common(relations)
    relations.add_argument("--json", action="store_true", help="输出 JSON")
    relations.set_defaults(func=cmd_relations)

    owners = sub.add_parser("owners", help="按 owner 生成 CODEOWNERS")
    _add_common(owners)
    owners.add_argument("--org", help="GitHub 组织名，给出时生成 @org/team 形式")
    owners.add_argument("--out", help="输出文件，缺省打印")
    owners.set_defaults(func=cmd_owners)

    export = sub.add_parser("export", help="把声明图导出为 RDF/Turtle（语义网层 L1）")
    _add_common(export)
    export.add_argument("--out", help="输出 Turtle 文件，缺省打印到 stdout")
    export.set_defaults(func=cmd_export)

    shacl = sub.add_parser("shacl", help="用 SHACL shapes 验证导出的 RDF 图（语义网层 L3）")
    _add_common(shacl)
    shacl.add_argument("--json", action="store_true", help="输出 JSON")
    shacl.set_defaults(func=cmd_shacl)

    sparql = sub.add_parser("sparql", help="用 SPARQL 属性路径查依赖闭包（语义网层 L4）")
    _add_common(sparql)
    sparql.add_argument("--service", required=True, help="服务名（abox 里的实例 local name）")
    sparql.add_argument("--json", action="store_true", help="输出 JSON")
    sparql.set_defaults(func=cmd_sparql)

    schema = sub.add_parser(
        "render-schema",
        help="由 tbox/decisions.ttl 生成 contracts/schemas/decision.yaml（生成物，勿手改）",
    )
    _add_common(schema, contracts=True)
    schema.add_argument("--out", help="输出路径；缺省 <contracts>/contracts/schemas/decision.yaml")
    schema.set_defaults(func=cmd_render_schema)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
