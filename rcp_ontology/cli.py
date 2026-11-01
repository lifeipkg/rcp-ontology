"""本体检查器 CLI。

用法（文件路径直接执行或 -m 均可）：
    python rcp_ontology/cli.py check --contracts ../rcp-contracts [--workspace .] [--json] [--baseline origin/main]
    python rcp_ontology/cli.py render --contracts ../rcp-contracts --out SERVICES.md
    python rcp_ontology/cli.py impact --contracts ../rcp-contracts --service dataway
    python rcp_ontology/cli.py owners --contracts ../rcp-contracts [--out .github/CODEOWNERS]
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
    LoadError,
    load_concepts,
    load_registry,
)

LEVEL_ORDER = {"error": 0, "warn": 1, "info": 2}


def _fmt(finding) -> str:
    tag = "[跨仓] " if finding.scope == SCOPE_WORKSPACE else ""
    return f"[{finding.level.upper():5}] {tag}{finding.code}: {finding.message}"


def _extract_contracts_at(contracts: Path, ref: str) -> Path:
    """把契约仓在 ref 处的快照解到临时目录，返回该目录（用于 --baseline）。"""
    tmpdir = Path(tempfile.mkdtemp(prefix="rcp-ontology-baseline-"))
    archive = tmpdir / "snapshot.tar"
    result = subprocess.run(
        ["git", "-C", str(contracts), "archive", "--output", str(archive), ref],
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
    contracts = Path(args.contracts).resolve()
    concepts_dir = Path(args.concepts).resolve() if args.concepts else None
    workspace = Path(args.workspace).resolve() if args.workspace else None

    # 先解析基线快照（若给），失败即输入错误，不产出半截结论。
    baseline_dir: Path | None = None
    if args.baseline:
        try:
            baseline_dir = _extract_contracts_at(contracts, args.baseline)
        except RuntimeError as exc:
            print(f"[rcp-ontology] {exc}", file=sys.stderr)
            return 2

    try:
        findings = check_all(contracts, concepts_dir, workspace)
    except LoadError as exc:
        if baseline_dir:
            shutil.rmtree(baseline_dir, ignore_errors=True)
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    findings.sort(key=lambda f: (LEVEL_ORDER.get(f.level, 9), f.code))
    errors = [f for f in findings if f.level == "error"]
    warns = [f for f in findings if f.level == "warn"]
    infos = [f for f in findings if f.level == "info"]
    cross_repo_skipped = [f for f in infos if f.code == "S001"]

    # 架构熵漂移（--baseline）：基线声明层结论 vs 当前声明层结论的差集。
    drift = None
    if baseline_dir is not None:
        try:
            baseline_findings = check_declarations(baseline_dir, concepts_dir)
            drift = diff_findings(
                _decl_entropy(baseline_findings), _decl_entropy(findings)
            )
        except LoadError as exc:
            print(
                f"[rcp-ontology] 基线声明不可用，跳过漂移对比: {exc}", file=sys.stderr
            )
        finally:
            shutil.rmtree(baseline_dir, ignore_errors=True)

    if args.json:
        payload = {
            "contracts": str(contracts),
            "workspace": str(workspace or contracts.parent),
            "errors": [f.as_dict() for f in errors],
            "warnings": [f.as_dict() for f in warns],
            "skipped": [f.as_dict() for f in infos],
            "closed": not errors,
        }
        if drift is not None:
            payload["drift"] = {
                "baseline": args.baseline,
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
            print(
                f"\n架构熵基线对比（baseline: {args.baseline}，声明层 error/warn）："
            )
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
    if args.require_workspace and cross_repo_skipped:
        print("[rcp-ontology] --require-workspace：跨仓检查不完整，视为失败", file=sys.stderr)
        return 2
    return 0


def cmd_render(args: argparse.Namespace) -> int:
    contracts = Path(args.contracts).resolve()
    concepts_dir = Path(args.concepts).resolve() if args.concepts else None
    try:
        registry = load_registry(contracts)
        concepts = load_concepts(
            concepts_dir or Path(__file__).resolve().parent.parent / "concepts"
        )
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    kind_zh = {k["name"]: k.get("zh", k["name"]) for k in concepts["kinds"]}
    cap_zh = {c["name"]: c.get("zh", c["name"]) for c in concepts["capabilities"]}

    lines = ["# 平台服务目录（由 rcp-ontology 渲染，勿手改）", "",
             f"基座版本：{registry.get('baseline_stack', {})}", "",
             "## 服务", "",
             "| 服务 | 种类 | 端口 | 对外 | 能力 | 依赖 |",
             "|---|---|---|---|---|---|"]
    for service in registry.get("services", []):
        caps = "、".join(cap_zh.get(c, c) for c in service.get("capabilities") or []) or "—"
        deps = "、".join(service.get("depends_on") or []) or "—"
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
    """改一个服务之前，先看它会波及谁。"""
    contracts = Path(args.contracts).resolve()
    try:
        registry = load_registry(contracts)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    graph = G.build_graph(registry)
    name = args.service
    if name not in graph:
        print(f"[rcp-ontology] 未登记的服务: {name}", file=sys.stderr)
        return 2

    services = {s.get("name"): s for s in registry.get("services", [])}
    downstream = G.dependents_of(graph, name)
    upstream = G.dependencies_of(graph, name)

    if args.json:
        print(json.dumps({
            "service": name,
            "kind": services[name].get("kind"),
            "owner": services[name].get("owner"),
            "depends_on": sorted(upstream),
            "depended_by": sorted(downstream),
            "impact_count": len(downstream),
        }, ensure_ascii=False, indent=2))
        return 0

    print(f"服务 {name}（kind={services[name].get('kind')}，owner={services[name].get('owner')}）")
    print(f"  直接依赖     : {', '.join(graph.get(name, [])) or '无'}")
    print(f"  间接依赖闭包 : {', '.join(sorted(upstream)) or '无'}")
    print(f"  被谁依赖     : {', '.join(sorted(downstream)) or '无'}")
    print(f"\n改它的契约会波及 {len(downstream)} 个服务"
          + (f"：{', '.join(sorted(downstream))}" if downstream else "（当前无人依赖）"))
    return 0


def cmd_owners(args: argparse.Namespace) -> int:
    """按 registry 的 owner 生成 CODEOWNERS，让归属真正落到审批上。"""
    contracts = Path(args.contracts).resolve()
    try:
        registry = load_registry(contracts)
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
        "# 由 rcp-ontology owners 生成，勿手改 —— 真源是 rcp-contracts/registry/services.yaml",
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rcp-ontology", description="风控平台本体检查器")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="登记/契约/红线/图 一致性检查")
    check.add_argument("--contracts", required=True, help="契约仓根目录")
    check.add_argument("--concepts", help="TBox 目录，缺省为本仓 concepts/")
    check.add_argument(
        "--workspace",
        help="多仓工作区根，用于仓布局级红线（RL-004/005/007）与 E107；缺省取契约仓父目录",
    )
    check.add_argument(
        "--baseline",
        help="git 基线（如 HEAD~1 / origin/main），给出则追加架构熵漂移对比（声明层 error/warn 差集）",
    )
    check.add_argument(
        "--require-workspace",
        action="store_true",
        help="要求跨仓检查必须完整执行；不完整时退出码 2（CI 用，防假绿灯）",
    )
    check.add_argument("--json", action="store_true", help="输出 JSON")
    check.set_defaults(func=cmd_check)

    render = sub.add_parser("render", help="渲染服务目录 Markdown")
    render.add_argument("--contracts", required=True, help="契约仓根目录")
    render.add_argument("--concepts", help="TBox 目录")
    render.add_argument("--out", help="输出文件，缺省打印")
    render.set_defaults(func=cmd_render)

    impact = sub.add_parser("impact", help="查一个服务的依赖与被依赖闭包")
    impact.add_argument("--contracts", required=True, help="契约仓根目录")
    impact.add_argument("--service", required=True, help="服务名（registry 里的 name）")
    impact.add_argument("--json", action="store_true", help="输出 JSON")
    impact.set_defaults(func=cmd_impact)

    owners = sub.add_parser("owners", help="按 owner 生成 CODEOWNERS")
    owners.add_argument("--contracts", required=True, help="契约仓根目录")
    owners.add_argument("--org", help="GitHub 组织名，给出时生成 @org/team 形式")
    owners.add_argument("--out", help="输出文件，缺省打印")
    owners.set_defaults(func=cmd_owners)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
