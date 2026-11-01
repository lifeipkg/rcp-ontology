"""本体检查器 CLI。

用法（文件路径直接执行或 -m 均可）：
    python rcp_ontology/cli.py check --contracts ../rcp-contracts [--json]
    python rcp_ontology/cli.py render --contracts ../rcp-contracts --out SERVICES.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rcp_ontology.checks import check_all  # noqa: E402
from rcp_ontology.loader import LoadError, load_concepts, load_registry  # noqa: E402


def cmd_check(args: argparse.Namespace) -> int:
    contracts = Path(args.contracts).resolve()
    concepts_dir = Path(args.concepts).resolve() if args.concepts else None
    workspace = Path(args.workspace).resolve() if args.workspace else None
    try:
        findings = check_all(contracts, concepts_dir, workspace)
    except LoadError as exc:
        print(f"[rcp-ontology] 声明不可用: {exc}", file=sys.stderr)
        return 2

    errors = [f for f in findings if f.level == "error"]
    warns = [f for f in findings if f.level == "warn"]

    if args.json:
        print(json.dumps({
            "contracts": str(contracts),
            "errors": [f.as_dict() for f in errors],
            "warnings": [f.as_dict() for f in warns],
            "closed": not errors,
        }, ensure_ascii=False, indent=2))
    else:
        for finding in findings:
            print(f"[{finding.level.upper():5}] {finding.code}: {finding.message}")
        print(f"\n结论：{len(errors)} 个错误，{len(warns)} 个提示 —— "
              f"{'闭合' if not errors else '未闭合'}")

    return 0 if not errors else 1


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
        caps = "、".join(cap_zh.get(c, c) for c in service.get("capabilities") or [])
        deps = "、".join(service.get("depends_on") or []) or "—"
        lines.append(
            f"| `{service.get('name')}` | {kind_zh.get(service.get('kind'), service.get('kind'))} "
            f"| {service.get('port')} | {'是' if service.get('external') else '否'} | {caps} | {deps} |"
        )
    lines += ["", "## 库", "", "| 库 | 坐标 | 能力 |", "|---|---|---|"]
    for library in registry.get("libraries", []):
        caps = "、".join(cap_zh.get(c, c) for c in library.get("capabilities") or [])
        lines.append(f"| `{library.get('name')}` | `{library.get('artifact')}` | {caps} |")

    text = "\n".join(lines) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"已渲染: {args.out}")
    else:
        print(text)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rcp-ontology", description="风控平台本体检查器")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="登记/契约/红线 一致性检查")
    check.add_argument("--contracts", required=True, help="契约仓根目录")
    check.add_argument("--concepts", help="TBox 目录，缺省为本仓 concepts/")
    check.add_argument(
        "--workspace",
        help="多仓工作区根，用于仓布局级红线（RL-004/005/007）；缺省取契约仓父目录",
    )
    check.add_argument("--json", action="store_true", help="输出 JSON")
    check.set_defaults(func=cmd_check)

    render = sub.add_parser("render", help="渲染服务目录 Markdown")
    render.add_argument("--contracts", required=True, help="契约仓根目录")
    render.add_argument("--concepts", help="TBox 目录")
    render.add_argument("--out", help="输出文件，缺省打印")
    render.set_defaults(func=cmd_render)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
