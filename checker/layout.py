"""仓布局与部署清单级红线的机械检查。

覆盖三条此前只有声明、没有实现的约束（现已参数化，规则即数据）：

- RL-004 建表/改表只允许在 ``rcp-ops/migrations``（file-scan）
- RL-005 业务服务不得直接引入 JDBC 驱动，读写只经 dataway（registry-scan）
- RL-007 部署清单不得写死内部服务的上游地址（upstream-scan）

本模块是"规则解释器"：执行参数（include / match / denyValues / allowPrefixes /
scanPrefix / internalHosts / message 模板）全部来自 policy/redlines.ttl 的 spec 声明，
这里不硬编码任何红线参数。新增或调整一条红线只需改 policy/redlines.ttl。

边界：只做文本与结构判定，不解析 Java 语义、不连集群、不判断"能否运行"。
判定依据是仓库里的文件内容，因此结论可复算、可复现。
"""

from __future__ import annotations

import os
import re
from datetime import date
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Iterable, Iterator

from .loader import Finding

# 遍历时跳过的目录：构建产物、依赖、VCS 元数据、worktree。
# 这是"基础设施"而非"规则参数"，对所有规则一致，故不放入 policy/redlines.ttl。
PRUNED_DIRS = {
    ".git",
    ".agents",
    ".idea",
    "target",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
}

# pom.xml 依赖抽取的实现细节：这三个正则是"如何解析 pom"的固定机制，不是
# "该禁哪些 groupId"的规则参数——后者在 spec 的 deny_values 里。
# spec 里的 extract: dependency.groupId 即指此抽取。
DEPENDENCY_BLOCK = re.compile(r"<dependency>(.*?)</dependency>", re.S)
GROUP_ID = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")
ARTIFACT_ID = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")


def is_worktree(path: Path) -> bool:
    """判断目录是不是某个仓的 worktree（而非独立检出）。

    机械判据：``.git`` 是文件且首行以 ``gitdir:`` 开头——这是 git worktree 与
    submodule 的布局，主仓的 ``.git`` 是目录。

    为什么必须排掉：worktree 目录名形如 ``rcp-ontology-team``，在只看目录名的
    检查里会被当成"未登记的仓"，而且其中的文件会被重复扫一遍，导致同一条红线
    报两次。worktree 的真实归属仓已在主检出里登记，不该单独计一次。
    """
    dot_git = path / ".git"
    if not dot_git.is_file():
        return False
    try:
        head = dot_git.read_text(encoding="utf-8", errors="ignore").lstrip()
    except OSError:
        return False
    return head.startswith("gitdir:")


def _walk(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """按后缀遍历，跳过 PRUNED_DIRS 与 worktree 目录。不跟随符号链接。"""
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(
            d
            for d in dirnames
            if d not in PRUNED_DIRS and not is_worktree(Path(dirpath) / d)
        )
        for filename in sorted(filenames):
            if os.path.splitext(filename)[1] in suffixes:
                yield Path(dirpath) / filename


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _suffixes(spec: dict[str, Any]) -> tuple[str, ...]:
    """spec.include 形如 ["*.sql"]，转成 _walk 用的后缀元组 (".sql",)。"""
    return tuple(
        "." + p[2:]
        for p in (spec.get("include") or [])
        if isinstance(p, str) and p.startswith("*.")
    )


def _compile_match(spec: dict[str, Any]) -> re.Pattern[str]:
    flags = re.IGNORECASE if spec.get("case_insensitive") else 0
    return re.compile(spec["match"], flags)


def run_file_scan(
    spec: dict[str, Any],
    workspace: Path,
    redline_id: str,
) -> list[Finding]:
    """file-scan：按后缀遍历工作区，跳过允许前缀，正则命中即报。

    执行参数全部来自 spec：include / allow_prefixes / match / case_insensitive /
    message。message 支持 {rel} {matched} {allowed} 占位。
    """
    findings: list[Finding] = []
    pattern = _compile_match(spec)
    allowed = tuple(spec.get("allow_prefixes") or ())
    template = spec.get("message") or "{rel} 命中「{matched}」"
    for path in _walk(workspace, _suffixes(spec)):
        rel = _rel(path, workspace)
        if allowed and rel.startswith(allowed):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        hit = pattern.search(text)
        if hit:
            matched = " ".join(hit.group(0).split())
            findings.append(
                Finding(
                    "error",
                    redline_id,
                    template.format(rel=rel, matched=matched, allowed=allowed),
                )
            )
    return findings


def _dependencies(pom_text: str) -> Iterator[tuple[str, str]]:
    for block in DEPENDENCY_BLOCK.findall(pom_text):
        group = GROUP_ID.search(block)
        artifact = ARTIFACT_ID.search(block)
        yield (group.group(1) if group else "", artifact.group(1) if artifact else "")


def run_registry_scan(
    spec: dict[str, Any],
    workspace: Path,
    registry: dict[str, Any],
    redline_id: str,
) -> list[Finding]:
    """registry-scan：遍历登记的服务/库，读其 pom.xml，抽取依赖 groupId，命中 deny 即报。

    执行参数：include（仓内文件名）/ extract / deny_values / allow_kinds / message。
    message 支持 {repo} {name} {group} {artifact} 占位。
    """
    findings: list[Finding] = []
    allowed_kinds = set(spec.get("allow_kinds") or [])
    deny = set(spec.get("deny_values") or [])
    filename = (spec.get("include") or ["pom.xml"])[0]
    template = (
        spec.get("message")
        or "{repo}（{name}）命中禁用依赖 {group}:{artifact}"
    )

    allowed_repos = {
        service.get("repo")
        for service in registry.get("services", [])
        if service.get("kind") in allowed_kinds
    }
    targets: list[tuple[str, str]] = [
        (service.get("repo"), service.get("name"))
        for service in registry.get("services", [])
        if service.get("kind") not in allowed_kinds
    ]
    targets += [
        (library.get("repo"), library.get("name"))
        for library in registry.get("libraries", [])
    ]

    for repo, name in targets:
        if not repo or repo in allowed_repos:
            continue
        pom = workspace / repo / filename
        if not pom.is_file():
            # 仓缺失由构建暴露，不在本检查里重复报。
            continue
        text = pom.read_text(encoding="utf-8", errors="replace")
        for group, artifact in _dependencies(text):
            if group in deny:
                findings.append(
                    Finding(
                        "error",
                        redline_id,
                        template.format(repo=repo, name=name, group=group, artifact=artifact),
                    )
                )
    return findings


def _match_exception(
    redline_id: str,
    rel: str,
    line: str,
    exceptions: Iterable[dict[str, Any]],
) -> dict[str, Any] | None:
    for exception in exceptions:
        if exception.get("redline") != redline_id:
            continue
        scope = str(exception.get("scope") or "")
        if scope and not (fnmatch(rel, scope) or rel.startswith(scope.rstrip("/") + "/")):
            continue
        pattern = exception.get("match")
        if pattern and not re.search(str(pattern), line):
            continue
        return exception
    return None


def _expired(exception: dict[str, Any], today: date) -> bool:
    raw = exception.get("review_by")
    if not raw:
        return False
    try:
        return date.fromisoformat(str(raw)) < today
    except ValueError:
        return False


def _brief(text: Any, limit: int = 48) -> str:
    flat = " ".join(str(text or "未说明").split())
    return flat if len(flat) <= limit else flat[:limit] + "…"


def run_upstream_scan(
    spec: dict[str, Any],
    workspace: Path,
    registry: dict[str, Any],
    exceptions: Iterable[dict[str, Any]],
    redline_id: str,
    today: date | None = None,
) -> list[Finding]:
    """upstream-scan：扫 scan_prefix 下的清单，匹配 host:port，内部地址写死即报。

    登记例外降级为 warn（按 (文件, 例外) 聚合为一条），review_by 过期恢复为 error。
    执行参数：scan_prefix / include / match / internal_hosts / message 模板。
    """
    findings: list[Finding] = []
    exceptions = [e for e in exceptions if e.get("redline") == redline_id]
    today = today or date.today()
    pattern = _compile_match(spec)
    internal = {
        service.get("name")
        for service in registry.get("services", [])
        if not service.get("external")
    }
    excepted: dict[tuple[str, int], dict[str, Any]] = {}

    t_unreg = (
        spec.get("message")
        or "{rel}:{lineno} 写死上游 {url}；应经服务发现解析，或在 policy/redlines.ttl 登记例外"
    )
    t_expired = (
        spec.get("message_expired")
        or "{rel}:{lineno} 写死上游 {url}；登记的例外已于 {review_by} 过期，须复审"
    )
    t_excepted = (
        spec.get("message_excepted")
        or "{rel} {span}写死内部服务地址（例外：{reason}；owner={owner}，复审 {review_by}）"
    )

    root = workspace / str(spec.get("scan_prefix") or "").rstrip("/")
    for path in _walk(root, _suffixes(spec)):
        rel = _rel(path, workspace)
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in pattern.finditer(line):
                host = match.group(1)
                if host not in internal:
                    continue
                url = match.group(0)
                exception = _match_exception(redline_id, rel, line, exceptions)
                if exception is None:
                    findings.append(
                        Finding(
                            "error",
                            redline_id,
                            t_unreg.format(rel=rel, lineno=lineno, url=url),
                        )
                    )
                elif _expired(exception, today):
                    findings.append(
                        Finding(
                            "error",
                            redline_id,
                            t_expired.format(
                                rel=rel,
                                lineno=lineno,
                                url=url,
                                review_by=exception.get("review_by"),
                            ),
                        )
                    )
                else:
                    key = (rel, id(exception))
                    entry = excepted.setdefault(
                        key, {"exception": exception, "lines": []}
                    )
                    entry["lines"].append(lineno)

    for (rel, _), entry in sorted(excepted.items()):
        exception = entry["exception"]
        lines = entry["lines"]
        span = f"第 {lines[0]} 行" if len(lines) == 1 else f"{len(lines)} 处"
        findings.append(
            Finding(
                "warn",
                redline_id,
                t_excepted.format(
                    rel=rel,
                    span=span,
                    reason=_brief(exception.get("reason")),
                    owner=exception.get("owner", "未指定"),
                    review_by=exception.get("review_by", "未定"),
                ),
            )
        )
    return findings


def run_declared_scans(
    redlines: dict[str, Any],
    workspace: Path,
    registry: dict[str, Any],
) -> list[Finding]:
    """按 policy/redlines.ttl 的 spec 声明执行三类扫描红线。

    每类 spec.type 对应一个解释器；新增一条已支持类型的红线只需在 redlines.ttl
    加一条声明，无需改本文件。registry-assert 与 cross-source 的判定由 checks.py
    的 TBox 驱动检查与跨源比对承担（不在这里）。
    """
    findings: list[Finding] = []
    exceptions = redlines.get("exceptions", [])
    for constraint in redlines.get("constraints", []):
        spec = constraint.get("spec")
        if not isinstance(spec, dict):
            continue
        redline_id = constraint.get("id") or "?"
        spec_type = spec.get("type")
        if spec_type == "file-scan":
            findings += run_file_scan(spec, workspace, redline_id)
        elif spec_type == "registry-scan":
            findings += run_registry_scan(spec, workspace, registry, redline_id)
        elif spec_type == "upstream-scan":
            findings += run_upstream_scan(
                spec, workspace, registry, exceptions, redline_id
            )
    return findings
