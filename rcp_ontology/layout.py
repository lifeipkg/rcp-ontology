"""仓布局与部署清单级红线的机械检查。

覆盖三条此前只有声明、没有实现的约束：

- RL-004 建表/改表只允许在 ``rcp-ops/migrations``
- RL-005 业务服务不得直接引入 JDBC 驱动（读写只经 dataway）
- RL-007 部署清单不得写死内部服务的上游地址（应经服务发现）

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

DDL_STATEMENT = re.compile(
    r"\b(?:create|alter|drop|truncate)\s+"
    r"(?:table|index|view|database|schema|unique\s+index)\b",
    re.IGNORECASE,
)

# JDBC 驱动：按 groupId 判定，避免误伤 jdbc 客户端抽象或连接池。
JDBC_DRIVER_GROUPS = {
    "mysql",
    "com.mysql",
    "com.mysql.jdbc",
    "org.postgresql",
    "com.h2database",
    "com.oracle.database.jdbc",
    "org.mariadb.jdbc",
}

# 允许持有 JDBC 驱动与 SQL 的种类：数据网关与 DDL 执行者是唯一出口。
DATA_LAYER_KINDS = {"data-gateway", "db-ops"}

# 迁移真源的两种可接受写法：工作区根下的 rcp-ops/migrations，
# 或把 rcp-ops 单独检出时其根下的 migrations（worktree / 独立 clone 布局）。
# 业务仓内的 rcp-xxx/migrations 不匹配这两种，约束强度不变。
DDL_ALLOWED_PREFIXES = ("rcp-ops/migrations/", "migrations/")

UPSTREAM_URL = re.compile(r"https?://([a-z][a-z0-9-]*):(\d{2,5})\b")

DEPENDENCY_BLOCK = re.compile(r"<dependency>(.*?)</dependency>", re.S)
GROUP_ID = re.compile(r"<groupId>\s*([^<\s]+)\s*</groupId>")
ARTIFACT_ID = re.compile(r"<artifactId>\s*([^<\s]+)\s*</artifactId>")


def _walk(root: Path, suffixes: tuple[str, ...]) -> Iterator[Path]:
    """按后缀遍历，跳过 PRUNED_DIRS。不跟随符号链接。"""
    if not root.is_dir():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNED_DIRS)
        for filename in sorted(filenames):
            if os.path.splitext(filename)[1] in suffixes:
                yield Path(dirpath) / filename


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def check_ddl_location(
    workspace: Path,
    allowed_prefixes: Iterable[str] = DDL_ALLOWED_PREFIXES,
) -> list[Finding]:
    """RL-004：迁移目录之外不得出现 DDL 语句。"""
    findings: list[Finding] = []
    allowed = tuple(allowed_prefixes)
    for sql_file in _walk(workspace, (".sql",)):
        rel = _rel(sql_file, workspace)
        if rel.startswith(allowed):
            continue
        text = sql_file.read_text(encoding="utf-8", errors="replace")
        hit = DDL_STATEMENT.search(text)
        if hit:
            findings.append(
                Finding(
                    "error",
                    "RL-004",
                    f"{rel} 含 DDL「{' '.join(hit.group(0).split())}」；"
                    f"建表/改表只允许经 db-ops 执行 {allowed} 下的迁移",
                )
            )
    return findings


def _dependencies(pom_text: str) -> Iterator[tuple[str, str]]:
    for block in DEPENDENCY_BLOCK.findall(pom_text):
        group = GROUP_ID.search(block)
        artifact = ARTIFACT_ID.search(block)
        yield (group.group(1) if group else "", artifact.group(1) if artifact else "")


def check_jdbc_in_business(workspace: Path, registry: dict[str, Any]) -> list[Finding]:
    """RL-005：业务服务与人共用库不得引入 JDBC 驱动。"""
    findings: list[Finding] = []
    allowed_repos = {
        service.get("repo")
        for service in registry.get("services", [])
        if service.get("kind") in DATA_LAYER_KINDS
    }

    targets: list[tuple[str, str]] = [
        (service.get("repo"), service.get("name"))
        for service in registry.get("services", [])
        if service.get("kind") not in DATA_LAYER_KINDS
    ]
    targets += [
        (library.get("repo"), library.get("name"))
        for library in registry.get("libraries", [])
    ]

    for repo, name in targets:
        if not repo or repo in allowed_repos:
            continue
        pom = workspace / repo / "pom.xml"
        if not pom.is_file():
            # 仓缺失由构建暴露，不在本检查里重复报。
            continue
        text = pom.read_text(encoding="utf-8", errors="replace")
        for group, artifact in _dependencies(text):
            if group in JDBC_DRIVER_GROUPS:
                findings.append(
                    Finding(
                        "error",
                        "RL-005",
                        f"{repo}（{name}）的 pom 引入 JDBC 驱动 {group}:{artifact}；"
                        f"业务读写只能经 dataway 的 HTTP 契约",
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


def check_hardcoded_upstream(
    workspace: Path,
    registry: dict[str, Any],
    exceptions: Iterable[dict[str, Any]] = (),
    today: date | None = None,
    scan_prefix: str = "rcp-ops/",
) -> list[Finding]:
    """RL-007：部署清单不得写死内部服务地址，例外须登记且定期复审。

    例外命中按 (文件, 例外) 聚合为一条 warn，避免同一例外刷屏多行；
    未登记与已过期的偏离逐条报 error，保留行号便于定位。
    """
    findings: list[Finding] = []
    exceptions = list(exceptions)
    today = today or date.today()
    internal = {
        service.get("name")
        for service in registry.get("services", [])
        if not service.get("external")
    }
    excepted: dict[tuple[str, int], dict[str, Any]] = {}

    root = workspace / scan_prefix.rstrip("/")
    for path in _walk(root, (".yml", ".yaml")):
        rel = _rel(path, workspace)
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for match in UPSTREAM_URL.finditer(line):
                host = match.group(1)
                if host not in internal:
                    continue
                exception = _match_exception("RL-007", rel, line, exceptions)
                if exception is None:
                    findings.append(
                        Finding(
                            "error",
                            "RL-007",
                            f"{rel}:{lineno} 写死上游 {match.group(0)}；"
                            f"应经服务发现解析，或在 redlines.yaml 登记例外",
                        )
                    )
                elif _expired(exception, today):
                    findings.append(
                        Finding(
                            "error",
                            "RL-007",
                            f"{rel}:{lineno} 写死上游 {match.group(0)}；"
                            f"登记的例外已于 {exception.get('review_by')} 过期，须复审",
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
                "RL-007",
                f"{rel} {span}写死内部服务地址（例外：{_brief(exception.get('reason'))}；"
                f"owner={exception.get('owner', '未指定')}，复审 {exception.get('review_by', '未定')}）",
            )
        )
    return findings
