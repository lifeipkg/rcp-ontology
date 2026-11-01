# rcp-ontology · 本体仓

平台**概念层**（TBox）与一致性检查器。它回答三类问题：

1. **有哪些种类的东西** —— 服务种类、能力、决策语义（TBox）
2. **登记的东西是否还在概念范围内** —— 实例对 TBox 的归属、归属关系是否成立（ABox ↔ TBox）
3. **这堆节点放在一起是否自洽** —— 依赖图有无环、谁不可达、能力归属是否与实现相符（图与公理层）

第 3 类是本体区别于"字段校验器"的地方：单看每个服务的字段都合法，但整张图可能互相矛盾。

## 什么是 TBox、什么是 ABox（本仓口径）

- **TBox（本仓 `concepts/`）**：种类（gateway / patrol-line / data-gateway / db-ops / frontend / meta）、能力立名、决策等级语义。不带具体服务名。
- **ABox（契约仓 `registry/services.yaml`）**：具体服务实例、端口、依赖、owner。
- 契约层（`rcp-contracts/contracts/`）：界面与结构的机器可读形态。

三者必须闭合：ABox 里出现的每个 kind 与 capability 都要在 TBox 声明；决策枚举与分值要逐字一致；
每个 kind 都要在 `vocabulary/terms.yaml` 立名。

**种类的行为全部由 TBox 属性决定，不在代码里硬编码种类名。** 新增种类只改 `concepts/kinds.yaml`：

| 属性 | 作用 |
|---|---|
| `must_be_external` | 是否必须 `external: true`（RL-002 判据） |
| `is_entry` | 是否为图上入口，允许入度为 0（E109 判据） |
| `requires_port` | 是否必须有 `port`（E001 判据；元仓为 false） |
| `requires_contract` | 是否必须挂 OpenAPI（RL-006 判据；前端与元仓为 false） |
| `allowed_depends_on_kinds` | 允许依赖的种类白名单，空列表 = 只允许零依赖（E106 / RL-001 判据） |

## 用法

```bash
pip install -r requirements.txt

# 一致性检查（在任意目录跑均可，参数指向契约仓）
python rcp_ontology/cli.py check --contracts ../rcp-contracts
python rcp_ontology/cli.py check --contracts ../rcp-contracts --json

# 含仓布局级红线（RL-004 / RL-005 / RL-007）与未登记仓检测：--workspace 指向多仓工作区根
python rcp_ontology/cli.py check --contracts ../rcp-contracts --workspace ..

# 要求跨仓检查必须完整执行：只检出单仓时退出码 2，防"假绿灯"
python rcp_ontology/cli.py check --contracts ../rcp-contracts --workspace .. --require-workspace

# 改一个服务之前，先看它会波及谁
python rcp_ontology/cli.py impact --contracts ../rcp-contracts --service dataway

# 按 owner 生成 CODEOWNERS（让归属落到审批上）
python rcp_ontology/cli.py owners --contracts ../rcp-contracts --org your-org --out .github/CODEOWNERS

# 渲染服务目录（生成物，勿手改）
python rcp_ontology/cli.py render --contracts ../rcp-contracts --out SERVICES.md

# 测试（正向闭合 + 每条约束各一条反例）
python -m pytest -q
```

## 检查项

### 结构与归属

| 编号 | 判据 | 级别 |
|---|---|---|
| E001 | 服务缺必填字段（name/repo/kind/external/owner/capabilities，port 视 `requires_port`） | error |
| E002 | 服务名重复、repo 重复、端口冲突 | error |
| E105 | 依赖了未登记的服务 | error |
| E106 | 依赖了种类规则不允许的种类（非巡查线互调） | error |
| E107 | 工作区存在 `rcp-*` 目录但未登记（或反之，仅完整工作区判后者） | error |
| E201 | kind 未在 TBox 声明 | error |
| E202 | capability 未在 TBox 立名 | error |

### 图与公理

| 编号 | 判据 | 级别 |
|---|---|---|
| E108 | 依赖成环 | error |
| E109 | 非入口节点入度为 0（可能是备用通道，也可能漏登记依赖方）；命中 `expected.no_dependents` 声明且未过期则静默 | warn |
| E110 | 从任何对外入口都不可达；命中 `expected.unreachable` 声明且未过期则静默 | warn |
| E111 | 能力的 owner 未在 services/libraries 登记 | error |
| E112 | 能力的 owner 并未声明持有该能力（归属与实现不符） | error |
| E113 | TBox 内部悬空：`allowed_depends_on_kinds` 引用未声明种类，或缺显式布尔属性 | error |
| E114 | 能力名不符合点分小写规范（如 `Patrol_Dispatch`） | error |
| E115 | 服务 `expected` 预期状态声明不合法（非映射 / 未知字段 / 标志非布尔 / 缺 reason/owner/review_by / review_by 非日期） | error |
| W306 | `expected` 声明与事实不符（声明无依赖但已有依赖方 / 声明不可达但已可达），提示移除过时声明 | warn |

### 红线与元检查

| 编号 | 判据 | 级别 |
|---|---|---|
| E301 | 红线在 `redlines.yaml` 声明但无 `spec` 规格，检查器无法执行（纸面红线） | error |
| E302 | 红线的 `spec` 规格不合法（type 未知 / 缺必填字段 / 正则无法编译） | error |
| W301 | capability 立名但无服务使用 | warn |
| W303 | 种类未在 `terms.yaml` 立名（`covers` 缺失） | warn |
| W304 | 能力除 owner 外还有别的实现者（多实现未声明） | warn |
| S001 | 跨仓检查未完整执行（只检出单仓），明示跳过而非静默通过 | info |
| RL-001 | 巡查线互相调用 | error |
| RL-002 | 对外入口不是网关/前端，或网关未对外 | error |
| RL-003 | 决策枚举或分值在契约层与本体层不一致 | error |
| RL-004 | `rcp-ops/migrations` 之外出现 DDL | error |
| RL-005 | 业务服务或基座引入了 JDBC 驱动 | error |
| RL-006 | 服务未挂契约或契约文件不存在 | error |
| RL-007 | 部署清单写死内部服务地址；命中已登记例外降为 warn，例外过期转回 error | error/warn |

## 三条设计约定

**1. 不可判就明说跳过，不假装通过。** 跨仓检查（RL-004/005/007、E107 的缺失方向）需要多仓
同处一个工作区。单仓 CI 里 `workspace_is_complete()` 返回 false，检查器输出 `S001` 说明哪些
判定没有执行，并可用 `--require-workspace` 把它升级为失败。这样"绿灯"的含义是确定的。

**2. 重复键即解析失败。** YAML 装载用严格构造器，同一映射里出现重复键直接报错并给出行号。
多人同时改 `services.yaml` 时，重复键会让"文件里写的"与"程序读到的"不一致，必须显式失败。

**3. worktree 不算独立仓。** `.git` 是文件且首行以 `gitdir:` 开头的目录被识别为 worktree，
不参与"未登记仓"判定，也不会被重复扫描。

## 边界

本仓**只判机械事实**：结构、归属、红线、枚举逐字一致、DDL 与 JDBC 的落位、上游地址是否写死、
图的连通性。像"这个需求是否被完整覆盖""这个裁决是否合理"属于语义判断，由主会话对照原文完成，
不由本检查器宣称闭合。差集为空≠需求无遗漏，只说明索引闭合。

已实现的两类判定有明确强弱之分：

- **强**：结构完整、枚举一致、DDL/JDBC 落位、依赖种类越界 —— 违反即确定有错
- **弱**：入度为 0、不可达、术语未立名 —— 只能提示"这里值得看一眼"，不能断定是错
  （例如 dataway / db-ops 入度为 0 是因为数据面尚未启用，不是漏登记）
