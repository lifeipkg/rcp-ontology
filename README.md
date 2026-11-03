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

## 真源分层：事实与表达分开

仓里没有"唯一一种格式的真源"，只有"每一层只有一个编辑面"：

| 层 | 内容 | 真源 | 为什么是这个格式 |
|---|---|---|---|
| 概念实例（ABox） | 服务、库、端口、owner、能力、边实例 | `rcp-contracts/registry/services.yaml` | 高变更频率，需要可评审的 diff 与唯一键检查 |
| 概念声明（TBox） | kind 及其五个行为属性、能力立名、决策语义 | `concepts/*.yaml` | 规则即数据：改声明即改判定，不需改代码 |
| 关系与公理 | 有哪些关系、属于哪张图、是否参与可达性、端点种类 | `ontology/relations.ttl` | `rdfs:subPropertyOf` / `owl:domain` 这类断言无法从 key: value 推导，只能写成三元组 |
| 结构约束 | SHACL shapes（静态） | `ontology/constraints.ttl` | 表达性约束（`sh:qualifiedValueShape`、`sh:or`），无法从属性机械生成 |

判据一句话：**能写成 `key: value` 的留在 YAML，只关于关系与公理的断言才进 TTL。**
因此"要不要把 YAML 全换成 TTL"是个错误的提法——换掉的是可操作性，换不来表达能力，
因为表达能力上限由建模形状决定，不由序列化格式决定。

## 关系层：分域图（`ontology/relations.ttl`）

边不是单一的 `depends_on`。登记可以写多条关系，每条关系属于一张**分域图**：

```yaml
services:
  - name: api-gateway
    relations:
      calls: [content-patrol, message-patrol]   # 调用图
      queries: [dataway]                        # 数据图
    depends_on: [fund-patrol]                   # 旧写法，等价于 relations.calls
```

六张图与分域理由：

| 图 | 是否参与可达性 | 为什么这样分 |
|---|---|---|
| `call` | 是 | 代码事实：同步调用、发布、订阅。环与不可达只在这张图上判 |
| `data` | 否 | 经 dataway 的读写与表级血缘。直连数据库由 RL-005 另判 |
| `contract` | 否 | 服务与 OpenAPI/schema 的归属，RL-003 的载体 |
| `build` | 否 | 编译期依赖与版本基线。基座被全员依赖，套进可达性会得出全连通 |
| `deploy` | 否 | workload、共置、网关路由。路由是配置事实，不等于有人在调 |
| `governance` | 否 | 归属、红线、例外。回答 who，不回答 can-reach |

不分域的后果是确定的：部署共置与数据血缘混进调用图，E108 会把合法的双向引用判成环，
E110 会把不参与调用的基座判成不可达。

新增一条关系只改 `relations.ttl`——不改代码、不改检查、不改 shapes：

```turtle
rcp:streams_to a rcp:RelationKind, owl:ObjectProperty ;
    rcp:name "streams_to" ;
    rcp:graph rcp:CallGraph ;          # 进哪张图
    rcp:status "declared" ;            # enforced = 参与判定；declared = 仅立名
    rdfs:subPropertyOf rcp:dependsOn ; # 参与可达性才需要
    rcp:targetKind rcp:Service .       # 端点种类约束（E117 判据）
```

`depends_on` 与 `relations.calls` 会在导出时同时产出 `rcp:calls`（类型化边）与
`rcp:dependsOn`（可达性汇总边）。汇总边是子属性推演的物化结果，由单一事实导出、不回写，
因此不构成第二份真源；它的价值是让 SHACL、SPARQL、推理机与外部工具不必各自跑一遍推理。


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

# 架构熵基线对比：契约仓在 <ref> 处与当前的声明层结论差集（新增/消失的 error+warn）
python rcp_ontology/cli.py check --contracts ../rcp-contracts --workspace .. --baseline origin/main

# 历史检查器看历史数据：用本体仓 <ref> 那版规则衡量基线，把"数据漂移"与"规则漂移"解耦。
# 缺省用当前规则衡量基线——若基线早于"规则数据化"，会混入 E301/E302 这类"规则变严"的假漂移，
# 此时应加 --checker-ref 指向与基线同时代的本体仓提交。
python rcp_ontology/cli.py check --contracts ../rcp-contracts --workspace .. --baseline origin/main --checker-ref HEAD~1

# 改一个服务之前，先看它会波及谁（--graph 选域：call/data/contract/build/deploy/governance）
python rcp_ontology/cli.py impact --contracts ../rcp-contracts --service dataway
python rcp_ontology/cli.py impact --contracts ../rcp-contracts --service dataway --graph data

# 我们到底建模了哪些关系、哪些还只是立了名没有实例
python rcp_ontology/cli.py relations --contracts ../rcp-contracts

# 按 owner 生成 CODEOWNERS（让归属落到审批上）
python rcp_ontology/cli.py owners --contracts ../rcp-contracts --org your-org --out .github/CODEOWNERS

# 渲染服务目录（生成物，勿手改）
python rcp_ontology/cli.py render --contracts ../rcp-contracts --out SERVICES.md

# 测试（正向闭合 + 每条约束各一条反例）
python -m pytest -q
```

## 检查项

检查按实现分两轨，下表「承担」列标注每项由哪一轨执行：

- **SHACL（声明式约束）**：可表达为「值/关系约束」的检查——依赖登记、依赖白名单、external
  方向、种类/能力声明、TBox 自洽、命名规范、port/contract 必填。约束来自 `ontology/constraints.ttl`
  （静态）+ `shapes.py` 从 `kinds.yaml` 编译（动态，规则即数据）。
- **Python（过程式检查）**：SHACL 表达不了的——键存在性、唯一键、跨源比对、契约文件存在、
  能力归属、图连通性、expected 形状、红线元检查、工作区布局（DDL/JDBC/上游地址扫描）。

### 结构与归属

| 编号 | 判据 | 承担 | 级别 |
|---|---|---|---|
| E001 | 服务缺必填字段（name/repo/kind/external/owner/capabilities，port 视 `requires_port`） | Python（键存在）+ SHACL（port 必填） | error |
| E002 | 服务名重复、repo 重复、端口冲突 | Python | error |
| E105 | 依赖了未登记的服务 | SHACL | error |
| E106 | 依赖了种类规则不允许的种类（非巡查线互调） | SHACL | error |
| E107 | 工作区存在 `rcp-*` 目录但未登记（或反之，仅完整工作区判后者） | Python | error |
| E201 | kind 未在 TBox 声明 | SHACL | error |
| E202 | capability 未在 TBox 立名 | SHACL | error |

### 图与公理

| 编号 | 判据 | 承担 | 级别 |
|---|---|---|---|
| E108 | 依赖成环（每张有边的分域图各判一次，消息标注图名） | Python | error |
| E109 | 非入口节点入度为 0（可能是备用通道，也可能漏登记依赖方）；命中 `expected.no_dependents` 声明且未过期则静默 | Python | warn |
| E110 | 从任何对外入口都不可达；命中 `expected.unreachable` 声明且未过期则静默 | Python | warn |
| E111 | 能力的 owner 未在 services/libraries 登记 | Python | error |
| E112 | 能力的 owner 并未声明持有该能力（归属与实现不符） | Python | error |
| E113 | TBox 内部悬空：`allowed_depends_on_kinds` 引用未声明种类，或缺显式布尔属性 | SHACL | error |
| E114 | 能力名不符合点分小写规范（如 `Patrol_Dispatch`） | SHACL | error |
| E115 | 服务 `expected` 预期状态声明不合法（非映射 / 未知字段 / 标志非布尔 / 缺 reason/owner/review_by / review_by 非日期） | Python | error |
| W306 | `expected` 声明与事实不符（声明无依赖但已有依赖方 / 声明不可达但已可达），提示移除过时声明 | Python | warn |

### 关系与公理

| 编号 | 判据 | 承担 | 级别 |
|---|---|---|---|
| E116 | 登记里的边使用了未在 `relations.ttl` 声明的关系名 | Python | error |
| E117 | 边的目标种类不符合该关系声明的 `targetKind` | Python | error |
| E118 | 关系未声明所属图，或引用了未声明的图 | Python | error |
| W307 | 关系标 `enforced` 但登记里零实例（判定空转） | Python | warn |
| S002 | 缺少 `relations.ttl`，关系级判定未执行（明示跳过） | Python | info |

### 红线与元检查

| 编号 | 判据 | 承担 | 级别 |
|---|---|---|---|
| E301 | 红线在 `redlines.yaml` 声明但无 `spec` 规格，检查器无法执行（纸面红线） | Python | error |
| E302 | 红线的 `spec` 规格不合法（type 未知 / 缺必填字段 / 正则无法编译） | Python | error |
| S001 | 跨仓检查未完整执行（只检出单仓），明示跳过而非静默通过 | Python | info |
| RL-001 | 巡查线互相调用 | SHACL | error |
| RL-002 | 对外入口不是网关/前端，或网关未对外 | SHACL | error |
| RL-003 | 决策枚举或分值在契约层与本体层不一致 | Python | error |
| RL-004 | `rcp-ops/migrations` 之外出现 DDL | Python | error |
| RL-005 | 业务服务或基座引入了 JDBC 驱动 | Python | error |
| RL-006 | 服务未挂契约或契约文件不存在 | SHACL（挂契约）+ Python（文件存在） | error |
| RL-007 | 部署清单写死内部服务地址；命中已登记例外降为 warn，例外过期转回 error | Python | error/warn |

### 已裁剪的检查

以下三项原为「弱提示」，对 AI 开发模式（个位数服务、以契约仓为真源）无实际收益，已随迁移移除：

| 编号 | 原判据 | 移除原因 |
|---|---|---|
| W301 | capability 立名但无服务使用 | 契约仓即真源，能力立名即「被引用」，无「立名而未用」场景 |
| W303 | 种类未在 `terms.yaml` 立名 | 术语立名与结构约束职责重叠，`kinds.yaml` 已唯一承载种类定义 |
| W304 | 能力除 owner 外还有别的实现者 | 单 owner 契约模型下不存在多实现，弱提示无裁决价值 |

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

## 语义网层（RDF / OWL / SHACL / SPARQL）

本仓的约束校验分两轨执行：**值/关系约束由 SHACL（声明式）承担，过程式检查由 Python 承担**。
同一份登记（registry）与概念（concepts）先导出为 RDF 图，再交给 SHACL 验证 + OWL 推理 +
SPARQL 查询处理。**YAML 仍是真源**，RDF 是它的图形态。

- SHACL 是依赖登记、依赖白名单、种类/能力声明、命名规范、port/contract 必填等约束的**唯一实现**
  （已从 `checks.py` 迁移过来），不再是「对照」而是「本尊」。
- OWL 与 SPARQL 仍与 `graph.py` 的 BFS 构成交叉验证：依赖闭包有且只有一个正确答案，三种范式算出的
  闭包必须一致。

### 四件套分工

| 技术 | 回答的问题 | 本仓对应 | 命令 |
|---|---|---|---|
| RDF | 事实如何描述 | `rcp_ontology/semweb/exporter.py`：YAML → 三元组 | `cli.py export` |
| OWL | 从已知推未知 | `ontology/rcp.ttl`（类与传递属性）+ `ontology/relations.ttl`（关系公理）+ `reasoner.py` | 测试交叉验证 |
| SHACL | 哪里违规 | `ontology/constraints.ttl`（静态）+ `shapes.py`（动态，从 `kinds.yaml` 编译）+ `validator.py` | `cli.py shacl` |
| SPARQL | 如何提问 | `query.py`：属性路径 `dependsOn+` | `cli.py sparql` |

### 交叉验证：三种范式同一结论

依赖闭包有且只有一个正确答案，这里用三种范式分别计算、断言一致：

- `graph.py` 的 BFS —— 手写图算法
- `reasoner.py` 的 owlrl 物化 —— OWL 推理机（`dependsOn` 声明为 `owl:TransitiveProperty`）
- `query.py` 的 `dependsOn+` —— SPARQL 属性路径

见 `tests/test_semweb.py`，对真实登记逐个服务断言三者闭包相等。

```bash
# 导出 RDF（默认打 stdout，--out 才落文件；生成物不入库）
python rcp_ontology/cli.py export --contracts ../rcp-contracts --out /tmp/services.ttl

# SHACL 验证（合规退 0，不合规退 1）
python rcp_ontology/cli.py shacl --contracts ../rcp-contracts

# SPARQL 依赖闭包（对照 impact 命令）
python rcp_ontology/cli.py sparql --contracts ../rcp-contracts --service dataway
```

### 定位与边界

- **SHACL 覆盖「能表达为图形状约束」的检查**（必填、依赖白名单、external 方向、声明归属、
  命名规范）。文件扫描类红线（RL-004 DDL / RL-005 JDBC / RL-007 上游地址）、跨源比对（RL-003）、
  键存在性与唯一键（E001 键存在 / E002）、图连通性（E108/E109/E110）不在 SHACL 能力内，
  仍由 `checks.py` 承担。
- **OWL/SPARQL 与 BFS 的交叉验证**仍保留：这是三种独立实现对齐同一图语义的回归护栏，防止
  任意一种实现漂移。其余部分在当前规模（个位数服务）下是"过度的"，价值在教学与前瞻——架构
  治理工具在服务膨胀到数百、依赖关系复杂化时，RDF 图 + 推理 + 查询是自然演进方向。

