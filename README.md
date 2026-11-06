# rcp-ontology · 本体仓

平台的**声明层唯一真源**：`ontology/` 下的 TTL 就是全部事实，没有第二种格式。
它回答四类问题：

1. **有哪些种类的东西** —— 服务种类、能力、决策等级、关系（`tbox/`）
2. **本平台登记了什么** —— 服务、库、端口、边、版本钉（`abox/`）
3. **什么算违规** —— 架构红线的执行参数与例外（`policy/`）
4. **这堆节点放在一起是否自洽** —— 环、不可达、能力归属、形状约束（检查器）

第 4 类是本体区别于「字段校验器」的地方：单看每个服务都合法，整张图仍可能互相矛盾。

## 目录：四层，一层一个编辑面

```
ontology/
├── manifest.ttl          本体身份与分层说明（人读；加载顺序由目录决定）
├── tbox/                 概念 —— 存在什么
│   ├── schema.ttl        类与属性的词汇层（本体的骨架）
│   ├── kinds.ttl         服务种类 + 五个行为属性
│   ├── capabilities.ttl  能力立名与归属
│   ├── decisions.ttl     决策等级与基准分（处置语义唯一真源）
│   ├── relations.ttl     关系种类、六张分域图、端点约束
│   └── terms.ttl         业务术语与概念的对应
├── abox/                 实例 —— 本平台登记了什么
│   ├── platform.ttl      平台标识、基座版本钉、服务发现
│   └── services.ttl      服务、库、边、预期状态
├── policy/               规则 —— 什么算违规
│   └── redlines.ttl      架构红线（spec 即执行参数）+ 例外登记
└── shapes/               约束 —— 图形状
    └── core.ttl          SHACL 静态约束
```

装载器按目录顺序扫描（`tbox` → `abox` → `policy`），层内按文件名字典序合并成一张图。
顺序固定是为了同一份声明每次产出相同结论。

## 为什么全是 TTL

判据一句话：**参与推理的进 TTL，纯配置的也进 TTL —— 因为"配置"同样被检查器读取，
同样会与实现漂移，却享受不到"声明即图"的好处。**

原来的分层是"图的进 TTL，`key: value` 的留 YAML"。问题是 YAML 那一半（平台配置、
红线规格、术语、决策分值）本来就参与判定，只是被排除在语义层之外：没有
`rdfs:subPropertyOf`、没有 `sh:targetClass`、没有办法跨源查询。格式一分裂，
"唯一真源"就只剩口号。

代价与对策都写明白：

| 风险 | 对策 |
|---|---|
| RDF 允许一个属性多值，原 YAML 的"重复键即失败"不再自动成立 | 装载期显式判功能属性多值（`abox.py` 管 port/repo/owner/external/health/artifact，`tbox.py` 管四个布尔、分值、归属） |
| 复数参数可能被读成字符串（遍历时逐字符匹配，永不命中） | 复数一律写 RDF 列表 `( "*.sql" )`，单数写字面量 —— **由结构决定，不靠键名猜** |
| Turtle 没有 raw string，正则里的 `\b` 会被吃掉 | 正则里的反斜杠写 `\\`；`test_policy.py` 用一条真正则守着 |
| 配置项变成字面量后失去 `grep` 便利 | 关键值保持在单行字面量上（`rcp:java "17"`），并给出对应 grep 命令 |

### 与契约仓的分工

`rcp-contracts` 只剩**接口契约**：7 份 OpenAPI、消息 schema、共享 CI 模板、对表脚本。

`contracts/schemas/decision.yaml` 是**生成物**，由 `cli.py render-schema` 从
`tbox/decisions.ttl` 产出。它存在只为一个理由：OpenAPI 需要一个能 `$ref` 的机器可读文件。
手改它会被 RL-003 判红 —— 真源不在这里。

## 语义网层：SHACL 判违规，SPARQL 提问题

- **SHACL** 是「值/关系约束」的唯一实现：依赖登记、依赖白名单、`external` 方向、
  种类/能力声明、TBox 自洽、port/contract 必填。约束来源是 `shapes/core.ttl`（静态）
  + `shapes.py`（从 `tbox/kinds.ttl` 编译，规则即数据）。
- **SPARQL 与 `graph.py` 的 BFS 是两条不同口径，两条都留**：`impact --graph <域>`
  按关系所属图分域算闭包，`sparql` 只覆盖可达性图（exporter 只为可达性图物化
  `dependsOn` 汇总边）。两者在可达性图上必须给出相同闭包，由 `tests/test_rdf.py`
  对真实登记逐服务校验；出了可达性图 SPARQL 不适用，这是分域语义的结果，不是缺陷。

不跑 OWL 推理机：`tbox/` 里的 `rdfs:subPropertyOf` 与 `owl:TransitiveProperty`
是声明，供外部工具与 SPARQL 属性路径消费；生产路径的汇总边由导出器一次性物化，
不依赖推理机跑闭包。

| 技术 | 回答的问题 | 本仓对应 | 命令 |
|---|---|---|---|
| RDF | 事实如何描述 | `exporter.py`：合并声明图 + 物化 `dependsOn` 汇总边 | `cli.py export` |
| OWL | 概念如何声明 | `tbox/` 的类、`rdfs:subPropertyOf`、`owl:TransitiveProperty` 声明 | 无（不跑推理机） |
| SHACL | 哪里违规 | `shapes/core.ttl` + `shapes.py` + `validator.py` | `cli.py shacl` |
| SPARQL | 如何提问 | `query.py`：属性路径 `dependsOn+` | `cli.py sparql` |

导出图会为每条可达性边同时产出 `rcp:calls`（类型化边）与 `rcp:dependsOn`（汇总边）。
汇总边是子属性推演的物化结果，由单一事实导出、不回写，因此不是第二份真源。
**真源里不写汇总边** —— 写进去等于把推导结论当事实。

## 用法

```bash
pip install -r requirements.txt

# 一致性检查（-w 指多仓工作区根；不给则跨仓判定输出 S001 明示跳过）
python checker/cli.py check --contracts ../rcp-contracts -w ..
python checker/cli.py check --contracts ../rcp-contracts -w .. --json

# 要求跨仓/跨源判定必须完整执行：有 S001/S003/S004 时退出码 2，防"假绿灯"
python checker/cli.py check --contracts ../rcp-contracts -w .. --require-workspace

# 架构熵基线对比：本体仓在 <ref> 处与当前的声明层结论差集（新增/消失的 error+warn）
python checker/cli.py check --contracts ../rcp-contracts -w .. --baseline origin/main

# 历史检查器看历史数据：把"数据漂移"与"规则漂移"解耦
python checker/cli.py check --contracts ../rcp-contracts -w .. \
  --baseline origin/main --checker-ref HEAD~1

# 改一个服务之前，先看它会波及谁（--graph 选域：call/data/contract/build/deploy/governance）
python checker/cli.py impact --service dataway
python checker/cli.py impact --service dataway --graph data

# 我们到底建模了哪些关系、哪些还只是立了名没有实例
python checker/cli.py relations

# 按 owner 生成 CODEOWNERS（让归属落到审批上）
python checker/cli.py owners --org your-org --out .github/CODEOWNERS

# 渲染服务目录（生成物，勿手改）
python checker/cli.py render --out SERVICES.md

# 由真源生成契约层的决策 schema（生成物，勿手改）
python checker/cli.py render-schema --contracts ../rcp-contracts

# 语义网层
python checker/cli.py export --out /tmp/services.ttl
python checker/cli.py shacl
python checker/cli.py sparql --service dataway

# 测试（正向闭合 + 每条约束各一条反例）
python -m pytest -q
```

`--ontology` 默认就是本仓，在本仓里跑不必写。契约仓只在需要判「契约文件是否存在」
与生成决策 schema 时才需要，不给则输出 `S004` 说明跳过。

## 检查项

两条轨：**SHACL（声明式）** 承担能表达为「值/关系约束」的检查；**Python（过程式）**
承担 SHACL 表达不了的 —— 键存在性、唯一键、跨源比对、文件扫描、图连通性、红线元检查。

### 结构与归属

| 编号 | 判据 | 承担 | 级别 |
|---|---|---|---|
| E001 | 服务缺必填字段（name/repo/kind/external/owner/capabilities，port 视 `requiresPort`） | Python + SHACL | error |
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
| E109 | 非入口节点入度为 0（命中 `expected.noDependents` 且未过期则静默） | Python | warn |
| E110 | 从任何对外入口都不可达（命中 `expected.unreachable` 且未过期则静默） | Python | warn |
| E111 | 能力的 owner 未在 services/libraries 登记 | Python | error |
| E112 | 能力的 owner 并未声明持有该能力 | Python | error |
| E113 | TBox 内部悬空：`allowsDependsOn` 引用未声明种类，或缺显式布尔属性 | SHACL | error |
| E114 | 能力名不符合点分小写规范（如 `Patrol_Dispatch`） | Python | error |
| E115 | `expected` 预期状态声明不合法 | Python | error |
| W306 | `expected` 声明与事实不符（过时声明应移除） | Python | warn |

### 关系与公理

| 编号 | 判据 | 承担 | 级别 |
|---|---|---|---|
| E116 | 登记里的边使用了未在 `tbox/relations.ttl` 声明的关系名 | Python | error |
| E117 | 边的目标种类不符合该关系声明的 `targetKind` | Python | error |
| E118 | 关系未声明所属图，或引用了未声明的图 | Python | error |
| W307 | 关系标 `enforced` 但登记里零实例（判定空转） | Python | warn |
| S002 | 关系层不可用，关系级判定未执行（明示跳过） | Python | info |

### 红线与元检查

| 编号 | 判据 | 承担 | 级别 |
|---|---|---|---|
| E301 | 红线声明但无 `spec` 规格（纸面红线） | Python | error |
| E302 | 红线的 `spec` 不合法（type 未知 / 缺必填字段 / 正则无法编译） | Python | error |
| S001 | 跨仓检查未完整执行（只检出单仓），明示跳过 | Python | info |
| S003 | RL-003 的对端不在工作区，跨源比对未执行 | Python | info |
| S004 | 未指定契约仓，RL-006 的「契约文件是否存在」未执行 | Python | info |
| RL-001 | 巡查线互相调用 | SHACL | error |
| RL-002 | 对外入口不是网关/前端，或网关未对外 | SHACL | error |
| RL-003 | 决策语义三方不一致：`decisions.ttl`（真源）、`Decision.java`（实现）、生成的 `decision.yaml`（生成物） | Python | error |
| RL-004 | `rcp-ops/migrations` 之外出现 DDL | Python | error |
| RL-005 | 业务服务或基座引入了 JDBC 驱动 | Python | error |
| RL-006 | 服务未挂契约或契约文件不存在 | SHACL + Python | error |
| RL-007 | 部署清单写死内部服务地址；命中例外降为 warn，例外过期转回 error | Python | error/warn |

### 已裁剪的检查

| 编号 | 原判据 | 移除原因 |
|---|---|---|
| W301 | capability 立名但无服务使用 | 真源唯一，立名即被引用 |
| W303 | 种类未在术语表立名 | 术语与结构约束职责重叠，`tbox/kinds.ttl` 已唯一承载种类 |
| W304 | 能力除 owner 外还有别的实现者 | 单 owner 契约模型下不存在多实现 |

## 三条设计约定

**1. 不可判就明说跳过，不假装通过。** 跨仓检查（RL-004/005/007、E107 的缺失方向）
与跨源比对（RL-003）需要多仓同处一个工作区。单仓 CI 里输出 `S001`/`S003`/`S004`
说明哪些判定没有执行；`--require-workspace` 把它们升级为失败。这样"绿灯"的含义是确定的。

**2. 同一事实只能有一个值。** TTL 没有"重复键"这回事，所以功能属性的多值在装载期
显式报错。失败要更早、更具体，而不是让"文件里写的"与"程序读到的"不一致。

**3. worktree 不算独立仓。** `.git` 是文件且首行以 `gitdir:` 开头的目录被识别为
worktree，不参与"未登记仓"判定，也不会被重复扫描。

## 边界

本仓**只判机械事实**：结构、归属、红线、枚举逐字一致、DDL 与 JDBC 的落位、
上游地址是否写死、图的连通性。像"这个需求是否被完整覆盖""这个裁决是否合理"
属于语义判断，由主会话对照原文完成，不由本检查器宣称闭合。
差集为空 ≠ 需求无遗漏，只说明索引闭合。

判定的强弱之分：

- **强**：结构完整、枚举一致、DDL/JDBC 落位、依赖种类越界 —— 违反即确定有错
- **弱**：入度为 0、不可达、关系零实例 —— 只能提示"这里值得看一眼"，
  不能断定是错（例如 dataway / db-ops 入度为 0 是因为数据面尚未启用）
