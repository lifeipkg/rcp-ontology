# rcp-ontology · 本体仓

平台**概念层**（TBox）与一致性检查器。回答两个问题：平台上有哪些种类的东西（服务/能力/决策语义），以及登记的东西是否都还在概念范围内。

## 什么是 TBox、什么是 ABox（本仓口径）

- **TBox（本仓 `concepts/`）**：种类（gateway / patrol-line / data-gateway / db-ops / frontend）、能力立名、决策等级语义。不带具体服务名。
- **ABox（契约仓 `registry/services.yaml`）**：具体服务实例、端口、依赖。
- 契约层（`rcp-contracts/contracts/`）：界面与结构的机器可读形态。

三者必须闭合：ABox 里出现的每个 kind 与 capability 都要在 TBox 声明；决策枚举要三方逐字一致。

## 用法

```bash
pip install -r requirements.txt

# 一致性检查（在任意目录跑均可，参数指向契约仓）
python rcp_ontology/cli.py check --contracts ../rcp-contracts
python rcp_ontology/cli.py check --contracts ../rcp-contracts --json

# 含仓布局级红线（RL-004 / RL-005 / RL-007）：--workspace 指向多仓工作区根
python rcp_ontology/cli.py check --contracts ../rcp-contracts --workspace ..

# 渲染服务目录（生成物，勿手改）
python rcp_ontology/cli.py render --contracts ../rcp-contracts --out SERVICES.md

# 测试（正向闭合 + 反向每个红线各一条反例）
python -m pytest -q
```

## 检查项

| 编号 | 判据 | 级别 |
|---|---|---|
| E001 | 服务缺必填字段（name/repo/kind/port/external/owner/capabilities） | error |
| E002 | 服务重名或端口冲突 | error |
| E105 | 依赖了未登记的服务 | error |
| E106 | 依赖了种类规则不允许的种类（非巡查线互调） | error |
| E201 | kind 未在 TBox 声明 | error |
| E202 | capability 未在 TBox 立名 | error |
| E301 | 红线在 `redlines.yaml` 声明但检查器无实现（纸面红线） | error |
| W301 | capability 立名但无服务使用 | warn |
| W302 | 红线有实现但未在 `redlines.yaml` 登记 | warn |
| RL-001 | 巡查线互相调用 | error |
| RL-002 | 对外入口不是网关/前端，或网关未对外 | error |
| RL-003 | 决策枚举在契约层与本体层不一致 | error |
| RL-004 | `rcp-ops/migrations` 之外出现 DDL | error |
| RL-005 | 业务服务或基座引入了 JDBC 驱动 | error |
| RL-006 | 服务未挂契约或契约文件不存在 | error |
| RL-007 | 部署清单写死内部服务地址；命中已登记例外降为 warn，例外过期转回 error | error/warn |

## 边界

本仓**只判机械事实**：结构、红线、枚举逐字一致、DDL 与 JDBC 的落位、上游地址是否写死。
像"这个需求是否被完整覆盖""这个裁决是否合理"属于语义判断，由主会话对照原文完成，
不由本检查器宣称闭合。差集为空≠需求无遗漏，只说明索引闭合。

仓布局类检查（RL-004/005/007）只做文本与结构判定：不解析 Java 语义、不连集群、
不判断"能否运行"。因此它们能证明"没有明显越界"，不能证明"运行一定正确"。
