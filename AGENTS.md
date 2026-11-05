# AGENTS.md · rcp-ontology

本仓规则。工作区级流程见 `<工作区根>/AGENTS.md`。

## 本仓是什么

**声明层唯一真源** + 检查器。`ontology/` 下的四层 TTL 是全部事实，本仓不再从任何
别处读登记：契约仓只剩 OpenAPI 与一份生成的决策 schema。

## 硬约束

1. **只有 TTL。** `ontology/` 下不放 YAML/JSON。真源格式一旦分裂，"唯一"就是口号。
   需要给 OpenAPI 用的机器可读形态，用 `cli.py render-schema` 生成到契约仓，并在文件头
   标"生成物，勿手改"。

2. **目录即层，别新建第五层。** `tbox/`（概念）→ `abox/`（实例）→ `policy/`（规则）
   → `shapes/`（约束）。新文件放对应层；依赖方向只允许 `abox → tbox`，不允许反向。
   装载顺序由目录与文件名决定，固定下来才能让同一份声明每次产出相同结论。

3. **概念变更必须先于实例。** 要新增服务种类或能力，先在 `tbox/` 立名并说明语义，
   再允许 `abox/` 登记对应实例；顺序反了就是"先上车后补票"，E201/E202 会红。

4. **决策语义只改一处。** 改 `tbox/decisions.ttl`，然后重跑
   `cli.py render-schema` 更新契约层生成物，再改 `rcp-core` 的 `Decision`。
   三者不一致即 RL-003。**不要手改 `decision.yaml`** —— 它是生成物。

5. **检查器只报机械事实。** 不新增"看起来是否合理"的启发式判断；分数、置信度这类
   不可复核的东西不进检查结论。

6. **生成物不入库手改。** `SERVICES.md`、`CODEOWNERS`、`decision.yaml` 都是渲染产物，
   改真源后重跑命令。

7. **关系先立名再使用，且必须落在一张图上。** 新增关系只改 `tbox/relations.ttl`：
   给 `rcp:RelationKind` 加一条、显式写 `rcp:graph`、`rcp:status`，参与可达性才加
   `rdfs:subPropertyOf rcp:dependsOn`。登记里出现未声明的关系名即 E116；关系不落在
   已声明的图上即 E118。**不要在 Python 里硬编码关系名** —— `service_relations` 是
   唯一的规范化入口。

8. **复数参数写 RDF 列表。** `rcp:include ( "*.sql" )` 而不是 `rcp:include "*.sql"`。
   装载器按图结构决定"单值还是列表"，一旦写成单值，消费者遍历时会逐字符匹配 ——
   不报错，但永远不命中。

## 验证

```bash
python -m pytest -q
python rcp_ontology/cli.py check --contracts ../rcp-contracts -w ..
```

反向用例必须覆盖每条红线：新增一条 rule 就要配一条反例测试，否则规则等于没验证过。
`tests/test_policy.py` 额外守着一条容易静默失败的路径 —— Turtle 里的正则转义。
