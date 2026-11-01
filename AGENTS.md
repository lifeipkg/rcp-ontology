# AGENTS.md · rcp-ontology

本仓规则。工作区级流程见 `<工作区根>/AGENTS.md`。

## 本仓是什么

概念层（TBox）+ 检查器。**只读其他仓，不写其他仓**：本仓没有权限改契约仓的登记，也不参与业务实现。

## 硬约束

1. **概念变更必须先于实例。** 要新增服务种类或能力，先在 `concepts/` 立名并说明语义，再允许契约仓登记对应实例；顺序反了就是"先上车后补票"，E201/E202 会红。
2. **决策语义只能改一处。** `concepts/decisions.yaml` 与 `rcp-contracts/contracts/schemas/decision.yaml`、`rcp-core` 的 `Decision` 必须同批改，三者不一致即 RL-003。
3. **检查器只报机械事实。** 不新增"看起来是否合理"的启发式判断；分数、置信度这类不可复核的东西不进检查结论。
4. **生成物不入库手改。** `SERVICES.md` 是渲染产物，改真源后重跑 render。

## 验证

```bash
python -m pytest -q
python rcp_ontology/cli.py check --contracts ../rcp-contracts
```

反向用例必须覆盖每条红线：新增一条 rule 就要配一条反例测试，否则规则等于没验证过。
