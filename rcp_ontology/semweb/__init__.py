"""语义网层：用 W3C RDF / SHACL / SPARQL 重新审视本体仓。

三件套分工：

    exporter  —— RDF：声明图 → 可查询的三元组图（L1，数据模型）
    validator —— SHACL：图形状约束验证（L3，找违规，已取代部分 checks.py）
    query     —— SPARQL：属性路径图查询（L4，问问题）

TTL 是唯一真源，导出图是它物化汇总边后的形态（不回写，因此不是第二份真源）。
SHACL 是「值/关系约束」的**唯一实现**（依赖登记、依赖白名单、external 方向、
种类/能力声明、TBox 自洽、命名、port/contract 必填）。

SPARQL 与 graph.py 的 BFS 是两条**不同口径**，不是同一结论的重复实现，因此都在：
    graph.py  BFS       —— 按关系所属图分域计算，支持 impact --graph <域>
    query.py  dependsOn+ —— 只算可达性图，语义等价于「可达性域上的 impact」

差别的来源是 exporter 只为可达性图物化 dependsOn 汇总边（非可达性图按设计只产出
typed 边，其边不得进入可达性计算）。两者在可达性图上的结论必须一致，由
tests/test_semweb.py 对真实登记逐服务校验。
"""

from ..namespaces import RCP
from .exporter import build_rdf, kind_class
from .query import dependencies_of as sparql_dependencies_of
from .query import dependents_of as sparql_dependents_of
from .shapes import build_shapes_graph
from .validator import ShaclFinding, validate_all

__all__ = [
    "RCP",
    "build_rdf",
    "kind_class",
    "sparql_dependencies_of",
    "sparql_dependents_of",
    "build_shapes_graph",
    "ShaclFinding",
    "validate_all",
]
