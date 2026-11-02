"""语义网层：用 W3C RDF / OWL / SHACL / SPARQL 重新审视本体仓。

四件套分工：

    exporter  —— RDF：YAML 声明 → 三元组图（L1，数据模型）
    reasoner  —— OWL：传递依赖的推理闭包（L2，从已知推未知）
    validator —— SHACL：图形状约束验证（L3，找违规，已取代部分 checks.py）
    query     —— SPARQL：属性路径图查询（L4，问问题）

YAML 仍是真源，RDF 是它的图形态。SHACL 是「值/关系约束」的**唯一实现**（依赖登记、
依赖白名单、external 方向、种类/能力声明、TBox 自洽、命名、port/contract 必填），
OWL/SPARQL 与 graph.py 的 BFS 交叉验证依赖闭包（见 tests/test_semweb.py）。
"""

from .exporter import build_rdf, kind_class
from .namespaces import RCP
from .query import dependencies_of as sparql_dependencies_of
from .query import dependents_of as sparql_dependents_of
from .reasoner import dependencies_of as inferred_dependencies_of
from .reasoner import dependents_of as inferred_dependents_of
from .reasoner import infer_transitive, local_name
from .shapes import build_shapes_graph
from .validator import ShaclFinding, validate_all

__all__ = [
    "RCP",
    "build_rdf",
    "kind_class",
    "infer_transitive",
    "local_name",
    "inferred_dependencies_of",
    "inferred_dependents_of",
    "sparql_dependencies_of",
    "sparql_dependents_of",
    "build_shapes_graph",
    "ShaclFinding",
    "validate_all",
]
