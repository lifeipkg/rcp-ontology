"""语义网层：用 W3C RDF / OWL / SHACL / SPARQL 重新审视本体仓。

四件套分工：

    exporter  —— RDF：YAML 声明 → 三元组图（L1，数据模型）
    reasoner  —— OWL：传递依赖的推理闭包（L2，从已知推未知）
    validator —— SHACL：图形状约束验证（L3，找违规）
    query     —— SPARQL：属性路径图查询（L4，问问题）

本层与现有 YAML + checks.py 是"双轨对照"而非替代：YAML 仍是真源，
语义网层是它的图形态，交叉验证同一结论（见 tests/test_semweb.py）。
"""

from .exporter import build_rdf, kind_class
from .namespaces import RCP
from .query import dependencies_of as sparql_dependencies_of
from .query import dependents_of as sparql_dependents_of
from .reasoner import dependencies_of as inferred_dependencies_of
from .reasoner import dependents_of as inferred_dependents_of
from .reasoner import infer_transitive, local_name
from .validator import ShaclFinding, validate

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
    "ShaclFinding",
    "validate",
]
