"""语义网层的命名空间出口。

真源已上移到 ``rcp_ontology/namespaces.py``：关系层（``relations.py``）需要读同一个
IRI，若它反过来依赖 semweb 包，会与 semweb → exporter → relations 形成导入环。
本模块只做转出，保持 ``from .namespaces import RCP`` 的既有引用不变。
"""

from ..namespaces import RCP

__all__ = ["RCP"]
