"""语义网命名空间定义。

rdflib 自带 RDF / RDFS / OWL / XSD / SH 等 W3C 标准命名空间，本模块只定义
平台本体的私有命名空间 rcp。所有类、属性、实例都挂在 rcp 之下。

用 https IRI 而非 urn：将来若要跨系统对齐同一套"服务/能力/种类"概念，
IRI 可作为全局唯一标识对外发布。

放在包根：relations / abox / tbox 这些底层模块都要读同一个 IRI，集中一处才不会让
「谁 Import 谁」变成环。
"""

from rdflib import Namespace

# 平台本体命名空间。
RCP = Namespace("https://risk-control.platform/ontology#")
