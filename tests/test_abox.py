"""ABox 层（ontology/abox/）：还原规则与严格性。

每条还原规则都配一条反例——只测"能读对"不测"读错会报"，等于没有护栏。
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from rcp_ontology.loader import LoadError, load_registry
from rdflib import Graph

from rcp_ontology.abox import AboxError, parse_abox

HEADER = """\
@prefix rcp:  <https://risk-control.platform/ontology#> .
@prefix xsd:  <http://www.w3.org/2001/XMLSchema#> .
"""


PLATFORM = """\
rcp:platform a rcp:Platform ;
    rcp:registrySchema "rcp.registry/v2" ;
    rcp:platformName "risk-control-platform" .
"""


def write_ttl(tmp_path: Path, body: str, *, platform: bool = False) -> Path:
    """把夹具写进 ontology/abox/：平台配置与实例登记是两个文件，同层合并。"""
    layer = tmp_path / "ontology" / "abox"
    layer.mkdir(parents=True, exist_ok=True)
    text = HEADER + PLATFORM
    if platform:
        text += 'rcp:platform rcp:stack [ rcp:java "17" ] .\n'
    (layer / "platform.ttl").write_text(text, encoding="utf-8")
    (layer / "services.ttl").write_text(HEADER + body, encoding="utf-8")
    return tmp_path


def _parse(path: Path):
    return parse_abox(Graph().parse(path, format="turtle"), path.name)


def test_service_attributes_kind_and_edges(tmp_path: Path) -> None:
    root = write_ttl(
        tmp_path,
        """
rcp:api-gateway
    a rcp:Gateway, rcp:Service ;
    rcp:repo "rcp-api-gateway" ;
    rcp:port 8080 ;
    rcp:external true ;
    rcp:owner "platform" ;
    rcp:health "/actuator/health" ;
    rcp:hasCapability rcp:patrol.dispatch ;
    rcp:contract "contracts/openapi/api-gateway.yaml" ;
    rcp:calls rcp:content-patrol .
""",
    )
    registry = load_registry(root)
    service = registry["services"][0]
    assert service["name"] == "api-gateway"
    assert service["kind"] == "gateway"  # 类名 Gateway -> kind gateway
    assert service["port"] == 8080
    assert service["external"] is True
    assert service["health"] == "/actuator/health"
    assert service["capabilities"] == ["patrol.dispatch"]
    assert service["contracts"] == ["contracts/openapi/api-gateway.yaml"]
    # 具体关系边，不产出 depends_on 汇总边
    assert service["relations"] == {"calls": ["content-patrol"]}


def test_kind_kebab_conversion(tmp_path: Path) -> None:
    root = write_ttl(
        tmp_path,
        """
rcp:a a rcp:PatrolLine, rcp:Service ; rcp:repo "r" ; rcp:external false ; rcp:owner "o" .
rcp:b a rcp:DbOps, rcp:Service ; rcp:repo "r2" ; rcp:external false ; rcp:owner "o" .
""",
    )
    kinds = {s["name"]: s["kind"] for s in load_registry(root)["services"]}
    assert kinds == {"a": "patrol-line", "b": "db-ops"}


def test_expected_block(tmp_path: Path) -> None:
    root = write_ttl(
        tmp_path,
        """
rcp:dataway
    a rcp:DataGateway, rcp:Service ;
    rcp:repo "rcp-dataway" ;
    rcp:external false ;
    rcp:owner "platform" ;
    rcp:expected [
        rcp:noDependents true ;
        rcp:unreachable true ;
        rcp:reason "尚未启用" ;
        rcp:owner "platform" ;
        rcp:reviewBy "2027-03-31"^^xsd:date
    ] .
""",
    )
    expected = load_registry(root)["services"][0]["expected"]
    assert expected == {
        "no_dependents": True,
        "unreachable": True,
        "reason": "尚未启用",
        "owner": "platform",
        "review_by": "2027-03-31",
    }


def test_library_is_not_a_service(tmp_path: Path) -> None:
    root = write_ttl(
        tmp_path,
        """
rcp:rcp-core
    a rcp:Library ;
    rcp:repo "rcp-core" ;
    rcp:artifact "com.risk.platform:rcp-core:1.0.0" ;
    rcp:owner "platform" ;
    rcp:hasCapability rcp:rule.engine .
""",
    )
    registry = load_registry(root)
    assert registry["services"] == []
    assert registry["libraries"][0]["artifact"] == "com.risk.platform:rcp-core:1.0.0"


def test_duplicate_functional_property_fails(tmp_path: Path) -> None:
    """RDF 允许多值，功能属性多值必须显式报错——这是 YAML 重复键护栏的等价物。"""
    root = write_ttl(
        tmp_path,
        """
rcp:a a rcp:PatrolLine, rcp:Service ;
    rcp:repo "r" ; rcp:owner "o" ; rcp:external false ;
    rcp:port 8080, 9090 .
""",
    )
    with pytest.raises(LoadError) as exc:
        load_registry(root)
    assert "port" in str(exc.value) and "2 个值" in str(exc.value)


def test_missing_kind_fails(tmp_path: Path) -> None:
    root = write_ttl(tmp_path, 'rcp:a rcp:repo "r" ; rcp:owner "o" ; rcp:external false .\n')
    with pytest.raises(LoadError) as exc:
        load_registry(root)
    assert "未声明种类" in str(exc.value)


def test_relation_target_must_be_iri(tmp_path: Path) -> None:
    root = write_ttl(
        tmp_path,
        'rcp:a a rcp:PatrolLine, rcp:Service ; rcp:repo "r" ; rcp:owner "o" ; rcp:external false ; rcp:calls "b" .\n',
    )
    with pytest.raises(LoadError) as exc:
        load_registry(root)
    assert "目标不是实例 IRI" in str(exc.value)


def test_yaml_leftovers_in_layer_are_ignored(tmp_path: Path) -> None:
    """ABox 层只读 .ttl：目录里残留的 YAML 不会被当成声明，也不会盖过真源。

    真源搬家之后，"两个文件同时说是真源"这种状态必须无法表达——只扫 *.ttl
    就是这句话的机械实现。
    """
    root = write_ttl(
        tmp_path,
        'rcp:from-ttl a rcp:PatrolLine, rcp:Service ; rcp:repo "r" ; rcp:owner "o" ; rcp:external false .\n',
    )
    (root / "ontology" / "abox" / "services.yaml").write_text(
        textwrap.dedent(
            """
            services:
              - name: from-yaml
                repo: r
                kind: patrol-line
                external: false
                owner: o
                capabilities: []
            """
        ),
        encoding="utf-8",
    )
    assert [s["name"] for s in load_registry(root)["services"]] == ["from-ttl"]


def test_platform_config_is_merged(tmp_path: Path) -> None:
    """平台配置与实例登记同层不同文件，装载后是同一份视图。"""
    root = write_ttl(
        tmp_path,
        'rcp:a a rcp:PatrolLine, rcp:Service ; rcp:repo "r" ; rcp:owner "o" ; rcp:external false .\n',
        platform=True,
    )
    registry = load_registry(root)
    assert registry["platform"] == "risk-control-platform"
    assert registry["baseline_stack"] == {"java": "17"}
    assert registry["schema"] == "rcp.registry/v2"


def test_broken_turtle_is_load_error(tmp_path: Path) -> None:
    """语法错误必须变成"声明不可用"，不能让人以为检查通过了。"""
    layer = tmp_path / "ontology" / "abox"
    layer.mkdir(parents=True)
    (layer / "services.ttl").write_text("rcp:a a rcp:Service ; ;", encoding="utf-8")
    with pytest.raises(LoadError):
        load_registry(tmp_path)
