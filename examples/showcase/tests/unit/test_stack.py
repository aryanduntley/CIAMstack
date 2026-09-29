"""Declared stacks against installed adapters (pure), and `opsdir check` on the showcase."""
import pytest

from opsdir.cli import check_text
from opsdir.connectors.registry import ADAPTER_VERSIONS, ADAPTERS, applicable, environment_specs
from opsdir.connectors.stack import declared_adapters, missing_adapters, stack_rows
from opsdir.core.contract import Adapter
from opsdir.core.environment import StackComponent, env_model


def adapter(name, kind="product", applies=True):
    return Adapter(name, kind, lambda m: applies, (), None, None, (), (), {}, None, None, {}, None, (), (), ())


def component(adapter_name, role="r", versions=">=1,<2", source=None):
    return StackComponent(role, adapter_name, versions, source)


@pytest.fixture(scope="module")
def source(estate):
    return env_model(estate["before"], "source/prod")


def test_environments_declare_their_stack(estate, source):
    assert {(c.role, c.adapter) for c in source.stack} == {("provider", "aws"), ("directory", "pingds"),
                                                           ("federation", "pingfederate")}
    assert environment_specs(estate["before"]) == ("source/prod", "target/prod")


def test_the_declared_stack_decides_which_adapters_render(source):
    assert [a.name for a in declared_adapters(source, ADAPTERS)] == ["aws", "pingds", "pingfederate"]
    only_provider = source._replace(stack=(component("aws", "provider"),))
    assert [a.name for a in declared_adapters(only_provider, ADAPTERS)] == ["aws"]


def test_without_a_stack_adapters_are_inferred_from_the_data(source):
    assert [a.name for a in declared_adapters(source._replace(stack=()), ADAPTERS)] == ["aws", "pingds", "pingfederate"]


def test_rendering_refuses_a_declared_adapter_that_is_not_installed(source):
    broken = source._replace(stack=(*source.stack, component("nosuch")))
    assert [c.adapter for c in missing_adapters(broken, ADAPTERS)] == ["nosuch"]
    with pytest.raises(SystemExit, match="not installed: nosuch"):
        applicable(broken)


@pytest.mark.parametrize("stack, adapters, versions, status, problems", [
    ((component("a"),), (adapter("a"),), {"a": "1.2"}, "ok (installed 1.2)", 0),
    ((component("a", source="https://example.test/a"),), (), {}, "NOT INSTALLED; get it from https://example.test/a", 1),
    ((component("a"),), (adapter("a"),), {"a": "2.0"}, "installed 2.0, but the stack accepts >=1,<2", 1),
    ((component("a", versions="not a range"),), (adapter("a"),), {"a": "1.0"}, "installed 1.0, but the stack accepts not a range", 1),
    ((component("a"),), (adapter("a", applies=False),), {"a": "1.0"},
     "installed 1.0, but the environment's data doesn't match it (provider or products)", 1),
    ((component("v"),), (adapter("v", kind="secret-store", applies=False),), {"v": "1.0"}, "ok (installed 1.0)", 0),
])
def test_each_component_is_checked(source, stack, adapters, versions, status, problems):
    rows, n = stack_rows(source._replace(stack=stack), adapters, versions)
    assert (rows[0][3], n) == (status, problems)


def test_an_adapter_that_applies_but_is_not_declared_is_a_problem(source):
    rows, n = stack_rows(source._replace(stack=(component("a"),)), (adapter("a"), adapter("b")), {"a": "1.0", "b": "1.0"})
    assert n == 1 and rows[-1][2:] == ("b", "applies to the environment's data but is not in its stack")


def test_an_environment_without_a_stack_is_reported_not_failed(source):
    rows, n = stack_rows(source._replace(stack=()), (adapter("a"),), {})
    assert n == 0 and rows[0][3] == "no stack declared; adapters inferred from the data: a"


def test_check_passes_on_the_showcase(estate):
    text, status = check_text(estate["before"], environment_specs(estate["before"]))
    assert status == 0 and text.endswith("0 problem(s)")


def test_servers_on_product_versions_their_adapter_doesnt_support_are_problems(source):
    pingds = next(a for a in ADAPTERS if a.name == "pingds")
    assert stack_rows(source, ADAPTERS, ADAPTER_VERSIONS)[1] == 0              # 7.5.1 is inside >=7,<9
    narrowed = tuple(a._replace(products=(("PingDS", ">=8"),)) if a is pingds else a for a in ADAPTERS)
    rows, n = stack_rows(source, narrowed, ADAPTER_VERSIONS)
    assert n == 3 and rows[-1][2:] == ("pingds", "server ds-3 runs PingDS 7.5.1; pingds supports >=8")
