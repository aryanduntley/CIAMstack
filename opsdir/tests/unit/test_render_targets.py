"""Render targets chosen at render time (`opsdir render --target ADAPTER=T[,T]`): every target of every adapter that
declares some by default, a subset when asked, an adapter or target that isn't there refused with what is; the
command line's form checked."""
from types import SimpleNamespace

import pytest

from opsdir.cli import render_targets
from opsdir.connectors.render import chosen_targets

PF = SimpleNamespace(name="pingfederate", render_targets=(("admin-api", "requests"), ("terraform", "Terraform"),
                                                         ("terraform-imports", "import blocks", False)))
PLAIN = SimpleNamespace(name="aws", render_targets=())


def test_every_target_by_default_and_a_subset_when_asked():
    assert chosen_targets((PF, PLAIN)) == {"pingfederate": ("admin-api", "terraform")}
    assert chosen_targets((PF, PLAIN), {"pingfederate": ("terraform",)}) == {"pingfederate": ("terraform",)}
    assert chosen_targets((PF,), {"pingfederate": ("terraform", "terraform-imports")}) == {      # only when asked
        "pingfederate": ("terraform", "terraform-imports")}


def test_an_adapter_or_target_that_isnt_there_is_refused_with_what_is():
    with pytest.raises(SystemExit, match=r"no render targets to choose for aws here \(adapters with targets: "
                                         r"pingfederate\)"):
        chosen_targets((PF, PLAIN), {"aws": ("terraform",)})
    with pytest.raises(SystemExit, match=r"unknown render targets: pingfederate=bulk \(it renders: admin-api, "
                                         r"terraform, terraform-imports\)"):
        chosen_targets((PF,), {"pingfederate": ("bulk",)})


def test_the_command_line_form():
    assert render_targets(["pingfederate=admin-api,terraform", "x=y"]) == {
        "pingfederate": ("admin-api", "terraform"), "x": ("y",)}
    assert render_targets([]) == {}
    with pytest.raises(SystemExit, match="--target takes ADAPTER=TARGET"):
        render_targets(["pingfederate"])
