"""Render targets chosen at render time (`opsdir render --target ADAPTER=T[,T]`) or by the environment's stack
(ciamRenderTarget): every target of every adapter that declares some by default, the stack's choice over that, a
render's own over both, an adapter or target that isn't there refused with what is; the command line's form
checked."""
from types import SimpleNamespace

import pytest

from opsdir.cli import render_targets
from opsdir.connectors.render import chosen_targets
from opsdir.core.environment import StackComponent

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


def test_the_user_chooses_unless_the_environment_holds_a_form():
    stack = (StackComponent("platform", "pingfederate", None, None, ("terraform",)),
             StackComponent("other", "pingfederate", None, None, ("terraform-imports",)),
             StackComponent("provider", "aws", None, None))
    assert chosen_targets((PF, PLAIN), stack=stack) == {"pingfederate": ("terraform", "terraform-imports")}
    assert chosen_targets((PF, PLAIN), {"pingfederate": ("terraform",)}, stack) == {"pingfederate": ("terraform",)}
    assert chosen_targets((PF, PLAIN), stack=stack[2:]) == {"pingfederate": ("admin-api", "terraform")}
    assert chosen_targets((PF, PLAIN), {"pingfederate": ("admin-api",)}, stack[2:]) == {"pingfederate": ("admin-api",)}
    with pytest.raises(SystemExit, match=r"the environment holds its render form \(pingfederate: terraform, "
                                         r"terraform-imports; its stack's ciamRenderTarget\): it can't be rendered "
                                         r"as pingfederate=admin-api"):
        chosen_targets((PF, PLAIN), {"pingfederate": ("admin-api",)}, stack)


def test_a_stack_choosing_what_its_adapter_doesnt_declare_is_refused():
    with pytest.raises(SystemExit, match=r"unknown render targets in the environment's stack "
                                         r"\(run `opsdir check`\): pingfederate=bulk"):
        chosen_targets((PF,), stack=(StackComponent("platform", "pingfederate", None, None, ("bulk",)),))
    with pytest.raises(SystemExit, match=r"no render targets to choose for aws in the environment's stack"):
        chosen_targets((PF, PLAIN), stack=(StackComponent("provider", "aws", None, None, ("cloudformation",)),))


def test_the_command_line_form():
    assert render_targets(["pingfederate=admin-api,terraform", "x=y"]) == {
        "pingfederate": ("admin-api", "terraform"), "x": ("y",)}
    assert render_targets([]) == {}
    with pytest.raises(SystemExit, match="--target takes ADAPTER=TARGET"):
        render_targets(["pingfederate"])
