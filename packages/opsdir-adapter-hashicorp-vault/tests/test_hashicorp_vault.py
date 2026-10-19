"""The HashiCorp Vault adapter as the core sees it: a registered secret store that renders nothing and resolves
vault:// references."""
import shlex
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS, secret_command
from opsdir_adapter_hashicorp_vault.adapter import ADAPTER

# A reference holding every character a shell treats specially (no slash: each split part takes it whole)
HOSTILE = "it's \"x\" $(touch made) `touch made` ${HOME}; touch made | cat & echo"


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "secret-store"


def test_never_renders_for_an_environment():
    assert not ADAPTER.applies(SimpleNamespace(provider="any")) and ADAPTER.render_env is None


def test_resolves_vault_references_through_the_registry():
    assert ADAPTER.ref_schemes == ("vault",)
    assert secret_command("vault://secret/ds/root", (ADAPTER,)) == "vault kv get -field=value secret/ds/root"


def test_a_reference_is_one_argument_whatever_it_holds():
    assert shlex.split(secret_command(f"vault://secret/{HOSTILE}", (ADAPTER,))) == [
        "vault", "kv", "get", "-field=value", f"secret/{HOSTILE}"]
