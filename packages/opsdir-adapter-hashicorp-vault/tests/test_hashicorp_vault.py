"""The HashiCorp Vault adapter as the core sees it: a registered secret store that renders nothing and resolves
vault:// references."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS, secret_command
from opsdir_adapter_hashicorp_vault.adapter import ADAPTER


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "secret-store"


def test_never_renders_for_an_environment():
    assert not ADAPTER.applies(SimpleNamespace(provider="any")) and ADAPTER.render_env is None


def test_resolves_vault_references_through_the_registry():
    assert ADAPTER.ref_schemes == ("vault",)
    assert secret_command("vault://secret/ds/root", (ADAPTER,)) == "vault kv get -field=value 'secret/ds/root'"
