"""The Azure adapter as the core sees it: registered, chosen from data, owning its vocabulary and secret scheme.
Its Terraform is exercised end to end by the showcase (examples/showcase golden outputs)."""
import shlex
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir_adapter_azure.adapter import ADAPTER
from opsdir_adapter_azure.secrets import keyvault_command

# A reference holding every character a shell treats specially (no slash: each split part takes it whole)
HOSTILE = "it's \"x\" $(touch made) `touch made` ${HOME}; touch made | cat & echo"


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "provider"


def test_applies_to_its_provider_only():
    assert ADAPTER.applies(SimpleNamespace(provider="azure")) and not ADAPTER.applies(SimpleNamespace(provider="aws"))


def test_owns_its_vocabulary_and_reference_schemes():
    assert ADAPTER.vocabulary["ciamCloudProvider"] == ("azure",)
    assert set(ADAPTER.vocabulary["ciamCloudEnvironment"]) == {"public", "usgovernment"}
    assert (set(ADAPTER.ref_schemes) == {"azkv", "azkv-key", "azkv-cert", "azblob"}
            and set(ADAPTER.secret_schemes) == {"azkv"})


def test_secret_references_resolve_with_the_azure_cli():
    assert keyvault_command("kv-prod/ds-root") == ("az keyvault secret show --vault-name kv-prod --name ds-root "
                                                   "--query value -o tsv")


def test_the_vault_and_the_name_are_one_argument_each_whatever_they_hold():
    assert shlex.split(keyvault_command(f"{HOSTILE}/{HOSTILE}/more")) == [
        "az", "keyvault", "secret", "show", "--vault-name", HOSTILE, "--name", f"{HOSTILE}/more", "--query", "value",
        "-o", "tsv"]
