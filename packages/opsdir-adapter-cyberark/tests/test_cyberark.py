"""The CyberArk adapter as the core sees it: a registered secret store that renders nothing and resolves cyberark://
references."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS, secret_command
from opsdir_adapter_cyberark.adapter import ADAPTER


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "secret-store"


def test_never_renders_for_an_environment():
    assert not ADAPTER.applies(SimpleNamespace(provider="any")) and ADAPTER.render_env is None


def test_resolves_vaulted_passwords_through_the_registry():
    assert ADAPTER.ref_schemes == ("cyberark",)
    assert secret_command("cyberark://ciam-ops/CIAM-PROD/ds-root", (ADAPTER,)) == (
        "clipasswordsdk GetPassword -p AppDescs.AppID='ciam-ops' -p Query='Safe=CIAM-PROD;Object=ds-root' "
        "-o Password")
