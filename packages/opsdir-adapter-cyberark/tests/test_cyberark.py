"""The CyberArk adapter as the core sees it: a registered secret store that renders nothing and resolves cyberark://
references."""
import shlex
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS, secret_command
from opsdir_adapter_cyberark.adapter import ADAPTER

# A reference holding every character a shell treats specially (no slash: each split part takes it whole)
HOSTILE = "it's \"x\" $(touch made) `touch made` ${HOME}; touch made | cat & echo"


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "secret-store"


def test_never_renders_for_an_environment():
    assert not ADAPTER.applies(SimpleNamespace(provider="any")) and ADAPTER.render_env is None


def test_resolves_vaulted_passwords_through_the_registry():
    assert ADAPTER.ref_schemes == ("cyberark",)
    assert secret_command("cyberark://ciam-ops/CIAM-PROD/ds-root", (ADAPTER,)) == (
        "clipasswordsdk GetPassword -p AppDescs.AppID=ciam-ops -p 'Query=Safe=CIAM-PROD;Object=ds-root' "
        "-o Password")


def test_the_application_and_the_query_are_one_argument_each_whatever_they_hold():
    assert shlex.split(secret_command(f"cyberark://{HOSTILE}/{HOSTILE}/{HOSTILE}/x", (ADAPTER,))) == [
        "clipasswordsdk", "GetPassword", "-p", f"AppDescs.AppID={HOSTILE}", "-p",
        f"Query=Safe={HOSTILE};Object={HOSTILE}/x", "-o", "Password"]
