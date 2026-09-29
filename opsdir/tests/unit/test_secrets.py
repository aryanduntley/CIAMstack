"""Secret material as data: every registered pattern is usable by the store, trips on its secrets and leaves ordinary
values alone; redaction; the registry's patterns and their owners."""
import pytest

from opsdir.connectors.registry import ADAPTERS, secret_patterns
from opsdir.core.contract import SecretPattern
from opsdir.core.secrets import CORE_PATTERNS, dialect_problems, redact, scan, value_findings
from mini_estate import FAKE
from secret_samples import CLEAN, SECRETS

ALL = tuple(p for p in CORE_PATTERNS) + tuple(p for a in ADAPTERS for p in a.secret_patterns)


def test_every_registered_pattern_is_in_the_shared_dialect():
    assert dialect_problems(ALL) == ()


@pytest.mark.parametrize("text, name", SECRETS)
def test_secret_material_trips_its_pattern(text, name):
    assert name in scan(text, ALL)


@pytest.mark.parametrize("text", CLEAN)
def test_ordinary_values_and_references_pass(text):
    assert scan(text, ALL) == ()


@pytest.mark.parametrize("pattern, problem", [
    (r"\bkey\b", r"uses \b"),
    (r"key(?=s)", "uses (?="),
    (r"(?P<k>key)", "uses (?P"),
    (r"key(?i)s", "inline flags only as a leading (?i)"),
    (r"key[", "unterminated character set"),
])
def test_patterns_the_store_cant_evaluate_are_reported(pattern, problem):
    found = dialect_problems((SecretPattern("p", pattern, "d"),))
    assert found and all(f.startswith("p: ") for f in found) and any(problem in f for f in found)


def test_a_name_registered_twice_is_reported():
    p = SecretPattern("p", "x", "d")
    assert dialect_problems((p, p)) == ("p: registered twice",)


def test_value_findings_name_the_attribute_and_pattern_never_the_value():
    attrs = {"description": ("see db.password=changeit",), "cn": ("svc",)}
    assert value_findings("cn=svc,dc=x", attrs, ALL) == (("cn=svc,dc=x", "description", "secret-assignment"),)


def test_redaction_keeps_the_text_around_the_secret():
    assert redact("url ldaps://cn=admin:hunter22@ds.example.test:1636 ok", ALL) == \
        "url [redacted: url-credentials]ds.example.test:1636 ok"


def test_the_registry_owns_each_pattern_and_refuses_unusable_ones():
    rows = secret_patterns((FAKE, *ADAPTERS))
    assert ("private-key", "opsdir") in [(name, owner) for name, _, owner, _ in rows]
    assert ("vault-token", "hashicorp-vault") in [(name, owner) for name, _, owner, _ in rows]
    bad = FAKE._replace(secret_patterns=(SecretPattern("fake-key", r"\bfk-", "d"),))
    with pytest.raises(SystemExit, match=r"fake-key: uses \\b"):
        secret_patterns((bad,))
