"""Guided onboarding's answers: one TOML document, read strictly (a typo is refused, never ignored), checked against
what is installed, written back unchanged, and turned into records that only add and set; the migration target's stack
is the source's with only what moves changed; the prompts only build the document."""
from argparse import Namespace

import pytest

from opsdir.cli import _onboard_setup, prompted_answers
from opsdir.connectors.answers import (Component, answers_notices, answers_problems, answers_toml, parse_answers,
                                       setup_records, stack_line, stack_text, target_environment)
from opsdir.connectors.importing import record_after
from opsdir.core.directory import get, one, values
from mini_estate import ADAPTER_NAME, FAKE, PROVIDER, directory

INSTALLED = (FAKE,)
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
DOCUMENT = f"""
version = 1

[record]
org = "exa"
name = "Example Aero"

[settings]
approval-separation = false

[[team]]
name = "ciam-platform"
operator = true

[[environment]]
cloud = "alpha"
env = "prod"
provider = "{PROVIDER}"
region = "region-1"
lifecycle = "active"
[environment.stack]
provider = {{ adapter = "{ADAPTER_NAME}", versions = ">=0.1,<1" }}
directory = "some-ds"

[migration]
from = "alpha/prod"
cloud = "gamma"
env = "prod"
provider = "{PROVIDER}"
region = "region-2"
[migration.stack]
directory = "other-ds"

[[source]]
importer = "{ADAPTER_NAME}/services"
path = "exports/services"
"""


def _answers(text=DOCUMENT):
    found, problems = parse_answers(text)
    assert problems == ()
    return found


def _ask(*replies):
    """An ask function giving the replies in order (a blank reply takes the default)."""
    queue = iter(replies)
    return lambda prompt, default="": next(queue) or default


def test_a_document_reads_strictly_and_writes_back_as_the_same_answers():
    a = _answers()
    assert (a.identity.org, a.settings, [t.operator for t in a.teams]) == ("exa", (("approval-separation", "FALSE"),),
                                                                           [True])
    assert a.environments[0].stack == (Component("provider", ADAPTER_NAME, ">=0.1,<1"),
                                       Component("directory", "some-ds", None))
    assert parse_answers(answers_toml(a)) == (a, ())
    _, problems = parse_answers('version = 1\n[[environment]]\ncloud = "x"\nenvv = "prod"\n[record]\norg = 3\n')
    assert "[[environment]] #1: unknown key 'envv' (known: cloud, env, provider, region, partition, account, " \
           "lifecycle, stack)" in problems
    assert "[[environment]] #1: env is required" in problems and "[record]: org must be str" in problems
    assert parse_answers("version = ")[1][0].startswith("not TOML")


def test_what_keeps_answers_from_being_applied_is_named():
    bad = DOCUMENT.replace('org = "exa"', 'org = "EXA"').replace('region = "region-1"', 'region = "region-1"\n'
                                                                 'partition = "moon"') \
        .replace('versions = ">=0.1,<1"', 'versions = "about 7"').replace('cloud = "gamma"', 'cloud = "alpha"') \
        .replace("approval-separation = false", "approval-separation = 3\nno-such-setting = 1") \
        .replace(f'importer = "{ADAPTER_NAME}/services"', 'importer = "nothing/here"')
    problems = answers_problems(_answers(bad), INSTALLED)
    assert any(p.startswith("org code 'EXA'") for p in problems)
    assert "environment alpha/prod: partition 'moon' isn't one of " in "\n".join(problems)
    assert "environment alpha/prod: stack role provider: 'about 7' isn't a version range (PEP 440, such as >=7.2,<9)" \
        in problems
    assert "migration: the target alpha/prod is already declared" in problems
    assert any(p.startswith("[settings] approval-separation: ") for p in problems)
    assert "[settings] no-such-setting: no installed domain or adapter declares it (`opsdir report settings` lists " \
           "them)" in problems
    assert any(p.startswith("source nothing/here: ") for p in problems)
    assert answers_problems(_answers(), INSTALLED) == ()


def test_the_migration_target_starts_as_the_source_and_changes_only_what_moves():
    a = _answers()
    target = target_environment(a)
    assert (target.cloud, target.provider, target.region, target.stack) == ("gamma", PROVIDER, "region-2", (
        Component("provider", ADAPTER_NAME, ">=0.1,<1"), Component("directory", "other-ds", None)))
    dropped = _answers(DOCUMENT.replace('directory = "other-ds"', 'directory = ""'))
    assert [c.role for c in target_environment(dropped).stack] == ["provider"]
    cleared = _answers(DOCUMENT.replace('[migration.stack]', 'clear = true\n[migration.stack]'))
    assert target_environment(cleared).stack == (Component("directory", "other-ds", None),)
    assert answers_notices(a, INSTALLED) == ("alpha/prod: directory = some-ds: not installed here (`opsdir check` says "
                                             "where to get it)", "gamma/prod: directory = other-ds: not installed here "
                                             "(`opsdir check` says where to get it)")


def test_the_records_only_add_and_set_and_name_what_the_record_holds_beyond_the_answers():
    d = directory()
    trimmed = _answers(DOCUMENT.replace(f'provider = {{ adapter = "{ADAPTER_NAME}", versions = ">=0.1,<1" }}\n', ""))
    changes, notices = setup_records(d, trimmed, "00000000-0000-4000-8000-000000000000")
    assert not [r for r in changes if r.changetype == "delete"]
    after = record_after(d, changes)
    assert one(get(after, f"cn=directory,ou=stack,{ALPHA}"), "ciamAdapter") == "some-ds"
    assert one(get(after, f"cn=provider,ou=stack,{ALPHA}"), "ciamAdapter") == ADAPTER_NAME   # left as it was
    assert one(get(after, ALPHA), "ciamLifecycle") == "active"
    assert values(get(after, "cn=approval-separation,ou=settings,dc=ciam-ops"), "ciamEstateValue") == ("FALSE",)
    assert one(get(after, "cn=ciam-platform,ou=owners,dc=ciam-ops"), "ciamOwnerKind") == "operator"
    assert get(after, "cn=directory,ou=stack,env=prod,cloud=gamma,ou=environments,dc=ciam-ops") is not None
    assert get(after, "ou=incidents,dc=ciam-ops") is not None
    assert "alpha/prod: stack role provider is in the record but not in the answers: left as it is" in notices
    assert setup_records(after, trimmed, "00000000-0000-4000-8000-000000000000")[0] == ()


def test_the_prompts_build_the_document_and_ask_only_what_moves():
    ask = _ask("exa", "Example Aero", "ciam-platform", "", "", "y",
               "alpha/prod", PROVIDER, "region-1", "", "directory=some-ds", "",
               "", "y", "", "gamma/prod", "", "region-2", "", "directory=other-ds",
               f"{ADAPTER_NAME}/services=exports/services", "")
    a = prompted_answers(ask, INSTALLED)
    assert a.settings == (("approval-separation", "FALSE"),)
    assert a.environments[0].stack == (Component("provider", ADAPTER_NAME, None),
                                       Component("directory", "some-ds", None))
    assert (a.migration.source, a.migration.target.cloud, a.migration.changes) == (
        "alpha/prod", "gamma", (Component("directory", "other-ds", None),))
    assert a.sources[0].importer == f"{ADAPTER_NAME}/services"


def test_setup_writes_the_answers_file_and_names_what_to_fix(tmp_path):
    out = tmp_path / "onboarding.toml"
    text = _onboard_setup(Namespace(out=str(out)), _ask("", "", "", "n", "", ""))
    assert out.read_text(encoding="utf-8").startswith("# CIAMstack onboarding answers")
    assert f"written to {out}" in text and "next: `opsdir onboard apply" in text
    with pytest.raises(SystemExit, match="kept"):
        _onboard_setup(Namespace(out=str(out)), _ask("n"))


def test_a_stack_typed_on_one_line_reads_back():
    typed = "directory=pingds@>=0.1,<1; federation=pingfederate;  gateway="
    assert stack_text(typed) == (Component("directory", "pingds", ">=0.1,<1"),
                                 Component("federation", "pingfederate", None), Component("gateway", "", None))
    assert stack_text(stack_line(stack_text(typed))) == stack_text(typed)
    with pytest.raises(ValueError, match="role=adapter"):
        stack_text("pingds")
