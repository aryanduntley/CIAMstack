"""Database sign-in tokens in the core: the command found by scheme among the installed adapters (none named in the
core), run once, its output the token; a failure says why; the posture check counts a token sign-in as sound."""
from types import SimpleNamespace

import pytest

from opsdir import live
from opsdir.connectors.posture import posture_rows
from opsdir.connectors.registry import db_token_command
from opsdir.core.contract import DbTarget
from opsdir.core.directory import make_directory
from opsdir.store.postgres import PostureFacts

TARGET = DbTarget("db.example.internal", 5432, "opsdir_app", "opsdir")
FAKE = SimpleNamespace(db_tokens={"test-token": lambda t: ("printf", f"token-for-{t.user}\\n")})


def test_the_command_comes_from_the_adapter_declaring_the_scheme():
    assert db_token_command("test-token", TARGET, installed=(FAKE,)) == ("printf", "token-for-opsdir_app\\n")
    with pytest.raises(SystemExit, match="no installed adapter signs in to the database with 'other'"):
        db_token_command("other", TARGET, installed=(FAKE, SimpleNamespace(db_tokens=None)))


def test_the_token_is_the_commands_output():
    assert live.db_token(db_token_command("test-token", TARGET, installed=(FAKE,))) == "token-for-opsdir_app"


def test_a_failing_token_command_says_why():
    with pytest.raises(SystemExit, match=r"failed \(exit 3\): expired credentials"):
        live.db_token(("sh", "-c", "echo expired credentials >&2; exit 3"))
    with pytest.raises(SystemExit, match="is not installed here"):
        live.db_token(("no-such-cloud-cli",))


def test_a_token_sign_in_is_sound_in_production():
    facts = PostureFacts(170009, "db.example.internal", "verify-full", "/ca.pem", True, True, False, False, True,
                         False, "opsdir", "opsdir_app", False, "opsdir_owner", False, False, ())
    rows = posture_rows(facts, make_directory((), {}, ()), (), token="aws-rds-iam")
    assert ("sign-in", "ok", "cloud database token (aws-rds-iam)") in rows
