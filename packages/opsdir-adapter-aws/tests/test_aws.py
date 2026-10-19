"""The AWS adapter as the core sees it: registered, chosen from data, owning its vocabulary and secret scheme.
Its Terraform is exercised end to end by the showcase (examples/showcase golden outputs)."""
import json
import os
import shlex
import subprocess
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.secrets import secretsmanager_command, secretsmanager_lookup

# A reference holding every character a shell treats specially (no slash: each split part takes it whole)
HOSTILE = "it's \"x\" $(touch made) `touch made` ${HOME}; touch made | cat & echo"


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "provider"


def test_applies_to_its_provider_only():
    assert ADAPTER.applies(SimpleNamespace(provider="aws")) and not ADAPTER.applies(SimpleNamespace(provider="other"))


def test_owns_its_vocabulary_and_reference_schemes():
    assert ADAPTER.vocabulary["ciamCloudProvider"] == ("aws",)
    assert (set(ADAPTER.ref_schemes) == {"aws-sm", "aws-kms", "aws-acm", "s3"}
            and set(ADAPTER.secret_schemes) == {"aws-sm"})


def test_secret_references_resolve_with_the_aws_cli():
    assert secretsmanager_command("prod/ds/root") == (
        "aws secretsmanager get-secret-value --secret-id prod/ds/root --query SecretString --output text")


def test_a_secret_reference_is_one_argument_whatever_it_holds():
    assert shlex.split(secretsmanager_command(f"prod/{HOSTILE}")) == [
        "aws", "secretsmanager", "get-secret-value", "--secret-id", f"prod/{HOSTILE}", "--query", "SecretString",
        "--output", "text"]


def test_the_shell_runs_the_aws_cli_with_the_reference_unexpanded(tmp_path):
    fake = tmp_path / "bin" / "aws"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\"\n")
    fake.chmod(0o755)
    done = subprocess.run(["sh", "-c", secretsmanager_command(HOSTILE)], capture_output=True, text=True, cwd=tmp_path,
                          env={**os.environ, "PATH": f"{fake.parent}{os.pathsep}{os.environ['PATH']}"}, check=True)
    assert done.stdout.splitlines() == ["secretsmanager", "get-secret-value", "--secret-id", HOSTILE, "--query",
                                        "SecretString", "--output", "text"]
    assert not (tmp_path / "made").exists()


def test_the_ansible_lookup_keeps_a_reference_one_literal():
    expr = secretsmanager_lookup(None, None, HOSTILE)
    assert json.loads(f"[{expr[len('lookup('):-1]}]") == ["amazon.aws.secretsmanager_secret", HOSTILE]
