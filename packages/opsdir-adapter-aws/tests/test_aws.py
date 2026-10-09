"""The AWS adapter as the core sees it: registered, chosen from data, owning its vocabulary and secret scheme.
Its Terraform is exercised end to end by the showcase (examples/showcase golden outputs)."""
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.secrets import secretsmanager_command


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
        "aws secretsmanager get-secret-value --secret-id 'prod/ds/root' --query SecretString --output text")
