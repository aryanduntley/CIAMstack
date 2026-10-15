"""The KV inventory against a real Vault (marker `vault`: the pinned Vault CLI, tools/bin/vault from
opsdir/scripts/fetch-tools.sh; skipped without it): a dev server on a free port holds KV 2 secrets at the root, under a
prefix and nested deeper; a token with ONLY the policy the README states (list on <mount>/metadata, list and read on
<mount>/metadata/*, nothing on data/*) runs the collector's own commands (`vault kv list -format=json -mount=..`,
`vault kv metadata get -format=json -mount=..`) through the core's runner; the importer reads what they wrote, the
reference reconciles as present, no value is in the export, and the same token is refused the secret's data."""
import datetime as dt
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from opsdir import live
from opsdir.connectors.collecting import collect
from opsdir.core.directory import get, one
from opsdir.domains.pki.inventory import PRESENT, inventories, reconcile, record_references
from opsdir_adapter_hashicorp_vault.adapter import ADAPTER
from opsdir_adapter_hashicorp_vault.collect import COLLECTORS
from opsdir_adapter_hashicorp_vault.inventory import read_kv_metadata
from network_fixtures import ALPHA, entry, model
from support import after_import

ROOT = Path(__file__).resolve().parents[3]
VAULT = ROOT / "tools" / "bin" / "vault"
README = Path(__file__).resolve().parents[1] / "README.md"
pytestmark = [pytest.mark.vault,
              pytest.mark.skipif(not VAULT.exists(), reason="no tools/bin/vault (opsdir/scripts/fetch-tools.sh)")]
# The inventory reader's policy for the mount `secret`, exactly as the README states it
POLICY = '''path "secret/metadata" {
  capabilities = ["list"]
}
path "secret/metadata/*" {
  capabilities = ["list", "read"]
}
'''
SECRETS = {"app": "s3cr3t-app-value", "ciam/db": "s3cr3t-db-value", "ciam/deep/k": "s3cr3t-deep-value"}


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _vault(env, *args, stdin=None):
    return subprocess.run([str(VAULT), *args], input=stdin, capture_output=True, text=True, env=env, timeout=60)


@pytest.fixture
def server(tmp_path):
    """(address, root environment): a dev server, its root token, HOME in the test's directory."""
    address = f"http://127.0.0.1:{_port()}"
    env = {**os.environ, "HOME": str(tmp_path), "VAULT_ADDR": address, "VAULT_TOKEN": "root"}
    proc = subprocess.Popen([str(VAULT), "server", "-dev", "-dev-root-token-id=root",
                             f"-dev-listen-address={address[len('http://'):]}"], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 30
        while _vault(env, "status").returncode != 0:
            assert time.monotonic() < deadline, "the dev server didn't start"
            time.sleep(0.2)
        yield address, env
    finally:
        proc.terminate()
        proc.wait(timeout=30)


def test_the_readme_policy_lists_and_reads_metadata_and_nothing_else(server, tmp_path, monkeypatch):
    address, root = server
    assert POLICY in README.read_text()
    for path, value in SECRETS.items():
        assert _vault(root, "kv", "put", "-mount=secret", path, f"value={value}").returncode == 0
    assert _vault(root, "policy", "write", "inventory", "-", stdin=POLICY).returncode == 0
    made = _vault(root, "token", "create", "-policy=inventory", "-no-default-policy", "-field=token")
    assert made.returncode == 0, made.stderr
    reader = made.stdout.strip()

    _, alpha, _ = model(alpha=(entry(ALPHA, "vault", "ciamSecretStore", ciamBindingRole="vault", ciamRefScheme="vault",
                                     ciamStoreEndpoint=address),
                               entry(ALPHA, "db", "ciamSecretRef", ciamBindingRole="db",
                                     ciamRefUri="vault://secret/ciam/db")))
    monkeypatch.setenv("PATH", f"{VAULT.parent}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("VAULT_TOKEN", reader)            # the operator's own login: only the inventory policy
    monkeypatch.delenv("VAULT_ADDR", raising=False)      # the store's address comes from the record
    c = collect("hashicorp-vault/kv-metadata", COLLECTORS[0], alpha.d, alpha,
                lambda call: live.run_call(call, live.resolver()))
    assert c.problems == ()
    assert sorted(c.files) == ["list/secret/_keys.json", "list/secret/ciam/_keys.json",
                               "list/secret/ciam/deep/_keys.json", "metadata/secret/app.json",
                               "metadata/secret/ciam/db.json", "metadata/secret/ciam/deep/k.json"]
    assert not any(v in text for v in SECRETS.values() for text in c.files.values())

    after = after_import(alpha.d, read_kv_metadata(c.files, alpha.d, (), dt.datetime.now(dt.timezone.utc)))
    inv = get(after, "cn=secret,ou=vault,ou=secret-inventory,dc=ciam-ops")
    assert one(inv, "ciamInventoryState") == "complete"
    assert {one(get(after, f"cn={p},{inv.dn}"), "ciamObjectState") for p in SECRETS} == {"active"}
    (ref,) = record_references(after, ADAPTER.inventory_locator)
    assert reconcile(after, ref, inventories(after)).state == PRESENT

    denied = _vault({**root, "VAULT_TOKEN": reader}, "kv", "get", "-mount=secret", "ciam/db")
    assert denied.returncode != 0 and "permission denied" in denied.stderr
    assert SECRETS["ciam/db"] not in denied.stdout
