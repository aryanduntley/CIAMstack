"""The PKI inventory against a real Vault (marker `vault`: the pinned Vault CLI, tools/bin/vault from
opsdir/scripts/fetch-tools.sh; skipped without it): a dev server's PKI mount with a root CA, URL templating, two roles
and an ACL policy granting one of them through `default`, three issued certificates and a revocation. A token with
ONLY the policy the README states runs the collector's own GETs through the core's runner; the importer reads what
they saved into the CA, its endpoints, its roles (who may request from each) and an inventory complete for what
Vault keeps, no private key anywhere; the same token is refused issuing; scripts/export-vault-pki.sh under that token
writes an export the importer reads the same way; a no_store role leaves the inventory incomplete."""
import datetime as dt
import os
import socket
import subprocess
import time
from pathlib import Path

import pytest

from opsdir import live
from opsdir.connectors.collecting import collect
from opsdir.core.directory import get, one, values
from opsdir.domains.pki.naming import authority_dn, issued_inventory_dn, template_dn
from opsdir_adapter_hashicorp_vault.pki import read_pki
from opsdir_adapter_hashicorp_vault.pki_collect import PKI_COLLECTORS
from network_fixtures import ALPHA, entry, model
from support import after_import

ROOT = Path(__file__).resolve().parents[3]
VAULT = ROOT / "tools" / "bin" / "vault"
PACKAGE = Path(__file__).resolve().parents[1]
README, SCRIPT = PACKAGE / "README.md", PACKAGE / "scripts" / "export-vault-pki.sh"
pytestmark = [pytest.mark.vault,
              pytest.mark.skipif(not VAULT.exists(), reason="no tools/bin/vault (opsdir/scripts/fetch-tools.sh)")]
CA = "Example Lab Root CA"
# The PKI inventory reader's policy for the mount `pki`, exactly as the README states it
POLICY = '''path "pki/issuers" { capabilities = ["list"] }
path "pki/issuer/+" { capabilities = ["read"] }
path "pki/roles" { capabilities = ["list"] }
path "pki/roles/+" { capabilities = ["read"] }
path "pki/certs" { capabilities = ["list"] }
path "pki/cert/+" { capabilities = ["read"] }
path "pki/config/urls" { capabilities = ["read"] }
path "pki/config/issuers" { capabilities = ["read"] }
path "pki/config/cluster" { capabilities = ["read"] }
path "pki/config/crl" { capabilities = ["read"] }
path "pki/config/auto-tidy" { capabilities = ["read"] }
# optional: who may request from each role
path "sys/policies/acl" { capabilities = ["list"] }
path "sys/policies/acl/+" { capabilities = ["read"] }
'''
DEFAULT_ADDITION = 'path "pki/issue/lab-client" {\n  capabilities = ["update"]\n}\n'
ISSUERS = 'path "pki/issue/*" {\n  capabilities = ["create", "update"]\n}\n'


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _vault(env, *args, stdin=None):
    done = subprocess.run([str(VAULT), *args], input=stdin, capture_output=True, text=True, env=env, timeout=60)
    return done


def _ok(env, *args, stdin=None):
    done = _vault(env, *args, stdin=stdin)
    assert done.returncode == 0, done.stderr
    return done.stdout


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


def _pki(root):
    """The mount `pki`: a root CA, templated URLs, roles lab-web (server only) and lab-client (any name, client),
    the default policy granting lab-client, lab-issuers granting every role; three certificates, one revoked.
    Returns the revoked one's serial."""
    _ok(root, "secrets", "enable", "pki")
    _ok(root, "secrets", "tune", "-max-lease-ttl=87600h", "pki")
    _ok(root, "write", "pki/root/generate/internal", f"common_name={CA}", "issuer_name=lab-root", "ttl=87600h")
    _ok(root, "write", "pki/config/cluster", "path=http://vault.lab.test:8200/v1/pki",
        "aia_path=http://pki.lab.test/v1/pki")
    _ok(root, "write", "pki/config/urls", "enable_templating=true",
        "crl_distribution_points={{cluster_aia_path}}/issuer/{{issuer_id}}/crl/der",
        "ocsp_servers={{cluster_path}}/ocsp", "issuing_certificates={{cluster_aia_path}}/issuer/{{issuer_id}}/der")
    _ok(root, "write", "pki/roles/lab-web", "allowed_domains=lab.test", "allow_subdomains=true", "max_ttl=720h",
        "server_flag=true", "client_flag=false")
    _ok(root, "write", "pki/roles/lab-client", "allow_any_name=true", "server_flag=false", "client_flag=true",
        "max_ttl=24h")
    default = _ok(root, "policy", "read", "default")
    _ok(root, "policy", "write", "default", "-", stdin=default + DEFAULT_ADDITION)
    _ok(root, "policy", "write", "lab-issuers", "-", stdin=ISSUERS)
    for cn in ("sso.lab.test", "portal.lab.test"):
        _ok(root, "write", "pki/issue/lab-web", f"common_name={cn}", "ttl=48h")
    serial = _ok(root, "write", "-field=serial_number", "pki/issue/lab-client", "common_name=bob", "ttl=1h").strip()
    _ok(root, "write", "pki/revoke", f"serial_number={serial}")
    return serial


def _reader(root):
    _ok(root, "policy", "write", "pki-inventory", "-", stdin=POLICY)
    return _ok(root, "token", "create", "-policy=pki-inventory", "-no-default-policy", "-field=token").strip()


def _check(d, revoked):
    ca = get(d, authority_dn(CA))
    assert one(ca, "ciamProviderRef") == "pki"
    issuer = _issuer_id(d)
    assert {one(e, "cn"): one(e, "ciamEndpointUrl") for e in d.entries.values()
            if e.dn.endswith(ca.dn) and e.dn != ca.dn} == {
        "crl-1": f"http://pki.lab.test/v1/pki/issuer/{issuer}/crl/der", "ocsp-1": "http://vault.lab.test:8200/v1/pki/ocsp",
        "ca-issuers-1": f"http://pki.lab.test/v1/pki/issuer/{issuer}/der"}
    inv = get(d, issued_inventory_dn(CA))
    assert one(inv, "ciamInventoryState") == "complete"
    issued = [e for e in d.entries.values() if e.dn.endswith(inv.dn) and e.dn != inv.dn]
    assert len(issued) == 4               # the root's own certificate is kept too
    assert sorted(one(e, "ciamSubject") for e in issued) == [f"CN={CA}", "CN=bob", "CN=portal.lab.test",
                                                            "CN=sso.lab.test"]
    bob = get(d, f"cn={revoked},{inv.dn}")
    assert one(bob, "ciamRevocationReason") == "unspecified" and one(bob, "ciamRevokedAt")
    web, client = get(d, template_dn(f"{CA}/lab-web")), get(d, template_dn(f"{CA}/lab-client"))
    assert (one(web, "ciamMaxValidityDays"), values(web, "ciamExtendedKeyUsage")) == ("30", ("1.3.6.1.5.5.7.3.1",))
    assert (values(web, "ciamEnrollee"), one(web, "ciamEnrollmentScope")) == (("policy lab-issuers",), "restricted")
    assert (values(client, "ciamEnrollee"), one(client, "ciamEnrollmentScope")) == (
        ("policy default", "policy lab-issuers"), "broad")


def _issuer_id(d):
    import re
    url = one(get(d, f"cn=ca-issuers-1,{authority_dn(CA)}"), "ciamEndpointUrl")
    return re.search(r"/issuer/([0-9a-f-]+)/der$", url).group(1)


def test_the_readme_policy_reads_the_mount_and_nothing_else(server, tmp_path):
    address, root = server
    assert POLICY in README.read_text()
    revoked = _pki(root)
    reader = _reader(root)
    _, alpha, _ = model(alpha=(entry(ALPHA, "collect-pki", "ciamCollectionSource", ciamBindingRole="collect-pki",
                                     ciamImporter="hashicorp-vault/pki", ciamSourceRef=f"{address}/pki",
                                     ciamCredentialRole="pki-reader", ciamCredentialScheme="api-key"),
                               entry(ALPHA, "pki-reader", "ciamSecretRef", ciamBindingRole="pki-reader",
                                     ciamRefUri="fake://vault/pki-reader")))
    c = collect("hashicorp-vault/pki", PKI_COLLECTORS[0], alpha.d, alpha,
                lambda call: live.run_call(call, lambda ref: (reader, None)))
    assert c.problems == ()
    assert "pki/pki/policies/default.json" in c.files and len([p for p in c.files if "/certs/" in p]) == 4
    assert not any("PRIVATE KEY" in t or "private_key" in t for t in c.files.values())
    d = after_import(alpha.d, read_pki(c.files, alpha.d, (), dt.datetime.now(dt.timezone.utc)))
    _check(d, revoked)

    refused = _vault({**root, "VAULT_TOKEN": reader}, "write", "pki/issue/lab-web", "common_name=x.lab.test")
    assert refused.returncode != 0 and "permission denied" in refused.stderr


def test_the_export_script_writes_what_the_importer_reads(server, tmp_path):
    address, root = server
    revoked = _pki(root)
    reader = {**root, "VAULT_TOKEN": _reader(root), "PATH": f"{VAULT.parent}{os.pathsep}{os.environ['PATH']}"}
    done = subprocess.run(["bash", str(SCRIPT), "pki", str(tmp_path / "out")], capture_output=True, text=True,
                          env=reader, timeout=120)
    assert done.returncode == 0, done.stderr
    files = {p.relative_to(tmp_path / "out").as_posix(): p.read_text() for p in (tmp_path / "out").rglob("*.json")}
    _, alpha, _ = model()
    d = after_import(alpha.d, read_pki(files, alpha.d, (), dt.datetime.now(dt.timezone.utc)))
    _check(d, revoked)

    _ok(root, "write", "pki/roles/ephemeral", "allow_any_name=true", "no_store=true")
    _ok(root, "write", "pki/issue/ephemeral", "common_name=gone")
    done = subprocess.run(["bash", str(SCRIPT), "pki", str(tmp_path / "again")], capture_output=True, text=True,
                          env=reader, timeout=120)
    assert done.returncode == 0, done.stderr
    files = {p.relative_to(tmp_path / "again").as_posix(): p.read_text() for p in (tmp_path / "again").rglob("*.json")}
    d = after_import(alpha.d, read_pki(files, alpha.d, (), dt.datetime.now(dt.timezone.utc)))
    assert one(get(d, issued_inventory_dn(CA)), "ciamInventoryState") == "incomplete"
