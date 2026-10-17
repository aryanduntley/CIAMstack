"""The inventory against a real EJBCA (marker `ejbca`: docker and the keyfactor/ejbca-ce image, current Community
release 9.6.3, pulled beforehand; skipped without them): a fresh container gets a CA writing CRL, OCSP and CA issuer
URLs into what it issues, a certificate profile and end entity profile built with EJBCA's own classes, three
certificates (one revoked for key compromise) and an inventory reader whose role holds ONLY the rules the README
states. The reader's client certificate runs the collector's own GET and POST calls through the core's runner over
mutual TLS; the importer reads what they saved into both CAs, their endpoints, their profiles as templates and
complete inventories, no private key anywhere. The same certificate is refused a revocation; without
/ca_functionality/view_certificate/ EJBCA answers every search with nothing, and the root CAs' inventories are
denied."""
import datetime as dt
import json
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

import pytest

from opsdir import live
from opsdir.connectors.collecting import collect
from opsdir.core.directory import get, one, values
from opsdir.domains.pki.naming import authority_dn, issued_inventory_dn, template_dn
from opsdir_adapter_ejbca.collect import COLLECTORS
from opsdir_adapter_ejbca.inventory import DENIED, read_inventory
from network_fixtures import ALPHA, entry, model
from support import after_import

IMAGE = "keyfactor/ejbca-ce:9.6.3"
HERE = Path(__file__).resolve().parent
README = HERE.parent / "README.md"
CA, MANAGEMENT = "CIAM Issuing CA", "ManagementCA"
RULES = ("/administrator/", "/ca/ManagementCA/", "/ca/CIAM Issuing CA/", "/ca_functionality/view_certificate/",
         "/endentityprofilesrules/EMPTY/view_end_entity/", "/endentityprofilesrules/ciam-servers/view_end_entity/")


def _image():
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True, timeout=60).returncode == 0


pytestmark = [pytest.mark.ejbca, pytest.mark.skipif(not _image(), reason=f"no docker or no {IMAGE} image")]


def _port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _docker(*args, stdin=None, timeout=300):
    done = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, timeout=timeout)
    assert done.returncode == 0, done.stderr[-2000:] + done.stdout[-2000:]
    return done.stdout


def _healthy(port, deadline):
    url = f"https://127.0.0.1:{port}/ejbca/publicweb/healthcheck/ejbcahealth"
    insecure = ssl._create_unverified_context()           # only to see the server is up, nothing read
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5, context=insecure) as answer:
                if answer.status == 200:
                    return
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(2)
    raise AssertionError("EJBCA didn't become healthy")


def _ejbca(name, *args):
    return _docker("exec", name, "/opt/keyfactor/bin/ejbca.sh", *args)


@pytest.fixture(scope="module")
def ejbca():
    """(container name, https port, ManagementCA certificate, the reader's certificate and key): a fresh container,
    set up by ejbca/setup.sh and restarted to trust its role members' CA, removed after."""
    name, port = f"opsdir-ejbca-test-{_port()}", _port()
    _docker("run", "-d", "--name", name, "--hostname", "localhost", "-p", f"127.0.0.1:{port}:8443", IMAGE)
    try:
        _healthy(port, time.monotonic() + 300)
        _docker("cp", str(HERE / "ejbca" / "Profiles.java"), f"{name}:/tmp/Profiles.java")
        _docker("exec", "-i", name, "sh", stdin=(HERE / "ejbca" / "setup.sh").read_text(), timeout=600)
        _docker("restart", name)
        _healthy(port, time.monotonic() + 300)
        _ejbca(name, "ca", "getcacert", "--caname", MANAGEMENT, "-f", "/tmp/management.pem")
        anchor = _docker("exec", name, "cat", "/tmp/management.pem")
        reader = _docker("exec", name, "sh", "-c", "cat /tmp/out/pem/inventory-reader.pem "
                                                   "/tmp/out/pem/inventory-reader-Key.pem")
        yield name, port, anchor, reader
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=120)


def _alpha(port):
    _, alpha, _ = model(alpha=(entry(ALPHA, "ejbca-lab", "ciamCollectionSource", ciamBindingRole="collect-ejbca",
                                     ciamImporter="ejbca/inventory", ciamSourceRef=f"https://localhost:{port}/ejbca",
                                     ciamCredentialRole="ejbca-reader", ciamCredentialScheme="client-certificate",
                                     ciamCaRole="ejbca-ca"),
                               entry(ALPHA, "ejbca-reader", "ciamSecretRef", ciamBindingRole="ejbca-reader",
                                     ciamRefUri="fake://vault/ejbca-reader"),
                               entry(ALPHA, "ejbca-ca", "ciamCertificateRef", ciamBindingRole="ejbca-ca",
                                     ciamRefUri="fake://vault/ejbca-ca")))
    return alpha


def _collected(ejbca):
    _, port, anchor, reader = ejbca
    refs = {"fake://vault/ejbca-reader": reader, "fake://vault/ejbca-ca": anchor}
    alpha = _alpha(port)
    c = collect("ejbca/inventory", COLLECTORS[0], alpha.d, alpha,
                lambda call: live.run_call(call, lambda ref: (refs.get(ref), None if ref in refs else "unknown")))
    return alpha, c


def test_the_readme_role_reads_both_cas_and_nothing_else(ejbca, tmp_path):
    readme = README.read_text()
    assert all(f"`{r}`" in readme for r in ("/administrator/", "/ca/<CA>/", "/ca_functionality/view_certificate/",
                                            "/endentityprofilesrules/<end entity profile>/view_end_entity/"))
    alpha, c = _collected(ejbca)
    assert c.problems == ()
    assert "ejbca/ejbca-lab/count.json" not in c.files            # the role may not count: nothing to read
    assert not any("PRIVATE KEY" in t for t in c.files.values())
    imported = read_inventory(c.files, alpha.d, (), dt.datetime.now(dt.timezone.utc))
    d = after_import(alpha.d, imported)
    for name in (CA, MANAGEMENT):
        assert one(get(d, issued_inventory_dn(name)), "ciamInventoryState") == "complete"
    inv = get(d, issued_inventory_dn(CA))
    issued = {one(e, "ciamRequester"): e for e in d.entries.values() if e.dn.endswith("," + inv.dn)}
    assert sorted(issued) == ["SYSTEMCA", "idm.lab", "old-sso.lab", "sso.lab"]
    assert one(issued["old-sso.lab"], "ciamRevocationReason") == "keyCompromise"
    assert one(issued["old-sso.lab"], "ciamRevokedAt") and one(issued["idm.lab"], "ciamRevocationReason") is None
    assert one(issued["idm.lab"], "ciamTemplateName") == f"{CA}/ciam-tls"
    ca = get(d, authority_dn(CA))
    assert {one(e, "cn"): one(e, "ciamEndpointUrl") for e in d.entries.values() if e.dn.endswith("," + ca.dn)} == {
        "crl-1": "http://pki.example.test/crl/ciam-issuing.crl", "ocsp-1": "http://ocsp.example.test/",
        "ca-issuers-1": "http://pki.example.test/ca/ciam-issuing.cer"}
    tls = get(d, template_dn(f"{CA}/ciam-tls"))
    assert (one(tls, "ciamMaxValidityDays"), values(tls, "ciamExtendedKeyUsage")) == (
        "397", ("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"))
    assert one(tls, "ciamTemplateAuthority") == authority_dn(CA)
    assert get(d, template_dn(f"{MANAGEMENT}/SERVER")) is not None

    # the same certificate may not change anything: a revocation is refused
    (tmp_path / "reader.pem").write_text(ejbca[3])
    tls_ctx = ssl.create_default_context(cadata=ejbca[2])
    tls_ctx.load_cert_chain(tmp_path / "reader.pem")
    serial = one(issued["sso.lab"], "cn")
    issuer = quote("CN=CIAM Issuing CA,O=CIAMstack Test", safe="")
    revoke = urllib.request.Request(f"https://localhost:{ejbca[1]}/ejbca/ejbca-rest-api/v1/certificate/{issuer}/"
                                    f"{serial}/revoke?reason=KEY_COMPROMISE", method="PUT")
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(revoke, timeout=60, context=tls_ctx)
    assert refused.value.code == 403
    again = after_import(alpha.d, read_inventory(_collected(ejbca)[1].files, alpha.d, (),
                                                 dt.datetime.now(dt.timezone.utc)))
    sso = get(again, f"cn={serial},{issued_inventory_dn(CA)}")
    assert one(sso, "ciamRevocationReason") is None


def test_without_view_certificate_every_search_is_empty_and_the_roots_are_denied(ejbca):
    name = ejbca[0]
    _ejbca(name, "roles", "changerule", "--name", "Inventory Reader", "--rule", "/ca_functionality/view_certificate/",
           "--state", "UNUSED")
    try:
        alpha, c = _collected(ejbca)
        assert c.problems == ()
        assert all(json.loads(t)["certificates"] == [] for p, t in c.files.items() if "/certificates/" in p)
        d = after_import(alpha.d, read_inventory(c.files, alpha.d, (), dt.datetime.now(dt.timezone.utc)))
        for ca in (CA, MANAGEMENT):                         # both self-signed here: each always holds its own
            inv = get(d, issued_inventory_dn(ca))
            assert (one(inv, "ciamInventoryState"), values(inv, "ciamInventoryProblem")) == ("denied", (DENIED,))
    finally:
        _ejbca(name, "roles", "changerule", "--name", "Inventory Reader", "--rule",
               "/ca_functionality/view_certificate/", "--state", "ACCEPT")
