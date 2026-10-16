"""The scripted checks' probes run for real: the Node.js ones (GCP synthetic monitors) against local TLS servers with a
throwaway certificate the runtime is told to trust: an LDAPS simple bind (RFC 4511 bytes, a refused bind fails), a GET
following a redirect (an answer of 400 or more fails), a client-credentials token request. Skipped without node or
openssl."""
import json
import os
import shutil
import subprocess

import pytest

from opsdir.domains.observability.probes import NODE_PROBES, PYTHON_PROBES

pytestmark = pytest.mark.skipif(not (shutil.which("node") and shutil.which("openssl")), reason="node and openssl")

SERVERS = r'''
const tls = require("tls"), https = require("https"), fs = require("fs");
const p = require("./probes.js");
const opts = {key: fs.readFileSync("key.pem"), cert: fs.readFileSync("cert.pem")};
const ldap = tls.createServer(opts, (s) => s.on("data", (d) => {
  const ok = d.toString("hex") === p.bindRequest("cn=x", "pw").toString("hex");
  s.write(Buffer.from(ok ? "300c02010161070a010004000400" : "300c02010161070a013104000400", "hex"));
}));
const web = https.createServer(opts, (req, res) => {
  if (req.url === "/start") { res.writeHead(302, {location: "/login"}); return res.end(); }
  if (req.url === "/login") { res.writeHead(200); return res.end("ok"); }
  if (req.url === "/token") { res.writeHead(200); return res.end('{"access_token":"t"}'); }
  res.writeHead(404); res.end();
});
const fail = (e) => "REJECT " + e.message.replace(/:\d+/, ":PORT");
ldap.listen(0, () => web.listen(0, async () => {
  const l = `ldaps://localhost:${ldap.address().port}`, w = `https://localhost:${web.address().port}`;
  const out = [
    await p.probe("ldap-bind", l, {bind_dn: "cn=x", password: "pw"}),
    await p.probe("ldap-bind", l, {bind_dn: "cn=x", password: "bad"}).catch(fail),
    await p.probe("health", `${w}/start`, null),
    await p.probe("login-page", `${w}/nope`, null).catch(fail),
    await p.probe("oidc-token", `${w}/token`, {client_id: "c", client_secret: "s"}),
    p.bindRequest("", "").toString("hex")];
  console.log(JSON.stringify(out)); ldap.close(); web.close();
}));
'''


def test_the_node_probes_bind_get_and_request_a_token(tmp_path):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out",
                    "cert.pem", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                   cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "probes.js").write_text(NODE_PROBES)
    (tmp_path / "servers.js").write_text(SERVERS)
    run = subprocess.run(["node", "servers.js"], cwd=tmp_path, capture_output=True, text=True, timeout=60,
                         env={"PATH": os.environ["PATH"], "NODE_EXTRA_CA_CERTS": "cert.pem"})
    assert json.loads(run.stdout) == [
        "bound as cn=x", "REJECT ldaps://localhost:PORT: the bind failed (result code 49)", "HTTP 200",
        "REJECT https://localhost:PORT/nope: HTTP 404", "HTTP 200, access token issued",
        "300c020101600702010304008000"]                                  # RFC 4511 anonymous simple bind


def test_both_languages_make_the_same_checks():
    for name in ("def get(", "def token(", "def ldap_bind(", "def probe("):
        assert name in PYTHON_PROBES
    for name in ("async function get(", "async function token(", "function ldapBind(", "async function probe("):
        assert name in NODE_PROBES


# A private CA hierarchy (root -> intermediate -> localhost), made with openssl: what a service behind a private CA
# presents. The servers send the leaf and the intermediate, as servers do.
PKI = (
    (["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "root.key", "-out",
      "root.pem", "-days", "2", "-subj", "/CN=Test Private Root CA", "-addext", "basicConstraints=critical,CA:TRUE",
      "-addext", "keyUsage=critical,keyCertSign,cRLSign"]),
    (["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "int.key", "-out", "int.csr",
      "-subj", "/CN=Test Private Issuing CA"]),
    (["x509", "-req", "-in", "int.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "int.pem",
      "-days", "2", "-extfile", "int.ext"]),
    (["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "key.pem", "-out",
      "leaf.csr", "-subj", "/CN=localhost"]),
    (["x509", "-req", "-in", "leaf.csr", "-CA", "int.pem", "-CAkey", "int.key", "-CAcreateserial", "-out", "leaf.pem",
      "-days", "1", "-extfile", "leaf.ext"]),
)
EXTENSIONS = {
    "int.ext": "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"
               "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
    "leaf.ext": "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                "subjectAltName=DNS:localhost\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"}

# HTTPS (a redirect, a login page, a token endpoint) and LDAPS (answers any bind with success) servers presenting the
# private chain; prints their ports, then serves until killed.
PRIVATE_SERVERS = r'''
const tls = require("tls"), https = require("https"), fs = require("fs");
const opts = {key: fs.readFileSync("key.pem"), cert: fs.readFileSync("leaf.pem") + fs.readFileSync("int.pem")};
const ldap = tls.createServer(opts, (s) => s.on("data", () =>
  s.write(Buffer.from("300c02010161070a010004000400", "hex"))));
const web = https.createServer(opts, (req, res) => {
  if (req.url === "/start") { res.writeHead(302, {location: "/login"}); return res.end(); }
  if (req.url === "/token") { res.writeHead(200); return res.end('{"access_token":"t"}'); }
  res.writeHead(200); res.end("ok");
});
ldap.listen(0, () => web.listen(0, () => console.log(`${ldap.address().port} ${web.address().port}`)));
'''

# The Node.js probes as a check (GCP's synthetic monitors) runs them, given the CA PEM (or none) and partial.
NODE_CHECKS = r'''
const p = require("./probes.js"), fs = require("fs");
const [ldapPort, webPort, caFile, partial] = process.argv.slice(2);
const ca = caFile === "-" ? null : fs.readFileSync(caFile, "utf8");
const fail = (e) => "REJECT " + (e.code || e.message);
(async () => console.log(JSON.stringify([
  await p.probe("ldap-bind", `ldaps://localhost:${ldapPort}`, null, ca, partial === "1").catch(fail),
  await p.probe("health", `https://localhost:${webPort}/start`, null, ca, partial === "1").catch(fail),
  await p.probe("oidc-token", `https://localhost:${webPort}/token`, {client_id: "c", client_secret: "s"}, ca,
                partial === "1").catch(fail)])))();
'''


@pytest.fixture(scope="module")
def private_ca(tmp_path_factory):
    """(directory with the private CA hierarchy, ldaps port, https port) of running servers presenting it."""
    where = tmp_path_factory.mktemp("private-ca")
    for name, text in EXTENSIONS.items():
        (where / name).write_text(text)
    for args in PKI:
        subprocess.run(["openssl", *args], cwd=where, check=True, capture_output=True)
    (where / "servers.js").write_text(PRIVATE_SERVERS)
    (where / "probes.js").write_text(NODE_PROBES)
    (where / "checks.js").write_text(NODE_CHECKS)
    servers = subprocess.Popen(["node", "servers.js"], cwd=where, stdout=subprocess.PIPE, text=True,
                               env={"PATH": os.environ["PATH"]})
    try:
        ldap, web = servers.stdout.readline().split()
        yield where, ldap, web
    finally:
        servers.kill()
        servers.wait()


def _python_checks(where, ldap, web, ca, partial):
    """The Python probes (AWS canaries, Azure check jobs) as a check runs them, given the CA PEM (or None)."""
    probes = {}
    exec(PYTHON_PROBES, probes)                                         # noqa: S102 (the rendered probes, as run)

    def run(flow, url, creds=None):
        try:
            return probes["probe"](flow, url, creds, ca, partial)
        except Exception as failure:                                    # noqa: BLE001 (what the check reports)
            return f"REJECT {type(failure).__name__}"
    return [run("ldap-bind", f"ldaps://localhost:{ldap}"), run("health", f"https://localhost:{web}/start"),
            run("oidc-token", f"https://localhost:{web}/token", {"client_id": "c", "client_secret": "s"})]


def _node_checks(where, ldap, web, ca_file, partial):
    run = subprocess.run(["node", "checks.js", ldap, web, ca_file, "1" if partial else "0"], cwd=where,
                         capture_output=True, text=True, timeout=60, env={"PATH": os.environ["PATH"]})
    return json.loads(run.stdout)


PASSED = ["bound as anonymous", "HTTP 200", "HTTP 200, access token issued"]


def test_python_probes_trust_a_private_root_ca_they_are_given(private_ca):
    where, ldap, web = private_ca
    assert _python_checks(where, ldap, web, (where / "root.pem").read_text(), False) == PASSED
    # the runtime's own trust store alone doesn't know the private CA
    assert all(r.startswith("REJECT") for r in _python_checks(where, ldap, web, None, False))


def test_python_probes_trust_an_intermediate_ca_as_the_anchor(private_ca):
    where, ldap, web = private_ca
    assert _python_checks(where, ldap, web, (where / "int.pem").read_text(), True) == PASSED


def test_node_probes_trust_a_private_root_ca_they_are_given(private_ca):
    where, ldap, web = private_ca
    assert _node_checks(where, ldap, web, "root.pem", False) == PASSED
    assert all(r.startswith("REJECT") for r in _node_checks(where, ldap, web, "-", False))


def test_node_probes_trust_an_intermediate_ca_only_when_told_it_is_the_anchor(private_ca):
    where, ldap, web = private_ca
    assert _node_checks(where, ldap, web, "int.pem", True) == PASSED
    assert all(r.startswith("REJECT") for r in _node_checks(where, ldap, web, "int.pem", False))


def test_node_probes_keep_the_runtime_roots_when_given_a_ca():
    # an explicit ca alone would replace the runtime's roots: the check adds to them
    assert 'ca: [...tls.getCACertificates("default"), ca]' in NODE_PROBES
