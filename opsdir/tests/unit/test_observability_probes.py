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
