"""A collection source's credential as a client certificate (ciamCredentialScheme client-certificate: mutual TLS):
the reference resolves to a PEM holding the certificate, its chain and private key, loaded into the request's TLS
context through an anonymous in-memory file (never a file on disk) and presented in the handshake, with no
Authorization header; a read-only query's body (EJBCA's certificate search) is posted the same way. Proved against a
local TLS server that requires a client certificate, with throwaway certificates openssl makes in a temporary
directory."""
import http.server
import os
import shutil
import ssl
import subprocess
import threading

import pytest

from opsdir import live
from opsdir.core.contract import Request

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None or not hasattr(os, "memfd_create"),
                                reason="needs openssl and memfd")


def _openssl(cwd, *args):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _issued(cwd, name, cn, usage, san=None):
    """A key and certificate for cn signed by the test CA in cwd (usage: serverAuth or clientAuth; san: a
    subjectAltName), with the extensions strict verification asks for."""
    _openssl(cwd, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", f"{name}.key",
             "-out", f"{name}.csr", "-subj", f"/CN={cn}")
    ext = cwd / f"{name}.ext"
    ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                   f"extendedKeyUsage={usage}\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n"
                   + (f"subjectAltName={san}\n" if san else ""))
    _openssl(cwd, "x509", "-req", "-in", f"{name}.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
             "-out", f"{name}.crt", "-days", "2", "-extfile", ext.name)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    cwd = tmp_path_factory.mktemp("mtls")
    _openssl(cwd, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
             "ca.key", "-out", "ca.crt", "-days", "2", "-subj", "/CN=opsdir test CA", "-addext",
             "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    _issued(cwd, "server", "127.0.0.1", "serverAuth", "IP:127.0.0.1")
    _issued(cwd, "client", "opsdir-reader", "clientAuth")
    return cwd


def _serving(pki):
    """A one-request HTTPS server requiring a client certificate the test CA issued; what it saw is appended to the
    list returned."""
    seen = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            subject = dict(x[0] for x in self.connection.getpeercert()["subject"])
            seen.append((self.path, subject.get("commonName"), self.headers.get("Authorization")))
            body = b'{"result": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            subject = dict(x[0] for x in self.connection.getpeercert()["subject"])
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
            seen.append((self.path, subject.get("commonName"), self.headers.get("Content-Type"), body))
            answer = b'{"certificates": []}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(answer)))
            self.end_headers()
            self.wfile.write(answer)

        def log_message(self, *args):
            pass
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(pki / "server.crt", pki / "server.key")
    tls.load_verify_locations(pki / "ca.crt")
    tls.verify_mode = ssl.CERT_REQUIRED
    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.handle_error = lambda *args: None
    threading.Thread(target=server.handle_request, daemon=True).start()
    return server, seen


def _resolver(pki):
    pem = (pki / "client.crt").read_text() + (pki / "client.key").read_text()
    values = {"fake://client": pem, "fake://ca": (pki / "ca.crt").read_text()}
    return lambda ref: (values[ref], None) if ref in values else (None, f"unknown {ref}")


def test_a_client_certificate_is_presented_in_the_handshake_with_no_authorization_header(pki):
    server, seen = _serving(pki)
    url = f"https://127.0.0.1:{server.server_port}/api/now/table/change_request"
    out, problem = live.run_call(Request(url, (), ("client-certificate", "fake://client", None), "fake://ca"),
                                 _resolver(pki))
    server.server_close()
    assert (out, problem) == ('{"result": []}', None)
    assert seen == [("/api/now/table/change_request", "opsdir-reader", None)]


def test_a_query_body_is_posted_as_json_over_mutual_tls(pki):
    server, seen = _serving(pki)
    url = f"https://127.0.0.1:{server.server_port}/ejbca/ejbca-rest-api/v2/certificate/search"
    body = '{"criteria": [{"property": "CA", "value": "Issuing CA", "operation": "EQUAL"}]}'
    out, problem = live.run_call(Request(url, (), ("client-certificate", "fake://client", None), "fake://ca",
                                         body=body), _resolver(pki))
    server.server_close()
    assert (out, problem) == ('{"certificates": []}', None)
    assert seen == [("/ejbca/ejbca-rest-api/v2/certificate/search", "opsdir-reader", "application/json", body)]


def test_without_one_the_server_refuses_the_handshake(pki):
    server, seen = _serving(pki)
    url = f"https://127.0.0.1:{server.server_port}/api/now/table/change_request"
    out, problem = live.run_call(Request(url, (), ("basic", "fake://ca", "reader"), "fake://ca"), _resolver(pki))
    server.server_close()
    assert out is None and problem and not seen


def test_a_pem_that_isnt_a_certificate_and_key_is_named_and_masked(pki):
    resolve = lambda ref: ("-----BEGIN NOTHING-----\nc2VjcmV0\n-----END NOTHING-----\n", None) \
        if ref == "fake://client" else _resolver(pki)(ref)
    out, problem = live.run_call(Request("https://127.0.0.1:9/x", (), ("client-certificate", "fake://client", None),
                                         "fake://ca"), resolve)
    assert out is None and problem.startswith("SSLError") and "c2VjcmV0" not in problem


def test_without_memfd_a_client_certificate_is_never_loaded_from_disk(monkeypatch):
    monkeypatch.delattr(os, "memfd_create")
    problem = live.load_client_certificate(ssl.create_default_context(), "unused")
    assert problem.startswith("a client certificate is loaded only through an in-memory file (memfd)")
