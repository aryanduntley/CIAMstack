"""The requests a scripted synthetic check makes, as the source a cloud's check script carries: Python (PYTHON_PROBES:
AWS CloudWatch Synthetics canaries, Azure Container Apps jobs) and Node.js (NODE_PROBES, a CommonJS module: Google Cloud
synthetic monitors), cloud-neutral, standard library only, the same checks in both. Each cloud's script adds how it
reads its credentials when it runs and how it reports; probe(flow, url, creds) does the request and returns what to
log, raising (Node.js: rejecting) on failure. Pure (text).

- health, login-page, saml-sso: GET the URL, redirects followed; an answer of 400 or more fails.
- oidc-token: a client-credentials grant at the token endpoint (HTTP Basic with creds' client_id and client_secret);
  an answer without an access_token fails.
- ldap-bind: an LDAP simple bind over TLS (RFC 4511, the BER encoded here) as creds' bind_dn and password, anonymous
  without creds; a result code other than success (0) fails.
TLS certificates are verified against the runtime's trust store.
"""

PYTHON_PROBES = '''import base64
import json
import socket
import ssl
import urllib.parse
import urllib.request

TIMEOUT = 10


def get(url):
    """GET the URL, redirects followed: urllib raises on an answer of 400 or more."""
    with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=TIMEOUT) as response:
        return f"HTTP {response.status}"


def token(url, creds):
    """A client-credentials grant at the token endpoint must return an access token."""
    basic = base64.b64encode(f"{creds['client_id']}:{creds['client_secret']}".encode()).decode()
    request = urllib.request.Request(url, data=urllib.parse.urlencode({"grant_type": "client_credentials"}).encode(),
                                     method="POST", headers={"Authorization": f"Basic {basic}",
                                                             "Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        if not json.loads(response.read()).get("access_token"):
            raise Exception(f"{url}: no access_token in the answer")
        return f"HTTP {response.status}, access token issued"


def _element(tag, body):
    """A BER element: its tag, its definite length, its body."""
    size = len(body).to_bytes((len(body).bit_length() + 7) // 8 or 1, "big")
    return bytes([tag]) + (size if len(body) < 128 else bytes([0x80 | len(size)]) + size) + body


def _read(stream, count):
    data = b""
    while len(data) < count:
        chunk = stream.recv(count - len(data))
        if not chunk:
            raise Exception("the connection closed before the bind response")
        data += chunk
    return data


def _response(stream):
    """The body of the LDAPMessage the server answers with."""
    _, first = _read(stream, 2)
    size = int.from_bytes(_read(stream, first & 0x7F), "big") if first & 0x80 else first
    return _read(stream, size)


def _parts(body):
    """The (tag, body) elements a constructed element holds."""
    at, parts = 0, []
    while at < len(body):
        first = body[at + 1]
        width = first & 0x7F if first & 0x80 else 0
        size = int.from_bytes(body[at + 2:at + 2 + width], "big") if width else first
        start = at + 2 + width
        parts.append((body[at], body[start:start + size]))
        at = start + size
    return parts


def ldap_bind(url, creds):
    """An LDAP simple bind over TLS must succeed (result code 0); anonymous without creds."""
    dn, password = (creds["bind_dn"], creds["password"]) if creds else ("", "")
    bind = _element(0x60, _element(0x02, b"\\x03") + _element(0x04, dn.encode()) + _element(0x80, password.encode()))
    where = urllib.parse.urlsplit(url)
    with socket.create_connection((where.hostname, where.port), timeout=TIMEOUT) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname=where.hostname) as stream:
            stream.sendall(_element(0x30, _element(0x02, b"\\x01") + bind))
            (_, _), (op, result) = _parts(_response(stream))[:2]
    code = _parts(result)[0][1][0] if op == 0x61 else None
    if code != 0:
        raise Exception(f"{url}: the bind failed (result code {code})")
    return f"bound as {dn or 'anonymous'}"


def probe(flow, url, creds):
    """The check a flow makes: what to log when it passes; raises when it fails."""
    return token(url, creds) if flow == "oidc-token" else ldap_bind(url, creds) if flow == "ldap-bind" else get(url)
'''


NODE_PROBES = r'''"use strict";
const https = require("https");
const tls = require("tls");

const TIMEOUT = 10000;
const REDIRECTS = 5;

function request(url, options, body) {
  // One HTTPS request: resolves {status, headers, body}.
  return new Promise((resolve, reject) => {
    const req = https.request(url, {timeout: TIMEOUT, ...options}, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({status: res.statusCode, headers: res.headers,
                                   body: Buffer.concat(chunks).toString()}));
    });
    req.on("timeout", () => req.destroy(new Error(`${url}: no answer in ${TIMEOUT / 1000}s`)));
    req.on("error", reject);
    req.end(body);
  });
}

async function get(url, left = REDIRECTS) {
  // GET the URL, redirects followed: an answer of 400 or more fails.
  const res = await request(url, {method: "GET"});
  if (res.status >= 300 && res.status < 400 && res.headers.location && left > 0) {
    return get(new URL(res.headers.location, url).toString(), left - 1);
  }
  if (res.status >= 400) {
    throw new Error(`${url}: HTTP ${res.status}`);
  }
  return `HTTP ${res.status}`;
}

async function token(url, creds) {
  // A client-credentials grant at the token endpoint must return an access token.
  const basic = Buffer.from(`${creds.client_id}:${creds.client_secret}`).toString("base64");
  const res = await request(url, {method: "POST", headers: {"Authorization": `Basic ${basic}`,
                                                            "Content-Type": "application/x-www-form-urlencoded"}},
                            "grant_type=client_credentials");
  if (res.status >= 400) {
    throw new Error(`${url}: HTTP ${res.status}`);
  }
  if (!JSON.parse(res.body).access_token) {
    throw new Error(`${url}: no access_token in the answer`);
  }
  return `HTTP ${res.status}, access token issued`;
}

function element(tag, body) {
  // A BER element: its tag, its definite length, its body.
  let size = [];
  for (let n = body.length; n > 0; n = Math.floor(n / 256)) {
    size.unshift(n % 256);
  }
  size = size.length ? size : [0];
  const length = body.length < 128 ? [body.length] : [0x80 | size.length, ...size];
  return Buffer.concat([Buffer.from([tag, ...length]), body]);
}

function parts(body) {
  // The [tag, body] elements a constructed element holds.
  const found = [];
  for (let at = 0; at < body.length;) {
    const first = body[at + 1];
    const width = first & 0x80 ? first & 0x7f : 0;
    const size = width ? body.subarray(at + 2, at + 2 + width).reduce((a, b) => a * 256 + b, 0) : first;
    const start = at + 2 + width;
    found.push([body[at], body.subarray(start, start + size)]);
    at = start + size;
  }
  return found;
}

function bindRequest(dn, password) {
  const bind = element(0x60, Buffer.concat([element(0x02, Buffer.from([3])), element(0x04, Buffer.from(dn)),
                                            element(0x80, Buffer.from(password))]));
  return element(0x30, Buffer.concat([element(0x02, Buffer.from([1])), bind]));
}

function bindResult(message) {
  // The result code of a bindResponse LDAPMessage, or null.
  const [, [op, result]] = parts(parts(message)[0][1]);
  return op === 0x61 ? parts(result)[0][1][0] : null;
}

function ldapBind(url, creds) {
  // An LDAP simple bind over TLS must succeed (result code 0); anonymous without creds.
  const [dn, password] = creds ? [creds.bind_dn, creds.password] : ["", ""];
  const where = new URL(url);
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const socket = tls.connect({host: where.hostname, port: Number(where.port), servername: where.hostname,
                                timeout: TIMEOUT}, () => socket.write(bindRequest(dn, password)));
    socket.on("data", (chunk) => {
      data = Buffer.concat([data, chunk]);
      const first = data[1];
      const width = first & 0x80 ? first & 0x7f : 0;
      const size = width ? data.subarray(2, 2 + width).reduce((a, b) => a * 256 + b, 0) : first;
      if (data.length >= 2 + width + size) {
        socket.end();
        const code = bindResult(data.subarray(0, 2 + width + size));
        code === 0 ? resolve(`bound as ${dn || "anonymous"}`)
                   : reject(new Error(`${url}: the bind failed (result code ${code})`));
      }
    });
    socket.on("timeout", () => socket.destroy(new Error(`${url}: no answer in ${TIMEOUT / 1000}s`)));
    socket.on("error", reject);
    socket.on("end", () => reject(new Error("the connection closed before the bind response")));
  });
}

async function probe(flow, url, creds) {
  // The check a flow makes: what to log when it passes; rejects when it fails.
  return flow === "oidc-token" ? token(url, creds) : flow === "ldap-bind" ? ldapBind(url, creds) : get(url);
}

module.exports = {probe, get, token, ldapBind, element, parts, bindRequest, bindResult};
'''
