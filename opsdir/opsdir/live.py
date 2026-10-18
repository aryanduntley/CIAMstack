"""Effects: running a collector's calls against the live system, read-only (connectors.collecting stays pure and gets
run_call). A Command runs as a subprocess without a shell: its argv as declared, any credential it needs only on its
standard input, extra environment only switches. A Request is an HTTP GET made here (urllib), or the POST of a
read-only query's body (a search the endpoint answers without changing anything; connectors.collecting refuses any POST
its collector doesn't declare a query, so none reaches here), its credential put in the Authorization header in memory
(or, a client certificate, loaded into the TLS context through an anonymous in-memory file: never a file on disk), its
endpoint trusted by the certificate its reference names (ssl
cadata) or the system's store. Credential references resolve through the secret-store adapters' commands (the
operator's own access to the store), once per run, held in memory only; a failing call's error output is shown with
every resolved value masked. Nothing is written anywhere but the caller's memory."""
import base64
import datetime as dt
import functools
import os
import pathlib
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request

from .connectors.collecting import redact
from .connectors.registry import ADAPTERS, secret_command
from .core.contract import Request
from .core.observation import observation

COMMAND_SECONDS, REQUEST_SECONDS, SECRET_SECONDS = 300, 120, 60
CLIENT_CERTIFICATE = "client-certificate"     # the credential scheme presenting a client certificate (mutual TLS)
OBSERVED_BYTES = 64 * 1024 * 1024       # the most an observed endpoint's answer may be (a large CA's CRL is megabytes)


def _resolve(ref, installed):
    """(value, problem) of a credential (or certificate) reference, through its store's adapter."""
    try:
        cmd = secret_command(ref, installed)
    except SystemExit as e:
        return None, str(e)
    try:
        done = subprocess.run(["sh", "-c", cmd], capture_output=True, encoding="utf-8", timeout=SECRET_SECONDS,
                              check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"resolving {ref}: {type(e).__name__}"
    if done.returncode:
        return None, f"resolving {ref} failed (exit {done.returncode}): {done.stderr.strip()[-300:] or 'no output'}"
    value = done.stdout[:-1] if done.stdout.endswith("\n") else done.stdout
    return (value, None) if value else (None, f"resolving {ref}: empty")


def db_token(argv):
    """Effect: the sign-in token a database token command prints (an adapter's Adapter.db_tokens command, run with the
    operator's or the server's own cloud identity), held in memory only; exits with its error output when it fails."""
    try:
        done = subprocess.run(list(argv), capture_output=True, encoding="utf-8", timeout=SECRET_SECONDS, check=False)
    except FileNotFoundError:
        raise SystemExit(f"{argv[0]} is not installed here: the database sign-in token needs it") from None
    except subprocess.TimeoutExpired:
        raise SystemExit(f"no database sign-in token from {argv[0]} in {SECRET_SECONDS} s") from None
    token = done.stdout.strip()
    if done.returncode or not token:
        raise SystemExit(f"getting the database sign-in token failed (exit {done.returncode}): "
                         f"{done.stderr.strip()[-300:] or 'no output'}")
    return token


def resolver(installed=ADAPTERS):
    """resolve(ref) -> (value, problem), each reference resolved once for the run (held in memory only)."""
    return functools.lru_cache(maxsize=None)(lambda ref: _resolve(ref, installed))


def _secrets(refs, resolve):
    found = {r: resolve(r) for r in refs}
    return {r: v for r, (v, _) in found.items()}, tuple(p for _, (_, p) in found.items() if p)


def _text(f):
    """A regular file's UTF-8 text, else None (a link, which could point anywhere, or not text)."""
    try:
        return None if f.is_symlink() else f.read_text(encoding="utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _written(root):
    """{relative path: text, or None when it isn't a regular UTF-8 file} of the files a tool wrote under root; a
    repository's .git is never read."""
    found = {f.relative_to(root).as_posix(): f for f in sorted(pathlib.Path(root).rglob("*"))
             if (f.is_file() or f.is_symlink()) and ".git" not in f.relative_to(root).parts}
    return {rel: _text(f) for rel, f in found.items()}


def _in_workdir(call, secrets):
    """(output, problem) of a workdir command: run in a private directory, its files under export/ the output."""
    with tempfile.TemporaryDirectory(prefix="opsdir-collect-") as work:
        os.chmod(work, 0o700)
        for name, text in call.inputs:
            (pathlib.Path(work) / name).write_text(text.replace("{dir}", work), encoding="utf-8", newline="\n")
        (pathlib.Path(work) / "export").mkdir()
        out, problem = _run(call._replace(argv=tuple(a.replace("{dir}", work) for a in call.argv), workdir=False),
                            secrets)
        if problem:
            return None, problem
        try:
            return _written(pathlib.Path(work) / "export"), None
        except OSError as e:
            return None, f"reading what it wrote: {type(e).__name__}"


def _command(call, resolve):
    secrets, problems = _secrets(call.secrets, resolve)
    if problems:
        return None, "; ".join(problems)
    return _in_workdir(call, secrets) if call.workdir else _run(call, secrets)


def _streamed(call, secrets):
    """(output, problem) of a digest command: its standard output read line by line through the digest as it comes,
    never held whole; its error output kept aside in a temporary file for the failure message."""
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as err:
        try:
            proc = subprocess.Popen(list(call.argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
                                    encoding="utf-8", env={**os.environ, **dict(call.env)})
        except FileNotFoundError:
            return None, f"{call.argv[0]} is not installed here"
        if call.stdin:
            proc.stdin.write(call.stdin(secrets))
        proc.stdin.close()
        try:
            out = call.digest(proc.stdout)
        except ValueError as e:
            proc.kill()
            return None, redact(str(e), tuple(secrets.values()))
        code = proc.wait(timeout=COMMAND_SECONDS)
        err.seek(0)
        if code:
            shown = redact(err.read().strip()[-600:], tuple(secrets.values()))
            return None, f"exit {code}: {shown or 'no error output'}"
        return out, None


def _run(call, secrets):
    if call.digest:
        return _streamed(call, secrets)
    try:
        done = subprocess.run(list(call.argv), input=call.stdin(secrets) if call.stdin else None, capture_output=True,
                              encoding="utf-8", env={**os.environ, **dict(call.env)}, timeout=COMMAND_SECONDS,
                              check=False)
    except FileNotFoundError:
        return None, f"{call.argv[0]} is not installed here"
    except subprocess.TimeoutExpired:
        return None, f"no answer in {COMMAND_SECONDS} s"
    if done.returncode:
        if any(a in done.stderr for a in call.absent):
            return None, None                                   # nothing there to read
        err = redact(done.stderr.strip()[-600:], tuple(secrets.values()))
        return None, f"exit {done.returncode}: {err or 'no error output'}"
    return done.stdout, None


def _authorization(credential, secret):
    """The headers carrying a resolved credential: Authorization (basic, bearer, or token: the value as it is, a
    session token a product's own logon issued), a login and a secret header (headers), or the secret in the header
    the request names (api-key: an API key, no login), after the prefix the request gives when it gives one
    (Elasticsearch's 'ApiKey '); none for a client certificate (presented in the TLS handshake: _context)."""
    scheme, _, login, *names = credential
    if scheme == "basic":
        return {"Authorization": "Basic " + base64.b64encode(f"{login}:{secret}".encode()).decode()}
    if scheme == "headers":
        login_header, secret_header = names[0]
        return {login_header: login, secret_header: secret}
    if scheme == "api-key":
        return {names[0]: (names[1] if len(names) > 1 else "") + secret}
    if scheme == "token":
        return {"Authorization": secret}
    if scheme == CLIENT_CERTIFICATE:
        return {}
    return {"Authorization": f"Bearer {secret}"}


def load_client_certificate(context, pem):
    """Effect: load a client certificate, its chain and private key (PEM text) into an SSL context through an
    anonymous in-memory file (memfd, read back as /proc/self/fd/N: the ssl module reads certificates from paths only),
    never a file on disk; None when loaded, else why not (no memfd here)."""
    if not hasattr(os, "memfd_create") or not pathlib.Path("/proc/self/fd").is_dir():
        return ("a client certificate is loaded only through an in-memory file (memfd), which this system lacks: it is "
                "never written to disk")
    fd = os.memfd_create("opsdir-client-certificate", os.MFD_CLOEXEC)
    try:
        data = pem.encode("utf-8")
        while data:
            data = data[os.write(fd, data):]
        context.load_cert_chain(f"/proc/self/fd/{fd}")
    finally:
        os.close(fd)
    return None


def _context(call, secrets):
    """(the TLS context of a Request: its trust anchor, and its client certificate when its credential is one, or
    None, problem)."""
    context = ssl.create_default_context(cadata=secrets[call.ca]) if call.ca else ssl.create_default_context()
    if call.credential and call.credential[0] == CLIENT_CERTIFICATE:
        problem = load_client_certificate(context, secrets[call.credential[1]])
        if problem:
            return None, problem
    return context, None


def _http(call, headers):
    """The urllib request of a Request: a GET, or the POST of its query's body as JSON."""
    if call.body is None:
        return urllib.request.Request(call.url, headers=headers, method="GET")
    return urllib.request.Request(call.url, data=call.body.encode("utf-8"), method="POST",
                                  headers={"Content-Type": "application/json", **headers})


def _request(call, resolve):
    refs = tuple(r for r in ((call.credential[1] if call.credential else None), call.ca) if r)
    secrets, problems = _secrets(refs, resolve)
    if problems:
        return None, "; ".join(problems)
    headers = {**dict(call.headers),
               **(_authorization(call.credential, secrets[call.credential[1]]) if call.credential else {})}
    try:
        context, problem = _context(call, secrets)
        if problem:
            return None, problem
        req = _http(call, headers)
        with urllib.request.urlopen(req, timeout=REQUEST_SECONDS, context=context) as answer:
            return answer.read().decode("utf-8"), None
    except urllib.error.HTTPError as e:
        return (None, None) if e.code in call.absent else (None, f"HTTP {e.code} {e.reason}")
    except (urllib.error.URLError, ssl.SSLError, OSError, UnicodeDecodeError, ValueError) as e:
        return None, redact(f"{type(e).__name__}: {getattr(e, 'reason', e)}", tuple(secrets.values()))


def _answer(call, resolve):
    """(status, content type, body bytes, error) of an observing GET: whatever the endpoint answered (an HTTP error
    status with its body too), or why it answered nothing."""
    refs = tuple(r for r in ((call.credential[1] if call.credential else None), call.ca) if r)
    secrets, problems = _secrets(refs, resolve)
    if problems:
        return None, None, None, "; ".join(problems)
    headers = {**dict(call.headers),
               **(_authorization(call.credential, secrets[call.credential[1]]) if call.credential else {})}
    try:
        context, problem = _context(call, secrets)
        if problem:
            return None, None, None, problem
        req = urllib.request.Request(call.url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=REQUEST_SECONDS, context=context) as answer:
            body = answer.read(OBSERVED_BYTES + 1)
            return answer.status, answer.headers.get("Content-Type"), body, None
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type") if e.headers else None, e.read(OBSERVED_BYTES + 1), None
    except (urllib.error.URLError, ssl.SSLError, OSError, ValueError) as e:
        return None, None, None, redact(f"{type(e).__name__}: {getattr(e, 'reason', e)}", tuple(secrets.values()))


def _observe(call, resolve):
    """(output, None) of an observing GET: the endpoint's answer, or why it gave none, as the observation's text
    (core.observation), dated by this host's UTC clock; never a failed call."""
    at = dt.datetime.now(dt.UTC).replace(microsecond=0)
    status, content_type, body, error = _answer(call, resolve)
    if body is not None and len(body) > OBSERVED_BYTES:
        body, error = None, f"the answer is larger than {OBSERVED_BYTES} bytes: not kept"
    return observation(at, status, content_type, body, error), None


def run_call(call, resolve):
    """(output, problem) of one call: a Command run as a subprocess, a Request made as an HTTP GET or a query's POST
    (an observing one's answer, whatever it is, as its output); (None, None) when it says there is nothing to read
    (its absent markers)."""
    if isinstance(call, Request):
        return _observe(call, resolve) if call.observe else _request(call, resolve)
    return _command(call, resolve)
