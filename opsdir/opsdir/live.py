"""Effects: running a collector's calls against the live system, read-only (connectors.collecting stays pure and gets
run_call). A Command runs as a subprocess without a shell: its argv as declared, any credential it needs only on its
standard input, extra environment only switches. A Request is an HTTP GET made here (urllib; no other method), its
credential put in the Authorization header in memory, its endpoint trusted by the certificate its reference names
(ssl cadata) or the system's store. Credential references resolve through the secret-store adapters' commands (the
operator's own access to the store), once per run, held in memory only; a failing call's error output is shown with
every resolved value masked. Nothing is written anywhere but the caller's memory."""
import base64
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

COMMAND_SECONDS, REQUEST_SECONDS, SECRET_SECONDS = 300, 120, 60


def _resolve(ref, installed):
    """(value, problem) of a credential (or certificate) reference, through its store's adapter."""
    try:
        cmd = secret_command(ref, installed)
    except SystemExit as e:
        return None, str(e)
    try:
        done = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=SECRET_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, f"resolving {ref}: {type(e).__name__}"
    if done.returncode:
        return None, f"resolving {ref} failed (exit {done.returncode}): {done.stderr.strip()[-300:] or 'no output'}"
    value = done.stdout[:-1] if done.stdout.endswith("\n") else done.stdout
    return (value, None) if value else (None, f"resolving {ref}: empty")


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
            (pathlib.Path(work) / name).write_text(text.replace("{dir}", work))
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
    with tempfile.TemporaryFile(mode="w+") as err:
        try:
            proc = subprocess.Popen(list(call.argv), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=err,
                                    text=True, env={**os.environ, **dict(call.env)})
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
                              text=True, env={**os.environ, **dict(call.env)}, timeout=COMMAND_SECONDS, check=False)
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
    """The headers carrying a resolved credential: Authorization (basic, bearer), or a login and a secret header."""
    scheme, _, login, *names = credential
    if scheme == "basic":
        return {"Authorization": "Basic " + base64.b64encode(f"{login}:{secret}".encode()).decode()}
    if scheme == "headers":
        login_header, secret_header = names[0]
        return {login_header: login, secret_header: secret}
    return {"Authorization": f"Bearer {secret}"}


def _request(call, resolve):
    refs = tuple(r for r in ((call.credential[1] if call.credential else None), call.ca) if r)
    secrets, problems = _secrets(refs, resolve)
    if problems:
        return None, "; ".join(problems)
    headers = {**dict(call.headers),
               **(_authorization(call.credential, secrets[call.credential[1]]) if call.credential else {})}
    try:
        context = ssl.create_default_context(cadata=secrets[call.ca]) if call.ca else ssl.create_default_context()
        req = urllib.request.Request(call.url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=REQUEST_SECONDS, context=context) as answer:
            return answer.read().decode("utf-8"), None
    except urllib.error.HTTPError as e:
        return (None, None) if e.code in call.absent else (None, f"HTTP {e.code} {e.reason}")
    except (urllib.error.URLError, ssl.SSLError, OSError, UnicodeDecodeError, ValueError) as e:
        return None, redact(f"{type(e).__name__}: {getattr(e, 'reason', e)}", tuple(secrets.values()))


def run_call(call, resolve):
    """(output, problem) of one call: a Command run as a subprocess, a Request made as an HTTP GET; (None, None) when
    it says there is nothing to read (its absent markers)."""
    return _request(call, resolve) if isinstance(call, Request) else _command(call, resolve)
