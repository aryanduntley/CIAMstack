"""Every file CIAMstack reads and writes is UTF-8 with LF line endings whatever the locale: no text read or write in
the core, its scripts or the adapter packages leaves the encoding (or, on writes, the newline) to the locale, and the
CLI's standard streams are UTF-8 even where the locale is not."""
import ast
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[3]
CORE = ROOT / "opsdir"
SKIPPED_DIRS = frozenset({"tests", ".venv", "__pycache__"})
SUBPROCESS_TEXT = frozenset({"run", "Popen", "check_output"})
TEMPFILES = frozenset({"TemporaryFile", "NamedTemporaryFile", "SpooledTemporaryFile"})


def _keywords(call):
    """The keyword names a call passes; None when it passes **kwargs (what it passes is then unknown)."""
    names = frozenset(k.arg for k in call.keywords)
    return None if None in names else names


def _argument(call, position, name):
    """The node passed by position or by name, or None."""
    named = next((k.value for k in call.keywords if k.arg == name), None)
    return named if named is not None else (call.args[position] if len(call.args) > position else None)


def _text_mode(node, default_text):
    """Whether a mode argument opens in text mode: a string without 'b'; the default when absent; False when it is not
    a literal (it cannot be told, so it is not flagged)."""
    if node is None:
        return default_text
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and "b" not in node.value


def _is_true(call, name):
    return any(k.arg == name and isinstance(k.value, ast.Constant) and k.value.value is True for k in call.keywords)


def _module_call(call, module, names):
    """Whether the call is module.<one of names>(...)."""
    f = call.func
    return isinstance(f, ast.Attribute) and f.attr in names and isinstance(f.value, ast.Name) and f.value.id == module


def _call_problems(call):
    """What one call leaves to the locale, as messages."""
    given = _keywords(call)
    if given is None:
        return ()
    f = call.func
    method = f.attr if isinstance(f, ast.Attribute) else None
    found = (
        (method in ("read_text", "write_text") and "encoding" not in given, f".{method}() without encoding"),
        (method == "write_text" and "newline" not in given, ".write_text() without newline"),
        (isinstance(f, ast.Name) and f.id == "open" and _text_mode(_argument(call, 1, "mode"), True)
         and "encoding" not in given, "open() in text mode without encoding"),
        (_module_call(call, "subprocess", SUBPROCESS_TEXT) and (_is_true(call, "text")
                                                                 or _is_true(call, "universal_newlines"))
         and "encoding" not in given, f"subprocess.{method}() in text mode without encoding"),
        (_module_call(call, "tempfile", TEMPFILES) and _text_mode(_argument(call, 0, "mode"), False)
         and "encoding" not in given, f"tempfile.{method}() in text mode without encoding"),
    )
    return tuple(message for bad, message in found if bad)


def source_problems(source, name="<source>"):
    """Each text read or write in a module's source that leaves its encoding or newline to the locale, as
    'name:line: problem'."""
    return tuple(f"{name}:{node.lineno}: {problem}" for node in ast.walk(ast.parse(source, name))
                 if isinstance(node, ast.Call) for problem in _call_problems(node))


def checked_files(root=ROOT):
    """The Python files the guard reads: the core, its scripts and every package's src, without tests or venvs."""
    tops = (root / "opsdir" / "opsdir", root / "opsdir" / "scripts", *sorted((root / "packages").glob("*/src")))
    return tuple(sorted(p for top in tops for p in top.rglob("*.py")
                        if not SKIPPED_DIRS.intersection(p.relative_to(top).parts)))


def test_the_checker_flags_each_rule_and_passes_its_fix():
    cases = (
        ("p.read_text()", "p.read_text(encoding='utf-8')"),
        ("p.write_text(t, encoding='utf-8')", "p.write_text(t, encoding='utf-8', newline='\\n')"),
        ("p.write_text(t, newline='\\n')", "p.write_text(t, encoding='utf-8', newline='\\n')"),
        ("open(p)", "open(p, encoding='utf-8')"),
        ("open(p, 'w')", "open(p, 'wb')"),
        ("open(p, mode='a')", "open(p, mode='a', encoding='utf-8')"),
        ("subprocess.run(a, text=True)", "subprocess.run(a, text=True, encoding='utf-8')"),
        ("subprocess.Popen(a, universal_newlines=True)", "subprocess.Popen(a, stdout=subprocess.PIPE)"),
        ("subprocess.check_output(a, text=True)", "subprocess.check_output(a)"),
        ("tempfile.TemporaryFile(mode='w+')", "tempfile.TemporaryFile()"),
        ("tempfile.NamedTemporaryFile('r+')", "tempfile.NamedTemporaryFile('r+', encoding='utf-8')"),
    )
    assert [(bool(source_problems(bad)), source_problems(good)) for bad, good in cases] == [(True, ())] * len(cases)
    assert source_problems("x = 1\np.read_text()", "m.py") == ("m.py:2: .read_text() without encoding",)
    assert source_problems("open(p, mode)\np.read_text(**options)") == ()      # not told by the source: not flagged


def test_no_text_read_or_write_leaves_its_encoding_or_newline_to_the_locale():
    files = checked_files()
    assert any(p.name == "cli.py" for p in files) and any("packages" in p.parts for p in files)
    problems = [problem for p in files
                for problem in source_problems(p.read_text(encoding="utf-8"), str(p.relative_to(ROOT)))]
    assert problems == []


def test_onboarding_setup_keeps_non_ascii_answers_under_a_non_utf8_locale(tmp_path):
    out = tmp_path / "answers.toml"
    name = "Société Ünïcode"
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0",
           "PYTHONIOENCODING": "latin-1",
           "PYTHONPATH": os.pathsep.join((str(CORE), *filter(None, (os.environ.get("PYTHONPATH"),))))}
    # org, its name, no operating team, no other team, not one-person, no environment, no export: then end of input
    replies = f"exa\n{name}\n\n\nn\n\n\n".encode("utf-8")
    done = subprocess.run([sys.executable, "-m", "opsdir", "onboard", "setup", "-o", str(out)], input=replies,
                          capture_output=True, env=env, cwd=tmp_path, timeout=120)
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")
    written = out.read_bytes()
    assert b"\r" not in written
    assert f'name = "{name}"' in written.decode("utf-8")
    assert name in done.stdout.decode("utf-8")
