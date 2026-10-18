"""No text I/O that depends on the server's locale: every text-mode read, write, open, temporary file, stream wrapper
and decoded subprocess in the shipped Python (the core, the packages and their scripts) names its encoding, and every
text write names its newline, so a server whose locale isn't UTF-8 reads and writes what a UTF-8 one does."""
import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCES = (ROOT / "opsdir" / "opsdir", ROOT / "opsdir" / "scripts", *sorted((ROOT / "packages").glob("*/src")),
           *sorted((ROOT / "packages").glob("*/scripts")))
SUBPROCESS = {"run", "Popen", "check_output", "call", "check_call"}
TEMPORARY = {"TemporaryFile", "NamedTemporaryFile", "SpooledTemporaryFile"}


def _keywords(call):
    return {k.arg: k.value for k in call.keywords if k.arg}


def _mode(call, position):
    value = _keywords(call).get("mode", call.args[position] if len(call.args) > position else None)
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, str) else None


def _true(node):
    return isinstance(node, ast.Constant) and node.value is True


def problem(call):
    """What a call leaves to the locale, or None."""
    f, kw = call.func, _keywords(call)
    name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
    if "encoding" in kw:
        return "write_text without newline=" if name == "write_text" and "newline" not in kw else None
    if name in ("read_text", "write_text"):
        return f"{name} without encoding="
    if name == "open" and isinstance(f, ast.Name) and "b" not in (_mode(call, 1) or "r"):
        return "open() in text mode without encoding="
    if name in TEMPORARY and "b" not in (_mode(call, 0) or "b"):
        return f"{name} in text mode without encoding="
    if name == "TextIOWrapper":
        return "TextIOWrapper without encoding="
    if name in SUBPROCESS and (_true(kw.get("text")) or _true(kw.get("universal_newlines"))):
        return f"subprocess {name} with text=True instead of encoding="
    return None


def findings():
    for source in SOURCES:
        for path in sorted(source.rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), str(path))):
                found = problem(node) if isinstance(node, ast.Call) else None
                if found:
                    yield f"{path.relative_to(ROOT)}:{node.lineno}: {found}"


def test_no_text_io_depends_on_the_locale():
    assert list(findings()) == []


def _call(code):
    return ast.parse(code).body[0].value


def test_the_check_sees_each_form():
    assert problem(_call("p.read_text()")) == "read_text without encoding="
    assert problem(_call("p.write_text(t, encoding='utf-8')")) == "write_text without newline="
    assert problem(_call("open(p, 'w')")) == "open() in text mode without encoding="
    assert problem(_call("tempfile.TemporaryFile(mode='w+')")) == "TemporaryFile in text mode without encoding="
    assert problem(_call("subprocess.run(a, text=True)")) == "subprocess run with text=True instead of encoding="
    assert problem(_call("io.TextIOWrapper(b)")) == "TextIOWrapper without encoding="
    for fine in ("p.read_text(encoding='utf-8')", "p.write_text(t, encoding='utf-8', newline='\\n')",
                 "open(p, 'rb')", "tempfile.TemporaryFile()", "subprocess.run(a, capture_output=True)",
                 "subprocess.run(a, encoding='utf-8')", "z.open(name)"):
        assert problem(_call(fine)) is None, fine
