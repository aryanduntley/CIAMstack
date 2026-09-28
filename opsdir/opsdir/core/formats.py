"""File formats as data: the standard formats the core registers, and how a file's format is found and how a
generated-file header is written in it. Packages register further formats (HCL, a product's batch syntax, ...) the
same way; adapters declare which format each file they render is in."""
import json
from fnmatch import fnmatchcase

from .contract import Format
from .interchange.ldif import parse, write_records


def _ldif_records(text):
    return tuple(parse(text))


def _json_text(value):
    return json.dumps(value, indent=2) + "\n"


def _format(name, title, media_type, extensions, comment, read=None, write=None):
    return Format(name, title, media_type, tuple(extensions), tuple(comment), read, write)


LDIF = _format("ldif", "LDAP Data Interchange Format (RFC 2849)", "text/x-ldif", (".ldif",), ("#",),
               _ldif_records, write_records)
JSON = _format("json", "JSON (RFC 8259)", "application/json", (".json",), (), json.loads, _json_text)
XML = _format("xml", "XML", "application/xml", (".xml",), ("<!--", "-->"))
YAML = _format("yaml", "YAML", "application/yaml", (".yaml", ".yml"), ("#",))
SHELL = _format("shell", "POSIX shell / bash script", "text/x-shellscript", (".sh",), ("#",))
JAVA_PROPERTIES = _format("java-properties", "Java properties", "text/x-java-properties", (".properties",), ("#",))
INI = _format("ini", "INI configuration", "text/plain", (".ini", ".cfg", ".conf"), ("#",))
TOML = _format("toml", "TOML", "application/toml", (".toml",), ("#",))
CSV = _format("csv", "CSV (RFC 4180)", "text/csv", (".csv",), ())
C = _format("c", "C source or header", "text/x-c", (".c", ".h"), ("/*", "*/"))
JAVASCRIPT = _format("javascript", "JavaScript", "text/javascript", (".js",), ("//",))
GROOVY = _format("groovy", "Groovy", "text/x-groovy", (".groovy",), ("//",))
PYTHON = _format("python", "Python", "text/x-python", (".py",), ("#",))
POWERSHELL = _format("powershell", "PowerShell", "text/x-powershell", (".ps1",), ("#",))
SQL = _format("sql", "SQL", "application/sql", (".sql",), ("--",))
HTML = _format("html", "HTML", "text/html", (".html", ".htm"), ("<!--", "-->"))
MARKDOWN = _format("markdown", "Markdown", "text/markdown", (".md",), ("<!--", "-->"))
PEM = _format("pem", "PEM certificate or public key (RFC 7468)", "application/x-pem-file", (".pem", ".crt"), ())
TEXT = _format("text", "Plain text", "text/plain", (".txt",), ())


def format_of(path, declarations):
    """The format a path is declared in: the first (glob, format name) whose glob matches it, else None."""
    return next((name for glob, name in declarations if fnmatchcase(path, glob)), None)


def comment_lines(fmt, lines):
    """Lines as comments in the format's syntax; () when the format has no comments."""
    if len(fmt.comment) == 1:
        return tuple(f"{fmt.comment[0]} {line}".rstrip() for line in lines)
    if len(fmt.comment) == 2:
        start, end = fmt.comment
        return (start, *(f"  {line}".rstrip() for line in lines), end)
    return ()


def generated_header(fmt, lines):
    """The do-not-edit header of a generated file (SPEC R10), in its format's comment syntax ("" when the format has
    no comments: the MANIFEST records the file instead)."""
    body = comment_lines(fmt, lines)
    return "\n".join(body) + "\n" if body else ""
