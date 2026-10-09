"""File formats as data: registered like domains and adapters, declared by adapters for every file they render,
recorded in the MANIFEST, and used for generated-file headers."""
import json

import pytest

from opsdir.connectors.registry import FORMATS, format_named
from opsdir.connectors.render import file_formats, render_env
from opsdir.core.formats import C, JSON, LDIF, SHELL, XML, comment_lines, format_of, generated_header
import mini_estate
from mini_estate import FAKE

ALPHA = "alpha/prod"


def test_the_core_registers_the_standard_formats_by_name():
    names = [f.name for f in FORMATS]
    assert names == sorted(names) and len(set(names)) == len(names)
    assert {"ldif", "json", "xml", "yaml", "shell", "java-properties", "ini", "toml", "csv", "c", "javascript",
            "groovy", "python", "powershell", "sql", "html", "markdown", "pem", "text"} <= set(names)
    assert format_named("c") == C and format_named("nosuch") is None


def test_a_formats_reader_and_writer_are_its_own():
    assert JSON.read(JSON.write({"a": [1]})) == {"a": [1]}
    (record,) = LDIF.read("dn: cn=x,dc=test\ncn: x\n")
    assert record.dn == "cn=x,dc=test" and XML.read is None


def test_the_first_matching_declaration_gives_a_files_format():
    declared = (("ds/setup-*.sh", "shell"), ("ds/*", "text"), ("*.json", "json"))
    assert [format_of(p, declared) for p in ("ds/setup-1.sh", "ds/notes", "a/b/c.json", "x.xml")] == [
        "shell", "text", "json", None]


def test_headers_are_written_in_the_formats_comment_syntax():
    assert comment_lines(SHELL, ("one", "")) == ("# one", "#")
    assert comment_lines(C, ("one",)) == ("/*", "  one", "*/")
    assert generated_header(XML, ("do not edit",)) == "<!--\n  do not edit\n-->\n"
    assert generated_header(JSON, ("do not edit",)) == ""                 # no comments: the MANIFEST says it


def test_the_manifest_records_each_files_format():
    _, files = render_env(mini_estate.directory(), ALPHA, (FAKE,))
    assert {p: f["format"] for p, f in json.loads(files["MANIFEST.json"])["files"].items()} == {
        "fake/env.txt": "text", "fake/neutral.txt": "text"}


def test_a_file_in_no_declared_format_is_refused():
    with pytest.raises(SystemExit, match="no adapter declares the format of: fake/env.txt"):
        render_env(mini_estate.directory(), ALPHA, (FAKE._replace(formats=(("fake/neutral.txt", "text"),)),))


def test_a_file_in_a_format_nothing_registers_is_refused():
    odd = FAKE._replace(formats=(("fake/*", "cobol-copybook"),))
    with pytest.raises(SystemExit, match="formats no installed package registers: fake/env.txt \\(cobol-copybook"):
        file_formats((odd,), ("fake/env.txt",))
