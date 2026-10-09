"""YAML as opsdir writes it: deterministic block style that every YAML reader reads back as the same value; strings
that a YAML 1.1 or 1.2 reader would take for something else are quoted; multi-line strings are literal blocks."""
import pytest

from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import documents, dump, scalar

yaml = pytest.importorskip("yaml")      # PyYAML reads by YAML 1.1 rules: the strictest reader at hand

MANIFEST = {"apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": "ds-idrepo", "namespace": "identity", "labels": {"app.kubernetes.io/name": "ds"},
                         "annotations": {}},
            "spec": {"replicas": 3, "template": {"spec": {
                "containers": [{"name": "ds", "image": "registry.example.test/ds:7.5.0",
                                "args": ["start", "--quiet"], "resources": {"requests": {"cpu": "500m"}},
                                "env": [{"name": "PORT", "value": "1636"}]}],
                "volumes": []}}}}


def test_a_manifest_reads_back_and_looks_like_kubectl_writes_it():
    text = dump(MANIFEST)
    assert yaml.safe_load(text) == MANIFEST
    assert text.splitlines()[:6] == ["apiVersion: apps/v1", "kind: StatefulSet", "metadata:", "  name: ds-idrepo",
                                     "  namespace: identity", "  labels:"]
    assert "  annotations: {}" in text and "      volumes: []" in text
    assert "      containers:\n      - name: ds\n        image: registry.example.test/ds:7.5.0\n" in text
    assert dump(MANIFEST) == text


@pytest.mark.parametrize("s", ["yes", "No", "on", "OFF", "y", "true", "False", "null", "~", "", "1636", "0.5", "1e3",
                               "0x1F", "012", "1_000", "2026-10-09", "1:30", ".inf", "-", "- a", "a: b", "a #b",
                               "trailing ", " leading", "end:", "*alias", "&anchor", "!tag", "%dir", "@at", "`tick",
                               "{x}", "[x]", "'q'", '"q"', "?", "|", ">", "#c", "100Gi", "ümlaut", "tab\there", "<<"])
def test_strings_that_could_read_as_something_else_are_quoted(s):
    assert yaml.safe_load(dump({"k": s})) == {"k": s}
    assert yaml.safe_load(dump([s])) == [s]
    assert yaml.safe_load(dump({s: 1})) == {s: 1}


def test_safe_strings_stay_plain():
    assert [scalar(s) for s in ("ds", "registry.example.test/am:8.0.1", "http://am:8080/am", "Prefix", "a-b_c",
                                "a b c", "key=value,x")] == \
        ["ds", "registry.example.test/am:8.0.1", "http://am:8080/am", "Prefix", "a-b_c", "a b c", "key=value,x"]
    assert [scalar(v) for v in (None, True, False, 3, 2.5)] == ["null", "true", "false", "3", "2.5"]


@pytest.mark.parametrize("s", ["line one\nline two\n", "no trailing\nnewline", "two\nblank\n\n\n",
                               "inner\n\nblank\n", "  indented first\nline\n", "trailing space \nx\n"])
def test_multi_line_strings_read_back_exactly(s):
    text = dump({"conf": s, "list": [s]})
    assert yaml.safe_load(text) == {"conf": s, "list": [s]}


def test_a_literal_block_when_it_can_be_one():
    assert dump({"conf": "a\nb\n"}) == "conf: |\n  a\n  b\n"
    assert dump({"conf": "a\nb"}) == "conf: |-\n  a\n  b\n"


def test_nested_lists_and_empty_values():
    value = {"m": [[1, 2], [], {}, [{"a": [3]}]], "e": {}, "n": None}
    assert yaml.safe_load(dump(value)) == value
    assert dump([]) == "[]\n" and dump({}) == "{}\n" and dump("x") == "x\n"


def test_several_documents():
    text = documents(({"kind": "Namespace"}, {"kind": "ServiceAccount", "metadata": {"name": "am"}}))
    assert list(yaml.safe_load_all(text)) == [{"kind": "Namespace"}, {"kind": "ServiceAccount",
                                                                      "metadata": {"name": "am"}}]
    assert text == "kind: Namespace\n---\nkind: ServiceAccount\nmetadata:\n  name: am\n"


def test_what_isnt_json_shaped_is_refused():
    with pytest.raises(TypeError):
        dump({"k": object()})
    with pytest.raises(ValueError):
        dump({"k": float("nan")})


def test_the_registered_format_writes_with_it():
    assert YAML.write is dump and YAML.write({"a": 1}) == "a: 1\n"
