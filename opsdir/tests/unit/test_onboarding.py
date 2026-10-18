"""Onboarding verification: the record rendered whole and read back says what the operator's original files said,
entry by entry and attribute by attribute; what differs is classified, and a loss, an alteration or something nothing
reads back fails it, unless its importer brings reference data no render writes."""
import datetime as dt

import pytest

from opsdir.connectors.onboarding import Difference, same_content, text_diff, verify
from opsdir.core.contract import Imported, Importer, ReadBack
from opsdir.core.directory import get, make_entry, one
from opsdir.domains.governance.imports import file_evidence, run_records
from mini_estate import ADAPTER_NAME, FAKE, FAKE_IMPORTER, directory

SSO = "cn=sso,ou=identity-services,dc=ciam-ops"
BASE = "ou=identity-services,dc=ciam-ops"
URL = "https://sso.example.test"
ORIGINAL = {"services/sso.url": URL + "\n"}
READS = (ReadBack("services", "fake/services/*", "fake/"),)
AT = dt.datetime(2026, 10, 18, 3, 0, tzinfo=dt.timezone.utc)


def _bare(files, d, patterns, at=None):
    """An export importer that brings only the URL (it keeps nothing of what the record holds)."""
    urls = {p.split("/")[-1][:-4]: t.strip() for p, t in files.items() if p.startswith("services/")}
    entries = tuple(make_entry(f"cn={n},{BASE}", ("top", "ciamIdentityService"), {"cn": (n,), "ciamBaseUrl": (u,)})
                    for n, u in urls.items())
    return Imported((make_entry(BASE, ("top", "organizationalUnit"), {"ou": ("identity-services",)}),),
                    tuple((e.dn, (e,)) for e in entries), ())


def _adapter(url_of=lambda m: one(get(m.d, SSO), "ciamBaseUrl"), reads=READS, importers=(FAKE_IMPORTER,)):
    return FAKE._replace(render_env=lambda m, services: {"fake/services/sso.url": url_of(m) + "\n"}, reads_back=reads,
                         formats=(*FAKE.formats, ("fake/services/*.url", "text")), importers=importers)


def _kinds(v):
    return [(x.dn, x.attr, x.kind) for x in v.differences]


def test_a_faithful_render_of_what_was_imported_passes():
    v = verify(directory(), ((f"{ADAPTER_NAME}/services", ORIGINAL),), (_adapter(),), AT)
    (checked,) = v.checked
    assert (v.status, v.differences, v.pairs, v.notices) == ("pass", (), (), ())
    assert checked.importer == f"{ADAPTER_NAME}/services" and checked.identical > 0 and checked.counts == {}


def test_a_render_that_loses_a_value_fails_and_keeps_both_files_for_a_text_diff():
    v = verify(directory(), ((f"{ADAPTER_NAME}/services", ORIGINAL),),
               (_adapter(lambda m: "https://elsewhere.example.test"),), AT)
    assert (v.status, _kinds(v)) == ("fail", [(SSO, "ciamBaseUrl", "loss")])
    (pair,) = v.pairs
    assert (pair.path, pair.environment, pair.layout_only) == ("services/sso.url", "alpha/prod", False)
    assert "-https://sso.example.test" in text_diff(pair) and "+https://elsewhere.example.test" in text_diff(pair)


def test_a_record_that_differs_from_the_originals_is_a_decided_change_when_the_render_follows_it():
    v = verify(directory(), ((f"{ADAPTER_NAME}/services", {"services/sso.url": "https://old.example.test\n"}),),
               (_adapter(),), AT)
    assert (v.status, v.differences) == ("pass", (Difference(
        f"{ADAPTER_NAME}/services", SSO, "ciamBaseUrl", "decided", ("https://old.example.test",), (URL,), (URL,)),))


def test_what_the_originals_lack_and_the_render_holds_from_the_record_is_a_gap_filled():
    adapter = _adapter(importers=(FAKE_IMPORTER, Importer("export", "the bare export", _bare)))
    v = verify(directory(), ((f"{ADAPTER_NAME}/export", ORIGINAL),), (adapter,), AT)
    assert v.status == "pass"
    assert {(x.attr, x.kind) for x in v.differences} == {(a, "gap-filled") for a in (
        "ciamEntityId", "ciamOidcIssuer", "ciamTargetRole")}


def test_what_nothing_reads_back_is_uncovered_unless_its_importer_brings_reference_data():
    unread = verify(directory(), ((f"{ADAPTER_NAME}/services", ORIGINAL),), (_adapter(reads=()),), AT)
    assert (unread.status, _kinds(unread)) == ("fail", [(SSO, "*", "uncovered")])
    reference = _adapter(reads=(), importers=(FAKE_IMPORTER._replace(reference=True),))
    by_design = verify(directory(), ((f"{ADAPTER_NAME}/services", ORIGINAL),), (reference,), AT)
    assert (by_design.status, _kinds(by_design)) == ("pass", [(SSO, "*", "by-design")])


def test_an_environment_that_cant_be_rendered_is_named_and_the_others_still_read_back():
    def url_of(m):
        if m.label == "beta/prod":
            raise SystemExit("no target for beta")
        return one(get(m.d, SSO), "ciamBaseUrl")
    v = verify(directory(), ((f"{ADAPTER_NAME}/services", ORIGINAL),), (_adapter(url_of),), AT)
    assert (v.status, v.notices) == ("pass", ("beta/prod: not rendered: no target for beta",))


def test_the_originals_are_checked_against_the_file_hashes_their_import_recorded():
    def given(record, files):
        return verify(record, ((f"{ADAPTER_NAME}/services", files),), (_adapter(),), AT).checked[0].warnings
    assert given(directory(), ORIGINAL) == (f"{ADAPTER_NAME}/services: no import run of these scopes: these originals "
                                            "were never imported",)
    imported = directory(run_records(directory(), f"{ADAPTER_NAME}/services", (SSO,), AT, "CHG-1",
                                     file_evidence({**ORIGINAL, "services/api.url": "https://api.example.test\n"})))
    assert given(imported, {"services/sso.url": URL + "/\n"}) == (
        f"{ADAPTER_NAME}/services: services/sso.url: changed since it was imported",
        f"{ADAPTER_NAME}/services: services/api.url: imported but not given")


def test_the_cli_reads_sources_given_and_saved_by_collect_without_its_manifest(tmp_path):
    from opsdir.cli import onboard_sources
    (tmp_path / "given" / "services").mkdir(parents=True)
    (tmp_path / "given" / "services" / "sso.url").write_text(URL + "\n")
    kept = tmp_path / "saved" / "fake-cloud" / "services" / "services"
    kept.mkdir(parents=True)
    (kept / "api.url").write_text("https://api.example.test\n")
    (kept.parent / "MANIFEST.txt").write_text("abc services/api.url <- fake-cli get\n")
    assert onboard_sources([f"fake-cloud/services={tmp_path / 'given'}"], tmp_path / "saved") == (
        ("fake-cloud/services", ORIGINAL),
        ("fake-cloud/services", {"services/api.url": "https://api.example.test\n"}))
    with pytest.raises(SystemExit, match="ADAPTER"):
        onboard_sources(["fake-cloud/services"])
    with pytest.raises(SystemExit, match="give the original exports"):
        onboard_sources([])


def test_the_cli_text_names_the_status_each_export_and_the_failing_differences():
    from opsdir.cli import onboard_text
    v = verify(directory(), ((f"{ADAPTER_NAME}/services", ORIGINAL),),
               (_adapter(lambda m: "https://elsewhere.example.test"),), AT)
    text = onboard_text(v, diffs=True)
    assert text.startswith("onboarding verification: FAIL (loss 1)\n")
    assert f"loss  {ADAPTER_NAME}/services  {SSO}  ciamBaseUrl  {URL}  https://elsewhere.example.test  {URL}" in text
    assert "+https://elsewhere.example.test" in text and "--diff shows them" not in text


def test_files_laid_out_differently_say_the_same():
    assert same_content('{"a": 1,\n "b": [2]}', '{\n  "b": [2],\n  "a": 1\n}\n')
    assert same_content("x  y\n", "x y")
    assert not same_content('{"a": 1}', '{"a": 2}') and not same_content("x", "y")
