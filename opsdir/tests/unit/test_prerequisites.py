"""Provider prerequisites: data an adapter needs fetched from its provider (with the fake adapter, whose environments
both declare it): pending once the adapter applies to an environment and the record lacks it, met once it holds it, not
needed yet for an adapter no environment uses; and `opsdir import --run`, which runs the importer's provider commands
under the operator's own login (here a stand-in for the provider's tool) and imports their output."""
import argparse
import subprocess

import pytest

from opsdir import cli
from opsdir.connectors.prerequisites import command_line, pending_prerequisites, prerequisite_rows
from opsdir.connectors.registry import ordered_adapters
from opsdir.core.contract import Prerequisite
import mini_estate
from mini_estate import FAKE, FAKE_IMPORTER

LISTED = FAKE_IMPORTER._replace(name="regions", commands=(("regions.json", ("fakecli", "regions", "list")),))
NEEDED = FAKE._replace(importers=(FAKE_IMPORTER, LISTED),
                       prerequisites=(Prerequisite("fake-regions", "the provider's regions", "regions",
                                                   lambda d: False),))
UNUSED = FAKE._replace(name="other-cloud", importers=(LISTED,),
                       prerequisites=(Prerequisite("other-regions", "another provider's regions", "regions",
                                                   lambda d: False),))


def test_a_prerequisite_is_pending_while_its_adapter_applies_and_the_record_lacks_it():
    d = mini_estate.directory()
    rows = prerequisite_rows(d, (NEEDED, UNUSED))
    assert rows == (("fake-regions", "fake-cloud", "pending", "opsdir import fake-cloud/regions --run",
                     "fakecli regions list > regions.json"),
                    ("other-regions", "other-cloud", "not needed yet", "opsdir import other-cloud/regions --run",
                     "fakecli regions list > regions.json"))
    assert pending_prerequisites(d, (NEEDED, UNUSED)) == rows[:1]
    met = NEEDED._replace(prerequisites=(NEEDED.prerequisites[0]._replace(met=lambda d: True),))
    assert prerequisite_rows(d, (met,))[0][2] == "met" and pending_prerequisites(d, (met,)) == ()
    assert prerequisite_rows(d, (FAKE,)) == ()                                  # an adapter declaring none


def test_a_provider_command_is_shown_as_a_shell_line():
    assert command_line("out file.json", ("az", "account", "list-locations", "-o", "json")) == \
        "az account list-locations -o json > 'out file.json'"


def _ran(monkeypatch, result):
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if isinstance(result, Exception):
            raise result
        return subprocess.CompletedProcess(argv, *result)
    monkeypatch.setattr(cli, "ADAPTERS", (NEEDED,))
    monkeypatch.setattr(cli.subprocess, "run", run)
    return calls


def test_run_produces_the_export_with_the_providers_own_tool(monkeypatch):
    calls = _ran(monkeypatch, (0, '{"regions": []}', ""))
    assert cli.run_export("fake-cloud/regions") == {"regions.json": '{"regions": []}'}
    assert calls == [("fakecli", "regions", "list")]


def test_run_refuses_a_missing_tool_a_failing_command_and_an_importer_without_one(monkeypatch):
    _ran(monkeypatch, FileNotFoundError())
    with pytest.raises(SystemExit, match=r"fakecli is not installed here: install it and sign in to the provider, or "
                                         r"run `fakecli regions list > regions.json` where you can"):
        cli.run_export("fake-cloud/regions")
    _ran(monkeypatch, (255, "", "not signed in\n"))
    with pytest.raises(SystemExit, match=r"`fakecli regions list > regions.json` failed \(exit 255\): not signed in"):
        cli.run_export("fake-cloud/regions")
    with pytest.raises(SystemExit, match="fake-cloud/services has no provider command: give the export's path"):
        cli.run_export("fake-cloud/services")


@pytest.mark.parametrize("run, path", [(True, "export.json"), (False, None)])
def test_import_takes_a_path_or_run_not_both(run, path):
    with pytest.raises(SystemExit, match=r"give the export's PATH or --run \(not both\)"):
        cli._cmd_import(None, argparse.Namespace(importer="fake-cloud/regions", run=run, path=path), None)


def test_an_adapter_whose_prerequisite_names_no_importer_of_its_own_is_refused():
    assert ordered_adapters((NEEDED,)) == (NEEDED,)
    wrong = NEEDED._replace(importers=(FAKE_IMPORTER,))
    with pytest.raises(SystemExit, match=r"prerequisites naming an importer their adapter doesn't have: fake-cloud "
                                         r"\(fake-regions: regions\)"):
        ordered_adapters((wrong,))
