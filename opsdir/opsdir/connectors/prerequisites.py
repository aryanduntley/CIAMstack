"""Provider prerequisites: data the installed adapters need fetched from their providers before the record is complete
(a provider's region catalog). Each is needed once its adapter applies to some environment, met when the record holds
it, and fetched with one of the adapter's importers: `opsdir import <adapter>/<importer> --run` runs the provider's own
command under the operator's login to the provider, or the operator runs the command and gives its output as the
export. Pure."""
import shlex

from ..core.environment import env_model
from .importing import import_commands
from .registry import ADAPTERS, environment_specs
from .stack import declared_adapters

HEADERS = ("prerequisite", "adapter", "status", "fetch", "provider command")
PENDING = "pending"


def command_line(path, argv):
    """A provider command as a shell line writing its output where the importer reads it."""
    return f"{shlex.join(argv)} > {shlex.quote(path)}"


def _needed(d, installed):
    return {a.name for spec in environment_specs(d) for a in declared_adapters(env_model(d, spec), installed)}


def _importer(adapter, prerequisite):
    return next((i for i in adapter.importers if i.name == prerequisite.importer), None)


def prerequisite_rows(d, installed=ADAPTERS):
    """One row per prerequisite an installed adapter declares: its name, adapter, status (met, pending: its adapter
    applies to an environment and the record lacks it, not needed yet), the opsdir command fetching it and the provider
    command(s) it runs."""
    needed = _needed(d, installed)
    return tuple((p.name, a.name, "met" if p.met(d) else PENDING if a.name in needed else "not needed yet",
                  f"opsdir import {a.name}/{p.importer} --run",
                  "; ".join(command_line(path, argv) for path, argv in (import_commands(i, d) if i else ())))
                 for a in installed for p in a.prerequisites for i in (_importer(a, p),))


def pending_prerequisites(d, installed=ADAPTERS):
    """The rows of prerequisites still pending (prerequisite_rows)."""
    return tuple(r for r in prerequisite_rows(d, installed) if r[2] == PENDING)
