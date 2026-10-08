"""PingFederate collector: the bulk export from the collection source's admin node (GET with X-XSRF-Header, Basic
credentials from the reference the record names, the CA it names as trust anchor); a source whose credential isn't
bound stops the collection with the reason; the collected export reads as a bulk export."""
import json

from opsdir.connectors.collecting import collect
from opsdir.core.contract import Request
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.collect import COLLECTORS, bulk_steps, source_problems
from opsdir_adapter_pingfederate.importer import read_export
from network_fixtures import ALPHA, entry, model

SOURCE = dict(ciamBindingRole="collect-pf", ciamImporter="pingfederate/bulk",
              ciamSourceRef="https://pf-admin.example.test:9999", ciamCredentialRole="pf-reader",
              ciamLoginName="opsdir-reader", ciamCaRole="pf-ca")
BOUND = (entry(ALPHA, "pf-reader", "ciamSecretRef", ciamBindingRole="pf-reader", ciamRefUri="fake://kv/pf-reader"),
         entry(ALPHA, "pf-ca", "ciamSecretRef", ciamBindingRole="pf-ca", ciamRefUri="fake://kv/pf-ca"))


def _alpha(*bindings):
    _, alpha, _ = model(alpha=bindings)
    return alpha


def test_the_bulk_export_from_the_admin_node_with_the_recorded_credential():
    assert [c.importer for c in ADAPTER.collectors] == ["bulk"]
    m = _alpha(entry(ALPHA, "pf-admin", "ciamCollectionSource", **SOURCE), *BOUND)
    ((path, call),) = bulk_steps(m.d, m, {}, {})
    assert path == "bulk-export-pf-admin.json"
    assert call == Request("https://pf-admin.example.test:9999/pf-admin-api/v1/bulk/export",
                           (("X-XSRF-Header", "PingFederate"),), ("basic", "fake://kv/pf-reader", "opsdir-reader"),
                           "fake://kv/pf-ca")
    export = json.dumps({"metadata": {"pfVersion": "12.1.0"}, "operations": []})
    c = collect("pingfederate/bulk", COLLECTORS[0], m.d, m, lambda r: (export, None))
    assert c.problems == () and c.files == {"bulk-export-pf-admin.json": export}
    read_export(c.files, m.d, ())                                     # reads as a bulk export


def test_an_unbound_credential_stops_it_with_the_reason():
    m = _alpha(entry(ALPHA, "pf-admin", "ciamCollectionSource", **SOURCE))
    assert bulk_steps(m.d, m, {}, {}) == ()
    assert source_problems(m.d, m, {}) == (
        "collection source `pf-admin`: role `pf-reader` (its credential) isn't bound in alpha/prod",
        "collection source `pf-admin`: role `pf-ca` (its trust anchor) isn't bound in alpha/prod")
    c = collect("pingfederate/bulk", COLLECTORS[0], m.d, m, lambda r: ("", None))
    assert c.files is None and len(c.problems) == 2
