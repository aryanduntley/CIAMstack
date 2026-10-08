"""PingIDM collector: the configuration listing, then each object saved where the project keeps it (a factory
instance after a dash) without the API's _id, read with the credential in X-OpenIDM-* headers; the collected project
reads as the project directory."""
import json

from opsdir.connectors.collecting import collect
from opsdir_adapter_pingidm.adapter import ADAPTER
from opsdir_adapter_pingidm.collect import COLLECTORS, LISTING, conf_path, config_steps, without_id
from opsdir_adapter_pingidm.project import read_project
from network_fixtures import ALPHA, entry, model

SOURCE = dict(ciamBindingRole="collect-idm", ciamImporter="pingidm/project", ciamSourceRef="https://idm.example.test",
              ciamCredentialRole="idm-reader", ciamLoginName="opsdir-reader")
LISTED = {"_id": "", "configurations": [{"_id": "managed", "pid": "managed", "factoryPid": None},
                                         {"_id": "provisioner.openicf/ldap", "pid": "provisioner.openicf.1a2b",
                                          "factoryPid": "provisioner.openicf"}]}
OBJECTS = {"/openidm/config/managed": {"_id": "managed", "objects": [{"name": "user"}]},
           "/openidm/config/provisioner.openicf/ldap": {"_id": "provisioner.openicf/ldap", "configurationProperties": {
               "host": "ldap.example.test", "credentials": {"$crypto": {"type": "x-simple-encryption"}}}}}


def _alpha():
    _, alpha, _ = model(alpha=(entry(ALPHA, "idm", "ciamCollectionSource", **SOURCE),
                               entry(ALPHA, "idm-reader", "ciamSecretRef", ciamBindingRole="idm-reader",
                                     ciamRefUri="fake://kv/idm-reader")))
    return alpha


def _run(request):
    path = request.url.split("idm.example.test", 1)[1]
    return json.dumps(LISTED if path == "/openidm/config" else OBJECTS[path]), None


def test_the_listing_then_each_object_where_the_project_keeps_it():
    assert [c.importer for c in ADAPTER.collectors] == ["project"]
    m = _alpha()
    ((path, listing),) = config_steps(m.d, m, {}, {})
    assert path == LISTING and listing.url == "https://idm.example.test/openidm/config"
    assert listing.credential == ("headers", "fake://kv/idm-reader", "opsdir-reader",
                                  ("X-OpenIDM-Username", "X-OpenIDM-Password"))
    assert ("Accept-API-Version", "resource=1.0") in listing.headers
    c = collect("pingidm/project", COLLECTORS[0], m.d, m, _run)
    assert c.problems == () and set(c.files) == {"conf/managed.json", "conf/provisioner.openicf-ldap.json"}
    assert json.loads(c.files["conf/managed.json"]) == {"objects": [{"name": "user"}]}       # no _id
    read_project(c.files, m.d, ())                                  # reads as the project directory
    assert conf_path("schedule/reconcile-hr") == "conf/schedule-reconcile-hr.json"
    assert without_id("not json") == "not json"
