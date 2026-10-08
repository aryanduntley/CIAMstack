"""Google Cloud collectors: the identity check (the project the cloud records, an account signed in); the
cli-inventory calls for the project and its Shared VPC host, in rounds (asset inventory and listings, then backend
health, record sets, firewall policies, tag bindings, roles, providers, deny and org policies), exactly the
operations pinned below and never `gcloud asset export` or a secret's value; what may carry secret material trimmed
in memory (startup scripts, scheduler bodies, channel labels); the collected outputs read as the importer reads them;
Terraform state from the collection source's object or with terraform state pull."""
import importlib.util
import json
import pathlib
import shlex

from opsdir.connectors.collecting import collect, provenance
from opsdir.core.directory import make_entry
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.collect import (COLLECTORS, channel_labels, host_project, identity_check, inventory_steps,
                                        scheduler_targets, state_steps)
from support import REGISTRY, build_directory

_SPEC = importlib.util.spec_from_file_location("gcp_cli_fixtures", pathlib.Path(__file__).with_name("test_gcp_cli.py"))
_CLI = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CLI)
OPERATIONS = {
    "asset list", "asset search-all-iam-policies", "projects describe", "compute instances list",
    "compute backend-services list", "compute backend-services get-health", "dns managed-zones list",
    "dns record-sets list", "scheduler jobs list", "beta monitoring channels list", "sql instances list",
    "compute disks list", "compute resource-policies list", "backup-dr backup-vaults list",
    "backup-dr backup-plans list", "backup-dr backup-plan-associations list", "compute url-maps list",
    "compute target-https-proxies list", "compute ssl-policies list", "compute health-checks list",
    "compute security-policies list", "compute network-firewall-policies list",
    "compute network-firewall-policies describe", "compute routes list", "compute service-attachments list",
    "compute vpn-tunnels list", "resource-manager tags bindings list", "resource-manager tags values list",
    "resource-manager tags keys list", "iam service-accounts list", "iam roles list",
    "iam roles describe", "iam workload-identity-pools list", "iam workload-identity-pools providers list",
    "iam policies list", "iam policies get", "org-policies list", "org-policies describe"}
NEVER = ("asset export", "secrets versions access", "--debug", "--log-http", "keys create")


def _model(**cloud):
    d = build_directory(REGISTRY, tuple(parse(_CLI.RECORDS)))
    dn = "cloud=gcp,ou=environments,dc=ciam-ops"
    d = d._replace(entries={**d.entries, dn: make_entry(dn, (*d.entries[dn].classes, "ciamCloudAccount"),
                                                        {**d.entries[dn].attrs, "ciamAccountRef": ("ciam-prod",),
                                                         **{k: (v,) for k, v in cloud.items()}})})
    return env_model(d, "gcp/prod")


def _words(argv):
    words = []
    for a in argv[1:]:
        if a.startswith("-"):
            break
        words.append(a)
    return " ".join(w for w in words if not w.startswith(("ciam-", "projects/", "roles/", "constraints/")))


def _answer(argv):
    f, cmd = _CLI.FILES, _words(argv)
    assets = [json.loads(line) for line in _CLI.EXPORT.splitlines()]
    answers = {"compute instances list": f["instances.json"], "projects describe": f["project.json"],
               "compute backend-services list": f["backend-services.json"],
               "compute backend-services get-health": f["health/ldaps.json"],
               "dns managed-zones list": json.dumps([{"name": "ciam-private"}]),
               "dns record-sets list": f["dns/ciam-private.json"],
               "scheduler jobs list": json.dumps([{"name": "projects/ciam-prod/locations/us-central1/jobs/nightly",
                                                   "schedule": "0 2 * * *", "httpTarget": {
                                                       "uri": "https://jobs.example.test/run", "body": "c2VjcmV0",
                                                       "headers": {"Authorization": "Bearer abc"}}}]),
               "beta monitoring channels list": json.dumps([{"name": "projects/ciam-prod/notificationChannels/1",
                                                             "type": "email", "labels": {"email_address": "a@b"},
                                                             "displayName": "ops"}])}
    if cmd == "asset list":
        host = "--project=host-net" in argv
        return json.dumps([a for a in assets if not host or a.get("assetType", "").endswith(("Network",
                                                                                              "Subnetwork"))]), None
    if cmd == "config list":
        return json.dumps({"core": {"account": "op@example.test", "project": "ciam-prod"}}), None
    return answers.get(cmd, "[]"), None


def _run(call):
    return _answer(call.argv)


def test_the_collectors_are_declared_on_the_adapter():
    assert [(c.importer, c.scope) for c in ADAPTER.collectors] == [("cli-inventory", "environment"),
                                                                    ("terraform-state", "environment")]


def test_the_login_must_be_the_project_the_cloud_records():
    call, check = identity_check(None, _model())
    assert call.argv == ("gcloud", "config", "list", "--format=json")
    assert check(json.dumps({"core": {"account": "op@example.test", "project": "ciam-prod"}})) is None
    assert check(json.dumps({"core": {"account": "op@example.test", "project": "other"}})) == \
        "gcloud's project is other, the record names ciam-prod (gcloud config set project)"
    assert check(json.dumps({"core": {"project": "ciam-prod"}})) == "no account is signed in (gcloud auth login)"


def test_secret_material_is_trimmed_before_anything_sees_it():
    m = _model()
    c = collect("gcp/cli-inventory", COLLECTORS[0], m.d, m, _run)
    assert c.problems == ()
    instances = c.files["gcp/prod/instances.json"]
    assert "startup-script" not in instances and "hunter2" not in instances and "ciam-role" in instances
    jobs = json.loads(c.files["gcp/prod/scheduler.json"])
    assert jobs[0]["httpTarget"] == {"uri": "https://jobs.example.test/run"}
    assert "labels" not in json.loads(c.files["gcp/prod/channels.json"])[0]
    assert scheduler_targets(json.dumps([{"pubsubTarget": {"topicName": "t", "data": "x"}}])) == \
        json.dumps([{"pubsubTarget": {"topicName": "t"}}])
    assert channel_labels("not json") == "[]"


def test_exactly_the_reviewed_operations_and_the_collected_outputs_read():
    m = _model()
    c = collect("gcp/cli-inventory", COLLECTORS[0], m.d, m, _run)
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {_words(a) for a in ran} <= OPERATIONS
    assert not [a for a in ran for word in NEVER if word in " ".join(a)]
    assert all(a[0] == "gcloud" and a[-1] == "--format=json" for a in ran)
    assert ["gcloud", "asset", "list", "--project=ciam-prod"] == ran[0][:4]
    assert host_project(m) == "host-net" and "--project=host-net" in ran[1]
    assert ["gcloud", "compute", "backend-services", "get-health", "ciam-prod-svc-ldaps", "--region",
            "us-central1"] == next(a for a in ran if a[3:4] == ["get-health"])[:7]
    assert "--scope=projects/ciam-prod" in next(a for a in ran if a[2] == "search-all-iam-policies")
    resources, _ = cli_resources({p.split("/", 2)[2]: t for p, t in c.files.items()})
    servers = {r.ref: r for r in resources if r.kind == "server"}
    assert servers[f"{_CLI.P}/zones/us-central1-b/instances/ds-2"].attrs["ciamProductVersion"] == ("PingDS 8.0.1",)
    policy = make_entry("cn=fwp,ou=bindings,env=prod,cloud=gcp,ou=environments,dc=ciam-ops",
                        ("top", "ciamFirewallPolicy"), {"cn": ("fwp",), "ciamBindingRole": ("firewall-policy",),
                                                        "ciamTagKeyRef": ("tagKeys/281479",)})
    tagged = m._replace(bindings=(*m.bindings, policy))
    assert ("gcp/prod/tag-values-281479.json", ("gcloud", "resource-manager", "tags", "values", "list",
                                                "--parent=tagKeys/281479", "--format=json")) in \
        {(p, c.argv) for p, c in inventory_steps(tagged.d, tagged, {}, {})}
    org = _model(ciamOrganizationRef="organizations/4321")
    keys = json.dumps([{"name": "tagKeys/77", "purpose": "GCE_FIREWALL"}, {"name": "tagKeys/88"}])
    found = {p: c.argv for p, c in inventory_steps(org.d, org, {"gcp/prod/tag-keys.json": keys}, {})}
    assert found["gcp/prod/tag-keys.json"][:6] == ("gcloud", "resource-manager", "tags", "keys", "list",
                                                   "--parent=organizations/4321")
    assert "gcp/prod/tag-values-77.json" in found and "gcp/prod/tag-values-88.json" not in found
    assert "--scope=organizations/4321" in next(c.argv for _, c in inventory_steps(org.d, org, {}, {})
                                                if c.argv[2] == "search-all-iam-policies")


def test_terraform_state_from_the_source_object_or_terraform_state_pull():
    m = _model()
    assert state_steps(m.d, m, {}, {}) == ()
    source = make_entry("cn=tf-state,ou=bindings,env=prod,cloud=gcp,ou=environments,dc=ciam-ops",
                        ("top", "ciamCollectionSource"),
                        {"cn": ("tf-state",), "ciamBindingRole": ("collect-state",),
                         "ciamImporter": ("gcp/terraform-state",),
                         "ciamSourceRef": ("gs://ciam-tf-state/ciam/prod.tfstate",)})
    with_source = m._replace(bindings=(*m.bindings, source))
    ((path, call),) = state_steps(m.d, with_source, {}, {})
    assert (path, provenance(call)) == ("gcp/prod/prod.tfstate", "gcloud storage cat gs://ciam-tf-state/ciam/prod.tfstate")
    ((_, pull),) = state_steps(m.d, with_source, {}, {"terraform_dir": "/work/ciam"})
    assert pull.argv == ("terraform", "-chdir=/work/ciam", "state", "pull")
