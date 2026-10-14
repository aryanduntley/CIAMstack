"""Compliance Manager on Google Cloud (5.7b g): the frameworks and cloud controls gcloud lists, fetched into the
framework catalog (a neutral id stamped on the framework Google shows under one of its names; controls kept only for
frameworks a posture service names); a posture service's frameworks and gcp-default (Security Essentials) rendered as
framework deployments listing every control (DETECTIVE, else AUDIT) or a request saying why; organization-wide ones
kept with the landing zone; read back from state and gcloud."""
import json

from opsdir.core.directory import get, values
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.estate.frameworks import catalog_dn, framework_import, frameworks_fetched
from opsdir_format_terraform.hcl import TfBlock, as_text
from opsdir_adapter_gcp.account import organization_id
from opsdir_adapter_gcp.cli import cli_resources
from opsdir_adapter_gcp.frameworks import PREREQUISITE, framework_commands, framework_rows, read_frameworks
from opsdir_adapter_gcp.security import render_security, security_resources
from network_fixtures import ALPHA, entry, model

CLOUD = ALPHA.split(",", 1)[1]
PARTY = "cn=landing-zone,ou=owners,dc=ciam-ops"
OWNERS = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
          f"dn: {PARTY}\nobjectClass: top\nobjectClass: ciamParty\ncn: landing-zone\nciamOwnerKind: team\n")
ORG = "123"
BASE = f"organizations/{ORG}/locations/global"


def _catalog(provider="fakecloud", controls=None):
    cat = catalog_dn(provider, ORG)
    nist, sec = f"cn=builtin-nist-800-53-r5,{cat}", f"cn=builtin-security-essentials,{cat}"
    kept = controls if controls is not None else (
        ("restrict-bucket-region", ("detective", "preventive"), ('locations={"stringListValue": {"values": ["us"]}}',)),
        ("evidence-iam", ("audit",), ()))
    return ("dn: ou=frameworks,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: frameworks\n",
            f"dn: {cat}\nobjectClass: top\nobjectClass: ciamFrameworkCatalog\ncn: {provider}:{ORG}\n"
            f"ciamCloudProvider: {provider}\nciamOrganizationRef: {ORG}\n",
            f"dn: {nist}\nobjectClass: top\nobjectClass: ciamProviderFramework\ncn: builtin-nist-800-53-r5\n"
            f"ciamProviderRef: {BASE}/frameworks/builtin-nist-800-53-r5\nciamRevision: 3\n"
            "ciamFrameworkName: NIST SP 800-53 R5\nciamComplianceStandard: nist-800-53-r5\n",
            *(f"dn: cn={c},{nist}\nobjectClass: top\nobjectClass: ciamProviderControl\ncn: {c}\n"
              f"ciamProviderRef: {BASE}/cloudControls/{c}\nciamRevision: 2\n"
              + "".join(f"ciamEnforcementMode: {x}\n" for x in modes)
              + "".join(f"ciamControlParameter: {p}\n" for p in params) for c, modes, params in kept),
            f"dn: {sec}\nobjectClass: top\nobjectClass: ciamProviderFramework\ncn: builtin-security-essentials\n"
            f"ciamProviderRef: {BASE}/frameworks/builtin-security-essentials\nciamRevision: 1\n"
            "ciamSecurityBaseline: gcp-default\n",
            f"dn: cn=sha-enabled,{sec}\nobjectClass: top\nobjectClass: ciamProviderControl\ncn: sha-enabled\n"
            f"ciamProviderRef: {BASE}/cloudControls/sha-enabled\nciamRevision: 1\nciamEnforcementMode: detective\n")


def _org(ref=f"organizations/{ORG}"):
    return LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                            ("replace", "ciamOrganizationRef", (ref,))))


def svc(cn="posture", **more):
    return entry(ALPHA, cn, "ciamSecurityService", ciamBindingRole=cn, ciamSecurityKind="posture", **more)


def _model(*services, tree=None, org=True):
    return model(alpha=services, tree=(*OWNERS, *(tree if tree is not None else _catalog())),
                 changes=(_org(),) if org else ())


def _render(*services, **kw):
    _, alpha, _ = _model(*services, **kw)
    return render_security(alpha)


def _text(items):
    return "\n\n".join(as_text(items))


POSTURE = svc(ciamComplianceStandard=("nist-800-53-r5", "fedramp-high"), ciamSecurityBaseline="gcp-default")


def test_a_framework_and_the_baseline_render_as_deployments_of_every_control():
    out = _text(_render(POSTURE))
    assert 'resource "google_cloud_security_compliance_framework_deployment" "posture_nist_800_53_r5"' in out
    assert 'resource "google_cloud_security_compliance_framework_deployment" "posture_gcp_default"' in out
    assert f'framework         = "{BASE}/frameworks/builtin-nist-800-53-r5"' in out
    assert 'major_revision_id = "3"' in out
    assert 'existing_target_resource = "projects/${var.project_id}"' in out
    assert 'organization            = var.organization_id' in out and 'location                = "global"' in out
    assert 'description             = "posture\'s nist-800-53-r5 assessment (ciam:nist-800-53-r5)"' in out
    assert out.count("cloud_control_metadata {") == 3                     # nist's two controls, essentials' one
    assert 'enforcement_mode = "DETECTIVE"' in out and 'enforcement_mode = "AUDIT"' in out   # audit-only: AUDIT
    assert f'name              = "{BASE}/cloudControls/restrict-bucket-region"' in out
    assert 'values = ["us"]' in out                                       # the framework's parameter value
    assert 'variable "organization_id"' in out and 'default     = "123"' in out
    assert ("# NOTE: posture: fedramp-high: Compliance Manager offers no framework for it (held by an Assured "
            "Workloads") in out


def test_deployments_stay_a_request_naming_why():
    def why(out):
        return [line for line in _text(out).splitlines() if "nist-800-53-r5 assessed" in line]
    nist = svc(ciamComplianceStandard="nist-800-53-r5")
    assert why(_render(nist, org=False)) == [
        "# NOTE: posture: nist-800-53-r5 assessed by a Compliance Manager framework deployment: the cloud names no "
        "organization (ciamOrganizationRef): a request to the organization's administrators (not rendered)"]
    assert "the framework catalog holds no framework for it, or not its controls (opsdir import gcp/frameworks --run)" \
        in why(_render(nist, tree=()))[0]
    assert "its controls block-public can only be PREVENTIVE (they would block changes; posture assesses)" in why(
        _render(nist, tree=_catalog(controls=(("block-public", ("preventive",), ()),))))[0]
    assert "its controls require values with no default: pick-region region" in why(
        _render(nist, tree=_catalog(controls=(("pick-region", ("detective",), ("region",)),))))[0]


def test_an_organization_wide_deployment_is_kept_with_the_landing_zone():
    items = _render(svc(ciamComplianceStandard="nist-800-53-r5", ciamAuditScope="organization"))
    deployed = [x for x in items if isinstance(x, TfBlock) and x.labels[:1] ==
                ("google_cloud_security_compliance_framework_deployment",)]
    assert [x.origin for x in deployed] == [f"organization:cn=posture,ou=bindings,{ALPHA}"]
    out = _text(items)
    assert 'existing_target_resource = "organizations/${var.organization_id}"' in out
    assert "# posture: organization-wide: enabled for every account by" in out


STATE = [("google_cloud_security_compliance_framework_deployment", {
              "name": f"{BASE}/frameworkDeployments/posture-nist-800-53-r5",
              "description": "posture's nist-800-53-r5 assessment (ciam:nist-800-53-r5)",
              "framework": [{"framework": f"{BASE}/frameworks/builtin-nist-800-53-r5", "major_revision_id": "3"}],
              "target_resource_config": [{"existing_target_resource": "projects/example"}]}),
         ("google_cloud_security_compliance_framework_deployment", {
              "name": f"{BASE}/frameworkDeployments/by-hand",
              "framework": [{"framework": f"{BASE}/frameworks/builtin-security-essentials"}],
              "target_resource_config": [{"existing_target_resource": f"organizations/{ORG}"}]})]


def test_deployments_are_read_back_as_what_the_posture_service_assesses():
    (r,) = security_resources(STATE)
    assert (r.attrs["ciamSecurityKind"], r.attrs["ciamComplianceStandard"], r.attrs["ciamSecurityBaseline"],
            r.attrs["ciamAuditScope"]) == (("posture",), ("nist-800-53-r5",), ("gcp-default",), ("organization",))
    notified = ("google_scc_v2_project_notification_config", {
        "name": "projects/example/locations/global/notificationConfigs/posture-findings",
        "config_id": "posture-findings", "pubsub_topic": "projects/p/topics/t",
        "streaming_config": [{"filter": 'finding_class="MISCONFIGURATION" AND state="ACTIVE"'}]})
    (folded,) = security_resources([notified, *STATE])                  # folded into the notification's service
    assert folded.name == "posture-findings" and folded.attrs["ciamComplianceStandard"] == ("nist-800-53-r5",)


def test_gcloud_reads_the_same_deployments_as_state():
    listed = [{"name": f"{BASE}/frameworkDeployments/posture-nist-800-53-r5",
               "description": "posture's nist-800-53-r5 assessment (ciam:nist-800-53-r5)",
               "framework": {"framework": f"{BASE}/frameworks/builtin-nist-800-53-r5", "majorRevisionId": "3"},
               "targetResourceConfig": {"existingTargetResource": "projects/example"}},
              {"name": f"{BASE}/frameworkDeployments/by-hand",
               "framework": {"framework": f"{BASE}/frameworks/builtin-security-essentials"},
               "targetResourceConfig": {"existingTargetResource": f"organizations/{ORG}"}}]
    resources, _ = cli_resources({"framework-deployments.json": json.dumps(listed)})
    assert [r for r in resources if r.kind == "security"] == list(security_resources(STATE))


# ------------------------------------------------------------------ the catalog fetched
FRAMEWORKS = [
    {"name": f"{BASE}/frameworks/builtin-nist-800-53-r5", "majorRevisionId": "3", "displayName": "NIST SP 800-53 R5",
     "type": "BUILT_IN", "supportedEnforcementModes": ["DETECTIVE", "AUDIT"],
     "cloudControlDetails": [{"name": f"{BASE}/cloudControls/restrict-bucket-region", "majorRevisionId": "2",
                              "parameters": [{"name": "locations",
                                              "parameterValue": {"stringListValue": {"values": ["us"]}}}]},
                             {"name": f"{BASE}/cloudControls/evidence-iam", "majorRevisionId": "1"}]},
    {"name": f"{BASE}/frameworks/builtin-cis-gcp-v3", "majorRevisionId": "2",
     "displayName": "CIS GCP Foundations Benchmark v3.0", "type": "BUILT_IN",
     "cloudControlDetails": [{"name": f"{BASE}/cloudControls/sha-enabled", "majorRevisionId": "1"}]},
    {"name": f"{BASE}/frameworks/builtin-security-essentials", "majorRevisionId": "1",
     "displayName": "Google Cloud Security Essentials", "type": "BUILT_IN",
     "cloudControlDetails": [{"name": f"{BASE}/cloudControls/sha-enabled", "majorRevisionId": "1"}]}]
CONTROLS = [{"name": f"{BASE}/cloudControls/restrict-bucket-region", "majorRevisionId": "2",
             "supportedEnforcementModes": ["PREVENTIVE", "DETECTIVE"]},
            {"name": f"{BASE}/cloudControls/evidence-iam", "majorRevisionId": "1",
             "supportedEnforcementModes": ["AUDIT"],
             "parameterSpec": [{"name": "roles", "isRequired": True, "valueType": "STRINGLIST",
                                "defaultValue": {"stringListValue": {"values": ["roles/owner"]}}},
                               {"name": "optional", "isRequired": False}]},
            {"name": f"{BASE}/cloudControls/sha-enabled", "majorRevisionId": "1",
             "supportedEnforcementModes": ["DETECTIVE"]}]


def _by(imported):
    ((dn, entries),) = imported.groups
    return dn, {e.dn.split(",", 1)[0]: e for e in entries}


def test_the_catalog_keeps_every_framework_and_the_named_ones_controls():
    d, *_ = _model(svc(ciamComplianceStandard=("nist-800-53-r5", "soc2")), tree=())
    assert framework_commands(d) == ()                         # the test cloud isn't Google Cloud: nothing to fetch
    imported = read_frameworks({f"frameworks/{ORG}/frameworks.json": json.dumps(FRAMEWORKS),
                                f"frameworks/{ORG}/cloud-controls.json": json.dumps(CONTROLS),
                                "other.json": "{}"}, d, ())
    dn, by = _by(imported)
    assert dn == catalog_dn("gcp", ORG) and get(d, dn) is None
    assert values(by["cn=builtin-nist-800-53-r5"], "ciamComplianceStandard") == ("nist-800-53-r5",)
    assert values(by["cn=builtin-cis-gcp-v3"], "ciamComplianceStandard") == ("cis",)
    assert values(by["cn=builtin-security-essentials"], "ciamSecurityBaseline") == ("gcp-default",)
    assert "cn=evidence-iam" not in by                     # no Google Cloud posture service names a framework
    assert "other.json: not `gcloud compliance-manager` frameworks or cloud-controls list output; not read" \
        in imported.notices
    # the same lists, for the test cloud's provider: nist's controls kept (it names nist-800-53-r5), soc2 not offered
    dn, by = _by(framework_import(d, "fakecloud", framework_rows(FRAMEWORKS, CONTROLS), organization_id))
    assert values(by["cn=evidence-iam"], "ciamControlParameter") == ('roles={"stringListValue": {"values": '
                                                                     '["roles/owner"]}}',)
    assert values(by["cn=restrict-bucket-region"], "ciamEnforcementMode") == ("preventive", "detective")
    assert values(by["cn=restrict-bucket-region"], "ciamControlParameter") == (
        'locations={"stringListValue": {"values": ["us"]}}',)
    assert "cn=sha-enabled" not in by                      # no service names cis or gcp-default
    assert framework_import(d, "fakecloud", framework_rows(FRAMEWORKS, CONTROLS), organization_id).notices == (
        "fakecloud organization 123: 3 frameworks, the controls of builtin-nist-800-53-r5 kept",
        "fakecloud organization 123: no framework listed answers soc2 (not offered, or listed under another name)")


def test_the_fetch_commands_and_prerequisite_follow_the_record():
    d, *_ = _model(svc(ciamComplianceStandard="nist-800-53-r5"))
    assert PREREQUISITE.name == "gcp-frameworks" and PREREQUISITE.met(d)   # no Google Cloud environment needs it
    assert frameworks_fetched(d, "fakecloud", organization_id)
    assert not frameworks_fetched(_model(svc(ciamComplianceStandard="soc2"), tree=())[0], "fakecloud",
                                  organization_id)
