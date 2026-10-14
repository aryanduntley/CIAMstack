"""Google Cloud's compliance frameworks as rendered (Security Command Center's Compliance Manager): which Google
framework answers a neutral framework id, and the framework deployment a posture service's framework renders as. The
catalog it reads is fetched by frameworks.py.

Google publishes no table of its built-in framework ids, so a framework answers a neutral framework id when its name
as shown is one NAMES gives for it (Google's pages name some two ways); the gcp-default baseline is the Security
Essentials framework (builtin-security-essentials, offered in every tier).

A posture service's framework (and gcp-default) renders as a google_cloud_security_compliance_framework_deployment of
the catalog's framework at its revision, in the organization (location global), on the project or, organization-wide,
on the organization (kept with the landing zone, decision 2777). It lists every control of the framework (Google
documents no subset) at the revision the framework holds, DETECTIVE where the control can be, else AUDIT (posture
assesses, it never blocks: decision 2801), with the parameter values the framework sets, else the defaults of those the
control requires. It stays a request, naming why, when a control can only be PREVENTIVE or requires a parameter with no
value, when the catalog doesn't hold the framework or its controls (fetch them), and when the cloud names no
organization. A framework Google doesn't offer (FedRAMP Moderate and High, NIST SP 800-171, CMMC, the DoD impact levels,
ITAR, CJIS, HIPAA) is named in a comment: FedRAMP and impact levels are held by an Assured Workloads folder (from the
cloud authorization's level). Google's pages say both that one and that several frameworks may be deployed on one
resource: one deployment per framework is rendered, and its comment says so. Frameworks other than Security Essentials
need Security Command Center Premium (the tier's request names it).

Read back (security.security_resources): a deployment's description carries the neutral id it was rendered for
(ciam:<id>); one without it answers by its framework's id (Security Essentials: gcp-default). Pure."""
import re

from opsdir.core.directory import one, rdn_value, values
from opsdir.core.inventory import of_types
from opsdir.core.notes import note, note_comment
from opsdir.domains.estate.frameworks import control_parameters, framework_controls, provider_framework
from opsdir.domains.estate.naming import ENFORCEMENT_MODES
from opsdir.domains.governance.keepers import organization_origin, organization_wide
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import ORGANIZATION, organization_id

DEPLOYMENT = "google_cloud_security_compliance_framework_deployment"
LOCATION = "global"
# neutral framework id -> the names Google shows its framework under (its overview and framework pages differ)
NAMES = {"nist-800-53-r5": ("NIST SP 800-53 R5", "NIST 800-53 Revision 5"),
         "cis": ("CIS Google Cloud Computing Platform Benchmark v3.0", "CIS GCP Foundations Benchmark v3.0"),
         "pci-dss": ("PCI DSS 4.0",), "iso-27001": ("ISO 27001, 2022",), "soc2": ("SOC 2",),
         "fedramp-low": ("FedRAMP Low", "FedRAMP Low 20x")}
BASELINE = "gcp-default"
ESSENTIALS = "builtin-security-essentials"
ESSENTIALS_NAMES = ("Security Essentials", "Google Cloud Security Essentials")
ASSURED = ("fedramp-", "dod-il")          # regimes an Assured Workloads folder holds
_KEY = re.compile(r"\(ciam:([a-z0-9-]+)\)")


def _norm(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


def short_id(name):
    """The last segment of a Google resource name (a framework's or control's id)."""
    return (name or "").rstrip("/").rsplit("/", 1)[-1]


def enforcement_modes(x):
    """The enforcement modes (naming.ENFORCEMENT_MODES) an API framework or control item supports."""
    return tuple(m.lower() for m in x.get("supportedEnforcementModes") or () if m.lower() in ENFORCEMENT_MODES)


def answers(framework_id, title):
    """(neutral framework ids, baselines) a Google framework answers, by its id and name as shown."""
    shown = _norm(title)
    return (tuple(k for k, names in NAMES.items() if shown in {_norm(n) for n in names}),
            (BASELINE,) if framework_id == ESSENTIALS or shown in {_norm(n) for n in ESSENTIALS_NAMES} else ())


def _snake(key):
    return re.sub(r"([A-Z])", r"_\1", key).lower()


def _value(v):
    """A parameter value (the API's ParameterValue: stringValue, stringListValue{values}, ...) as its block."""
    return Block(tuple((_snake(k), _value(x) if isinstance(x, dict) else x) for k, x in v.items()))


def _mode(c):
    modes = values(c, "ciamEnforcementMode")
    return "DETECTIVE" if "detective" in modes or not modes else "AUDIT"


def _metadata(c):
    return ("cloud_control_metadata", Block((
        ("enforcement_mode", _mode(c)),
        ("cloud_control_details", Block((
            ("name", one(c, "ciamProviderRef")), ("major_revision_id", one(c, "ciamRevision")),
            *(("parameters", Block((("name", n), ("parameter_value", _value(v))))) for n, v in control_parameters(c)
              if isinstance(v, dict))))))))


def _block(m, s, key, fw, controls):
    cn = rdn_value(s)
    target = f"organizations/{ref('var.' + ORGANIZATION)}" if organization_wide(s) else "projects/${var.project_id}"
    return tf_block("resource", [DEPLOYMENT, tf_name(f"{cn}_{key}")], [
        ("#", f"{key}: Compliance Manager's {one(fw, 'ciamFrameworkName') or rdn_value(fw)}, every control (DETECTIVE "
              "where it can be, else AUDIT); one deployment per framework (Google's pages say both one and several "
              "may be deployed on one resource)"),
        ("organization", ref(f"var.{ORGANIZATION}")), ("location", LOCATION),
        ("framework_deployment_id", f"{cn}-{key}"), ("description", f"{cn}'s {key} assessment (ciam:{key})"),
        ("framework", Block((("framework", one(fw, "ciamProviderRef")),
                             ("major_revision_id", one(fw, "ciamRevision"))))),
        ("target_resource_config", Block((("existing_target_resource", target),))),
        *(_metadata(c) for c in controls)])


def _why_not(m, key, fw, controls):
    """Why a framework's deployment isn't rendered (the request's reason), or None."""
    if organization_id(m) is None:
        return "the cloud names no organization (ciamOrganizationRef)"
    if fw is None or not controls:
        return ("the framework catalog holds no framework for it, or not its controls (opsdir import gcp/frameworks "
                "--run)")
    preventive = [rdn_value(c) for c in controls if values(c, "ciamEnforcementMode")
                  and not {"detective", "audit"} & set(values(c, "ciamEnforcementMode"))]
    if preventive:
        return (f"its controls {', '.join(preventive)} can only be PREVENTIVE (they would block changes; posture "
                "assesses)")
    unset = [f"{rdn_value(c)} {n}" for c in controls for n, v in control_parameters(c) if not isinstance(v, dict)]
    return f"its controls require values with no default: {', '.join(unset)}" if unset else None


def request_note(m, s, what):
    """The render note of something only the organization's administrators can turn on for service s (no Terraform
    resource, or one the build doesn't use): an action, a request to them."""
    return note("Security", "action", rdn_value(s), f"{what}: a request to the organization's administrators (not "
                "rendered)", (f"Ask the organization's administrators for it: {what}",), s.dn, "the organization")


def _framework(m, key):
    org = organization_id(m)
    fw = provider_framework(m.d, m.provider, org, key) if org else None
    return fw, framework_controls(m.d, fw) if fw is not None else []


def deployment_note(m, s, key):
    """The render note of posture service s's framework (or baseline) key when no framework deployment is rendered,
    or None: Google offers no framework for it (a plain note when an Assured Workloads folder holds it, else an
    action: assess it another way), or the deployment can't be rendered (request_note, its reason)."""
    cn = rdn_value(s)
    if key not in NAMES and key != BASELINE:
        if key.startswith(ASSURED):
            return note("Security", "note", cn, f"{key}: Compliance Manager offers no framework for it (held by an "
                        "Assured Workloads folder, from the cloud authorization's level)", (), s.dn, m.label)
        return note("Security", "action", cn, f"{key}: Compliance Manager offers no framework for it (not rendered)",
                    (f"Assess {key} another way (a custom Compliance Manager framework, or the organization's own "
                     "controls), by hand",), s.dn, m.label)
    why = _why_not(m, key, *_framework(m, key))
    return request_note(m, s, f"{key} assessed by a Compliance Manager framework deployment: {why}") if why else None


def deployment(m, s, key):
    """Items for posture service s's framework (or baseline) key: its framework deployment (organization-wide: stamped
    with s's organization origin), else its note's comment (deployment_note)."""
    found = deployment_note(m, s, key)
    if found is not None:
        return (comment(note_comment(found)),)
    fw, controls = _framework(m, key)
    block = _block(m, s, key, fw, controls)
    return from_entry(organization_origin(s.dn), (block,)) if organization_wide(s) else (block,)


def deployment_keys(pairs):
    """((key, organization-wide), ...) of the framework deployments among (google type, attributes) pairs: the neutral
    id its description carries, else gcp-default for Security Essentials, else its framework's id."""
    def key(a):
        found = _KEY.search(a.get("description") or "")
        fw = a.get("framework")
        fw = fw[0] if isinstance(fw, list) and fw else fw if isinstance(fw, dict) else {}
        return found.group(1) if found else BASELINE if short_id(fw.get("framework")) == ESSENTIALS \
            else short_id(fw.get("framework")) or None

    def wide(a):
        t = a.get("target_resource_config")
        t = t[0] if isinstance(t, list) and t else t if isinstance(t, dict) else {}
        return (t.get("existing_target_resource") or a.get("computed_target_resource") or "").startswith(
            "organizations/")
    return tuple((key(a), wide(a)) for a in of_types(pairs, DEPLOYMENT) if key(a))
