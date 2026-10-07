"""An environment's guardrails as Google Cloud organization policies on its project: each neutral denial (ciamDenies)
as the constraints that prevent it, each constraint once. Pure.

Constraints from the organization policy constraints page (checked 2026-10-02, note 457). audit-log-disable: Admin
Activity audit logs can't be disabled at all; the constraint rendered stops new audit-logging exemptions (said in a
comment). Not applicable on Google Cloud, and NOTEs: metadata-v1 (the metadata server requires its Metadata-Flavor
header), root-use. region-escape allows the regions the environment may hold resources in
(estate.residency.permitted_regions: its cloud's region and those its residency allows), each as its value group.
"""
from opsdir.core.directory import rdn_value, values
from opsdir.core.environment import of_class
from opsdir.domains.access.naming import DENIALS
from opsdir.domains.estate.residency import permitted_regions
from opsdir_format_terraform.hcl import Block, block, tf_name

PROJECT = "projects/${var.project_id}"
NOT_APPLICABLE = {"metadata-v1": "the metadata server already requires its Metadata-Flavor header",
                  "root-use": "Google Cloud has no root user"}
COMMENTS = {"iam.disableAuditLoggingExemption": "Admin Activity audit logs can't be disabled; this stops new "
                                                "audit-logging exemptions"}


def _constraints(denial, regions):
    """((constraint, True for an enforced boolean, else allowed values), ...) preventing a neutral denial (regions:
    those region-escape allows)."""
    return {"region-escape": (("gcp.resourceLocations", tuple(f"in:{r}-locations" for r in regions)),),
            "public-storage": (("storage.publicAccessPrevention", True),),
            "audit-log-disable": (("iam.disableAuditLoggingExemption", True),),
            "service-account-keys": (("iam.disableServiceAccountKeyCreation", True),
                                     ("iam.disableServiceAccountKeyUpload", True)),
            "key-deletion": (("cloudkms.disableBeforeDestroy", True),)}.get(denial, ())


def denial_of(constraint):
    """What an organization policy constraint prevents (read back on import), or None."""
    name = (constraint or "").removeprefix("constraints/")
    return next((d for d in DENIALS for c, _ in _constraints(d, ()) if c == name), None)


def _policy(constraint, rule):
    spec = (("enforce", "TRUE"),) if rule is True else (("values", Block((("allowed_values", list(rule)),))),)
    return block("resource", ["google_org_policy_policy", tf_name(constraint)], [
        *((("#", COMMENTS[constraint]),) if constraint in COMMENTS else ()),
        ("name", f"{PROJECT}/policies/{constraint}"), ("parent", PROJECT),
        ("spec", Block((("rules", Block(spec)),)))])


def render_guardrails(m):
    """HCL for environment m's guardrails: an organization policy per constraint; a NOTE for what doesn't apply."""
    regions = permitted_regions(m)
    denials = [(g, d) for g in of_class(m, "ciamGuardrail") for d in values(g, "ciamDenies")]
    policies = dict.fromkeys(c for _, d in denials for c in _constraints(d, regions))
    return (*(f"# NOTE: guardrail {rdn_value(g)}: {d}: {NOT_APPLICABLE.get(d, 'Google Cloud has no constraint for it')}"
              for g, d in denials if not _constraints(d, regions)),
            *(_policy(c, rule) for c, rule in policies))
