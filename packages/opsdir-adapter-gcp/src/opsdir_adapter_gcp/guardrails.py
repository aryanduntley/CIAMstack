"""An environment's guardrails as Google Cloud organization policies on its project: each neutral denial (ciamDenies)
as the constraints that prevent it, each constraint once. Pure.

Constraints from the organization policy constraints page (checked 2026-10-02, note 457). audit-log-disable: Admin
Activity audit logs can't be disabled at all; the constraint rendered stops new audit-logging exemptions (said in a
comment). Not applicable on Google Cloud, and plain notes: metadata-v1 (the metadata server requires its Metadata-Flavor
header), root-use. region-escape allows the regions the environment may hold resources in
(estate.residency.permitted_regions: its cloud's region and those its residency allows), each as its value group.
"""
from opsdir.core.directory import rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.access.naming import DENIALS
from opsdir.domains.estate.residency import permitted_regions
from opsdir_format_terraform.hcl import Block, comment, tf_block, tf_name

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
    return tf_block("resource", ["google_org_policy_policy", tf_name(constraint)], [
        *((("#", COMMENTS[constraint]),) if constraint in COMMENTS else ()),
        ("name", f"{PROJECT}/policies/{constraint}"), ("parent", PROJECT),
        ("spec", Block((("rules", Block(spec)),)))])


def guardrail_note(m, g, d):
    """The render note of guardrail g's denial d when Google Cloud has no constraint for it, or None: a plain note
    when it doesn't apply there (NOT_APPLICABLE), else an action (prevent it another way)."""
    if _constraints(d, permitted_regions(m)):
        return None
    if d in NOT_APPLICABLE:
        return note("Guardrails", "note", f"guardrail {rdn_value(g)}", f"{d}: {NOT_APPLICABLE[d]}", (), g.dn, m.label)
    return note("Guardrails", "action", f"guardrail {rdn_value(g)}", f"{d}: Google Cloud has no constraint for it",
                (f"Prevent {d} another way where the guardrail applies (a custom organization policy constraint), or "
                 f"remove it from the guardrail's ciamDenies, {RECORD}",), g.dn, m.label)


def guardrail_notes(m):
    """The render notes of environment m's guardrails (render_guardrails writes their comments)."""
    return tuple(n for g in of_class(m, "ciamGuardrail") for d in values(g, "ciamDenies")
                 for n in (guardrail_note(m, g, d),) if n is not None)


def render_guardrails(m):
    """HCL for environment m's guardrails: an organization policy per constraint; its note's comment
    (guardrail_note) for what doesn't apply."""
    regions = permitted_regions(m)
    denials = [(g, d) for g in of_class(m, "ciamGuardrail") for d in values(g, "ciamDenies")]
    policies = dict.fromkeys(c for _, d in denials for c in _constraints(d, regions))
    return (*(comment(note_comment(x)) for g, d in denials for x in (guardrail_note(m, g, d),) if x is not None),
            *(_policy(c, rule) for c, rule in policies))
