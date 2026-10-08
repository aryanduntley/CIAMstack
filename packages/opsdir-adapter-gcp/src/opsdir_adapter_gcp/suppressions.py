"""Suppressions of findings on Google Cloud (core estate: ciamSuppression, carrying out an exception). Pure.

Rendered for each suppression the platform team keeps (one someone else keeps is named in a comment): its
gcp:scc:<category> refs as a Security Command Center mute rule, google_scc_v2_project_mute_config (type STATIC, location
global, mute_config_id exc-<exception> in lower case, filter category="..." OR ...), the exception and its expiry in the
description. The google provider (8.x) takes no expiry for a mute rule: a comment says when to remove it. Another
provider's or kind's refs are named in a comment.

Read back from Terraform state: SCC mute configs (project v2 and v1, organization) -> a suppression (kind suppression)
of the categories their filter names, its exception from the description (exception <cn>) or the id (exc-<cn>).
"""
import re

from opsdir.core.directory import date_of, get, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.poam import exception_of, suppression_name
from opsdir_format_terraform.hcl import block, ref, tf_name

MUTE = "google_scc_v2_project_mute_config"
MUTES = ("google_scc_v2_project_mute_config", "google_scc_project_mute_config",
         "google_scc_v2_organization_mute_config", "google_scc_mute_config")
SUPPRESSION = "ciamSuppression"
_CATEGORY = re.compile(r'category\s*=\s*"([^"]+)"')


def _refs(s):
    return [r.split(":", 2)[2] for r in values(s, "ciamFindingRef") if r.split(":", 2)[:2] == ["gcp", "scc"]]


def _others(s):
    return [r for r in values(s, "ciamFindingRef") if r.split(":", 2)[:2] != ["gcp", "scc"]]


def _mute(m, s):
    name, categories = suppression_name(s), _refs(s)
    if not categories:
        return ()
    exc = get(m.d, one(s, "ciamExceptionRef")) if one(s, "ciamExceptionRef") else None
    until = date_of(s, "ciamExpiresAt") or (date_of(exc, "ciamExpiresAt") if exc is not None else None)
    note = f"exception {rdn_value(exc) if exc is not None else '(none recorded)'}" + (f", until {until}" if until
                                                                                       else "")
    return (*((f"# {name}: the google provider takes no expiry for a mute rule: remove it on {until}",) if until
              else ()),
            block("resource", [MUTE, tf_name(name)], [
                ("mute_config_id", name.lower()), ("project", ref("var.project_id")), ("location", "global"),
                ("description", note), ("type", "STATIC"),
                ("filter", " OR ".join(f'category="{c}"' for c in categories))]))


def render_suppressions(m):
    """HCL (and comments) for environment m's suppressions."""
    kept = [s for s in of_class(m, SUPPRESSION) if not one(s, "ciamManagedBy")]
    held = [s for s in of_class(m, SUPPRESSION) if one(s, "ciamManagedBy")]
    return (*(x for s in kept for x in (*_mute(m, s),
                                        *((f"# {suppression_name(s)}: not Google Cloud's (not rendered here): "
                                           f"{', '.join(_others(s))}",) if _others(s) else ()))),
            *(f"# Suppression {suppression_name(s)}: kept by {rdn_value(get(m.d, one(s, 'ciamManagedBy')))}, not "
              "rendered here" for s in held if get(m.d, one(s, "ciamManagedBy")) is not None))


def _exception(a):
    note = a.get("description") or ""
    named = note.split(",", 1)[0].split(" ", 1)[1] if note.startswith("exception ") else None
    return named if named and named != "(none recorded)" else exception_of(a.get("mute_config_id"))


def suppression_resources(pairs):
    """Suppressions of (google type, attributes) pairs."""
    return tuple(resource("suppression", a.get("name") or a.get("id"), {
        "ciamFindingRef": tuple(f"gcp:scc:{c}" for c in _CATEGORY.findall(a.get("filter") or "")),
        "ciamExceptionRef": _exception(a)}, name=a.get("mute_config_id"))
        for t in MUTES for a in of_types(pairs, t) if (a.get("name") or a.get("id")) and a.get("mute_config_id"))
