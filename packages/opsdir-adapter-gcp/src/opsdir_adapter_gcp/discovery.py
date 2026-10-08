"""Data discovery on Google Cloud (core estate: ciamDataDiscovery) as Sensitive Data Protection. Pure.

For each data discovery the platform team keeps (one someone else keeps is named in a comment): its own data types as
custom regular-expression info types of a google_data_loss_prevention_inspect_template (named by their names in upper
case), and a google_data_loss_prevention_discovery_config in the project and the cloud's region, running, profiling the
Cloud Storage buckets of the object stores it examines (a bucket-name regular expression) with that template. Sensitive
Data Protection refreshes profiles daily or monthly: monthly when ciamRescanDays is 30 or more, else daily (never less
often than the record asks; a comment when that is more often). Profile events (new, changed) go to the Pub/Sub topic of
the binding ciamFindingsRole names (ciamProviderRef projects/<p>/topics/<t>; another binding is a NOTE). Other stores it
examines (databases, volumes) are a comment: only Cloud Storage targets are rendered. It exports detailed profiles to
BigQuery only: a ciamResultsRole is a comment.

Read back from Terraform state: google_data_loss_prevention_discovery_config (its buckets from the bucket-name
expression, daily or monthly as days, its template's custom info types as own data types, the topic its Pub/Sub
notifications go to) -> data discovery (kind discovery)."""
import re

from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.inventory import of_types, resource
from opsdir.domains.estate.discovery import custom_identifiers, destination, discovery_services
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .storage import bucket_of

TEMPLATE, CONFIG = "google_data_loss_prevention_inspect_template", "google_data_loss_prevention_discovery_config"
PARENT = "projects/${var.project_id}/locations/${var.region}"
EVENTS = ("NEW_PROFILE", "CHANGED_PROFILE")
MONTHLY = 30                        # days from which a monthly refresh is as often as the record asks


def _keeper(m, s):
    holder = get(m.d, one(s, "ciamManagedBy"))
    return rdn_value(holder) if holder is not None else one(s, "ciamManagedBy")


def _binding(m, role):
    return next((x for x in m.bindings if one(x, "ciamBindingRole") == role), None)


def _buckets(m, s):
    """(Cloud Storage buckets of the stores discovery s examines, the roles that aren't buckets)."""
    found = [(r, b) for r in values(s, "ciamScansRole") for b in (_binding(m, r),)]
    names = [bucket_of(one(b, "ciamStorageRef")) if b is not None and is_kind(m.d, b, "ciamObjectStore") else None
             for _, b in found]
    return [x for x in names if x], [r for (r, _), x in zip(found, names) if not x]


def info_type(name):
    """The custom info type name of an own data type (cui-marking -> CUI_MARKING)."""
    return re.sub(r"[^A-Z0-9_]", "_", name.upper())


def _template(s, n):
    own = custom_identifiers(s)
    return (block("resource", [TEMPLATE, n], [
        ("parent", PARENT), ("template_id", f"ciam-{rdn_value(s)}"),
        ("display_name", f"{rdn_value(s)}: own data types"),
        ("inspect_config", Block(tuple(("custom_info_types", Block((
            ("info_type", Block((("name", info_type(name)),))), ("likelihood", "LIKELY"),
            ("regex", Block((("pattern", rx),)))))) for name, rx in own)))]),) if own else ()


def _refresh(s):
    days = one(s, "ciamRescanDays")
    d = int(days) if days is not None else MONTHLY
    return ("UPDATE_FREQUENCY_MONTHLY" if d >= MONTHLY else "UPDATE_FREQUENCY_DAILY",
            (f"# {rdn_value(s)}: Sensitive Data Protection refreshes profiles daily or monthly: the record asks every "
             f"{d} days, profiled daily",) if 1 < d < MONTHLY else ())


def _topic(m, s):
    dest = destination(m, s, "ciamFindingsRole")
    pref = one(dest, "ciamProviderRef") if dest is not None else None
    return dest, (pref if pref and "/topics/" in pref else None)


def _config(m, s):
    cn, n = rdn_value(s), tf_name(rdn_value(s))
    buckets, others = _buckets(m, s)
    frequency, note = _refresh(s)
    dest, topic = _topic(m, s)
    notes = (*note,
             *((f"# {cn}: only Cloud Storage targets are rendered: {', '.join(others)} not examined here",)
               if others else ()),
             *((f"# NOTE: {cn}'s findings to {one(s, 'ciamFindingsRole')}: not rendered: {rdn_value(dest)} names no "
                "Pub/Sub topic (ciamProviderRef projects/<p>/topics/<t>)",) if dest is not None and not topic else ()),
             *((f"# {cn}: Sensitive Data Protection exports detailed profiles to BigQuery only: "
                f"{one(s, 'ciamResultsRole')} isn't written to",) if one(s, "ciamResultsRole") else ()))
    if not buckets:
        return (*notes, f"# NOTE: data discovery {cn}: no discovery config: it examines no Cloud Storage bucket here")
    regex = "^(" + "|".join(re.escape(b) for b in buckets) + ")$"
    return (*notes, *_template(s, n), block("resource", [CONFIG, n], [
        ("parent", PARENT), ("location", ref("var.region")), ("display_name", cn), ("status", "RUNNING"),
        *((("inspect_templates", [ref(f"{TEMPLATE}.{n}.id")]),) if custom_identifiers(s) else ()),
        ("targets", Block((("cloud_storage_target", Block((
            ("filter", Block((("collection", Block((("include_regexes", Block((("patterns", Block((
                ("cloud_storage_regex", Block((("project_id_regex", "^${var.project_id}$"),
                                               ("bucket_name_regex", regex)))),))),))),))),))),
            ("generation_cadence", Block((("refresh_frequency", frequency),)))))),))),
        *(("actions", Block((("pub_sub_notification", Block((("topic", topic), ("event", e)))),)))
          for e in (EVENTS if topic else ()))]))


def render_discovery(m):
    """HCL (and comments) for environment m's data discovery."""
    return (*(f"# Data discovery {rdn_value(s)}: kept by {_keeper(m, s)}, not rendered here"
              for s in discovery_services(m) if one(s, "ciamManagedBy")),
            *(x for s in discovery_services(m) if not one(s, "ciamManagedBy") for x in _config(m, s)))


# ------------------------------------------------------------------ read back
def _first(v):
    return (v or [{}])[0] or {}


def _regex_buckets(rx):
    """The bucket names a ^(a|b)$ expression names (escapes undone), else ()."""
    found = re.fullmatch(r"\^\((.*)\)\$", rx or "")
    return tuple(re.sub(r"\\(.)", r"\1", b) for b in found.group(1).split("|")) if found else ()


def _config_buckets(a):
    target = _first(_first(a.get("targets")).get("cloud_storage_target"))
    patterns = _first(_first(_first(target.get("filter")).get("collection")).get("include_regexes")).get("patterns")
    return tuple(dict.fromkeys(b for p in patterns or () for b in _regex_buckets(
        _first(p.get("cloud_storage_regex")).get("bucket_name_regex")))), target


def _own(templates, a):
    """name: regex of the custom info types of the templates a discovery config uses."""
    used = [templates[t] for t in a.get("inspect_templates") or () if t in templates]
    return tuple(f"{_first(c.get('info_type')).get('name', '').lower().replace('_', '-')}: "
                 f"{_first(c.get('regex')).get('pattern')}"
                 for t in used for c in _first(t.get("inspect_config")).get("custom_info_types") or ()
                 if _first(c.get("regex")).get("pattern"))


def _discovery(a, templates):
    buckets, target = _config_buckets(a)
    frequency = _first(target.get("generation_cadence")).get("refresh_frequency")
    topic = next((n.get("topic") for x in a.get("actions") or () for n in x.get("pub_sub_notification") or ()
                  if n.get("topic")), None)
    return resource("discovery", a.get("id"), {
        "ciamRescanDays": {"UPDATE_FREQUENCY_DAILY": 1, "UPDATE_FREQUENCY_MONTHLY": MONTHLY}.get(frequency),
        "ciamCustomIdentifier": _own(templates, a)},
        links={"ciamScansRole": buckets, "ciamFindingsRole": topic}, name=a.get("display_name") or "sdp")


def discovery_resources(pairs):
    """Data discovery of (google type, attributes) pairs."""
    templates = {t.get("id"): t for t in of_types(pairs, TEMPLATE) if t.get("id")}
    return tuple(_discovery(a, templates) for a in of_types(pairs, CONFIG) if a.get("id"))
