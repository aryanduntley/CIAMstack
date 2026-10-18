"""The alert rules adopting a product's declared detection as Splunk saved searches (task 597): per rule the
environment delivers that no alarm binding of its own realizes (observability.detections.native_rules), a scheduled
search written here in SPL from the rule's canonical selector and the declaration's mapping for the product version the
environment runs, over the Splunk indexes the rule's server role's log routes reach (detections.searched). Pure.

The search: `index=<index> <selector>` (`(index=a OR index=b)` for several), each canonical field as the product's
field and each canonical value as the product's (field="value", or field IN ("a", "b")); then, when the rule counts,
`stats count by <its group-by fields> | where count >= <threshold>`, or with a distinct field `stats
dc(<distinct field>) AS value_count by <group-by fields> | where value_count >= <threshold>` (stats leaves out the
events missing a field it groups by). Each result is an alert (counttype number of events, relation greater than,
quantity 0: the trigger as savedsearches.conf names it) and alert.digest_mode = 0 makes one alert per group. A rule
without a threshold alerts per matching event, every 5 minutes over the 5 clock minutes before.

The window (research on task 597: Splunk's savedsearches.conf, time modifiers and streamstats references):
- fixed: the search runs on a cron schedule every window (minutes dividing an hour, hours dividing a day) over the
  window just ended, aligned to the clock (dispatch.earliest_time -<n>m@m, dispatch.latest_time @m; or hours);
- sliding: it runs every step (detections.overlap_step: a fifth of the window, a minute at least, a step cron keeps)
  over the whole window before it (-<window>s to now), and a group that fired is suppressed for a window
  (alert.suppress, alert.suppress.fields its group-by fields, alert.suppress.period), so a burst several runs find
  alerts once. Every burst within the window less one step is caught. streamstats time_window would count every span
  exactly, but Splunk caps its window at max_stream_window events (10,000 by default) even then, so on a busy index it
  undercounts: the overlapping runs are the sound form.
Where the stack runs Splunk Enterprise Security, the search is an ES correlation search (es.search_settings) whose
risk objects are what it groups by: a subject or actor as a user, a source address as a threat object (detections.
ENTITIES).

The saved search is named opsdir-<rule> (detections.native_name): its readers leave it out, the record holding no
search for it. A rule the render can't write is a blocker (detections.native_notes): its condition isn't a count
reached, no mapping holds for the product version the environment runs, a field the mapping doesn't name or SPL can't
name in a search (letters, digits, underscores and dots), a fixed window cron can't keep, or a sliding window too short
to search again within it.
"""
import re

from opsdir.core.directory import rdn_value
from opsdir.core.notes import note
from opsdir.domains.observability.detections import (ENTITIES, native_name, native_notes, native_rules, overlap_step,
                                                     product_field, product_values, searched)
from opsdir.domains.observability.siem import described
from .es import risk_entries, search_settings
from .naming import enterprise_security, index_name, keeps
from .schedule import aligned_window, cron_schedule

EVERY = 300                         # how often a rule without a threshold searches (each matching event an alert)
MIN_STEP = 60                       # cron's finest step: a sliding window's search runs again each minute at most
TRIGGER = (("counttype", "number of events"), ("relation", "greater than"), ("quantity", "0"))
_FIELD = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def spl_string(text):
    """An SPL quoted string."""
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _term(field, found):
    return f"{field}={spl_string(found[0])}" if len(found) == 1 else \
        f"{field} IN ({', '.join(map(spl_string, found))})"


def _selected(mapping, field, canonical):
    return tuple(dict.fromkeys(v for c in canonical for v in product_values(mapping, field, c)))


def grouped(det, mapping):
    """The product's fields a declaration as a rule has it (det) groups by, in order."""
    return tuple(product_field(mapping, f) for f in det.group_by)


def spl_search(det, mapping, names):
    """The SPL of a declaration as an alert rule has it (det) in the product's fields and values (mapping), over the
    Splunk indexes names: its matching events, counted per group (or their distinct values of its distinct field) and
    kept where they reach its threshold; the events themselves when it has none."""
    where = " OR ".join(f"index={n}" for n in names)
    head = " ".join((f"({where})" if len(names) > 1 else where,
                     *(_term(product_field(mapping, f), _selected(mapping, f, vals)) for f, vals in det.selector)))
    if det.threshold is None:
        return head
    by = f" by {', '.join(grouped(det, mapping))}" if det.group_by else ""
    if det.distinct:
        return (f"{head} | stats dc({product_field(mapping, det.distinct)}) AS value_count{by} "
                f"| where value_count >= {det.threshold}")
    return f"{head} | stats count{by} | where count >= {det.threshold}"


def timing(det, fields):
    """(the schedule settings of a declaration's saved search (det: as the rule has it; fields: the product's fields it
    groups by), None) or (None, why its window can't be kept)."""
    if det.threshold is None:
        return (("cron_schedule", cron_schedule(EVERY)[0]), *zip(("dispatch.earliest_time", "dispatch.latest_time"),
                                                                  aligned_window(EVERY))), None
    window = det.window_seconds
    if det.window_kind == "fixed":
        cron, why = cron_schedule(window)
        return ((("cron_schedule", cron), *zip(("dispatch.earliest_time", "dispatch.latest_time"),
                                               aligned_window(window))), None) if why is None else (
            None, f"its fixed window ({window}s) isn't one a cron schedule keeps aligned to the clock (minutes "
                  "dividing an hour, hours dividing a day)")
    step = overlap_step(window, MIN_STEP)
    if det.window_kind != "sliding" or step is None:
        return None, (f"its window kind {det.window_kind!r} isn't sliding or fixed" if det.window_kind != "sliding"
                      else f"its sliding window ({window}s) is too short to search again within it (a saved search "
                           "runs each minute at the most often)")
    return (("cron_schedule", cron_schedule(step)[0]), ("dispatch.earliest_time", f"-{window}s"),
            ("dispatch.latest_time", "now"), ("alert.suppress", "1"),
            *((("alert.suppress.fields", ",".join(fields)),) if fields else ()),
            ("alert.suppress.period", f"{window}s")), None


def _named(det, mapping):
    return tuple(dict.fromkeys(product_field(mapping, f) for f in (
        *(f for f, _ in det.selector), *det.group_by, *((det.distinct,) if det.distinct else ()))))


def _why(x):
    if x.why:
        return x.why
    bad = tuple(p for p in _named(x.det, x.mapping) if not _FIELD.match(p))
    if bad:
        return (f"the product's fields {', '.join(bad)} can't be named in an SPL search (letters, digits, underscores "
                "and dots)")
    return timing(x.det, grouped(x.det, x.mapping))[1]


def splunk_rules(m, services):
    """((NativeRule, the Splunk indexes it searches), ...) of environment m's adopting rules whose server role's logs
    reach a Splunk index it keeps (the rest are another SIEM's, or none's)."""
    return tuple((x, found) for x in native_rules(m, services.detections(m))
                 for found in (searched(m, x.det, keeps),) if found)


def native_stanza(m, x, indexes):
    """The savedsearches.conf stanza of adopting rule x (a NativeRule) over Splunk indexes in environment m (an ES
    correlation search where m runs Splunk Enterprise Security), or None when it isn't rendered (_why)."""
    if _why(x):
        return None
    rule, fields = rdn_value(x.rule), grouped(x.det, x.mapping)
    settings, _ = timing(x.det, fields)
    mapped = tuple((*ENTITIES[f], product_field(x.mapping, f)) for f in x.det.group_by if f in ENTITIES)
    search = spl_search(x.det, x.mapping, tuple(map(index_name, indexes)))
    return (native_name(rule),
            (("description", described(rule)), ("search", search), ("is_scheduled", "1"), *settings, *TRIGGER,
             ("alert.digest_mode", "0"), ("disabled", "0"),
             *(search_settings(x.rule, risk_entries(x.rule, mapped)) if enterprise_security(m) else ())))


def native_stanzas(m, services):
    """The savedsearches.conf stanzas of environment m's adopting rules rendered in Splunk."""
    return tuple(s for x, found in splunk_rules(m, services) for s in (native_stanza(m, x, found),) if s is not None)


def rendered_rules(m, services):
    """The alert rules of environment m rendered natively in Splunk (their saved searches: native_stanzas)."""
    return tuple(x.rule for x, _ in splunk_rules(m, services) if not _why(x))


def adopted_notes(m, services):
    """The render notes of environment m's adopting rules in Splunk: those not rendered (blockers), those rendered from
    a declaration documented only (notes), and that the searches name the product's fields as Splunk extracts them
    (a note)."""
    found = tuple(x for x, _ in splunk_rules(m, services))
    done = tuple(x for x in found if not _why(x))
    return (*native_notes(m, done, tuple((x, _why(x)) for x in found if _why(x)), "Splunk"),
            *((note("Monitoring", "note", "Splunk saved searches", "the searches of the alert rules adopting a "
                    "product's detection name the product's fields as Splunk extracts them from its JSON events (the "
                    "forwarders' sourcetype _json); events arriving otherwise (container output) are searched only "
                    "once the Splunk team extracts those fields",
                    ("Run each search once over the product's events and check its fields are there",), None,
                    m.label),) if done else ()))
