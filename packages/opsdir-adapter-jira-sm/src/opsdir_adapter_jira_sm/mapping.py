"""The operator's mapping of one Jira site's change tickets, as estate settings without defaults (the user's decision,
task 551): which neutral state each workflow status means (jira-sm-status-states) and which of the site's fields hold
the change's planned and actual windows and the other facts worth keeping (jira-sm-change-fields). Jira has no fixed
answer to either: a change workflow's statuses are the site's own (their ids differ between sites, and status
categories say only new, in progress or done), and the change fields are custom fields whose ids differ between sites
(their types are generic, so neither a name nor a type says what a field means). Pure.

A setting's text is comma-separated '<name>=<value>' pairs:
  jira-sm-status-states   '<status id or exact name>=<neutral state>, ...': 10010=assess, Implementing=implement
  jira-sm-change-fields   '<role>=<field id or exact name>, ...': planned-start=customfield_10070, planned-end=Planned
                          end, work-start=..., work-end=..., and any fact worth keeping (change-type=..., risk=...)
A name is resolved through the site's field list (GET /rest/api/{3|2}/field, which the collector saves): an exact name
two fields share is refused (map it by id). A status's id is matched before its name."""
import re

from opsdir.core.contract import Setting
from opsdir.core.settings import setting_value
from opsdir.domains.governance.schema import TICKET_STATES

STATUS_STATES = Setting("jira-sm-status-states", "string", None,
                        "What each Jira workflow status of the change tickets means, as comma-separated <status id "
                        f"or exact name>=<state> ({', '.join(TICKET_STATES)}): only mapped statuses are read in "
                        "neutral terms; any other is kept as Jira gives it")
CHANGE_FIELDS = Setting("jira-sm-change-fields", "string", None,
                        "Which of the Jira site's fields hold the change tickets' windows and facts, as "
                        "comma-separated <role>=<field id or exact name> (planned-start, planned-end, work-start, "
                        "work-end; any other role is kept as a fact, change-type, risk): the field ids are the site's "
                        "own (GET /rest/api/3/field)")
WINDOW = (("planned-start", "ciamTicketPlannedStart"), ("planned-end", "ciamTicketPlannedEnd"),
          ("work-start", "ciamTicketWorkStart"), ("work-end", "ciamTicketWorkEnd"))
ROLE = re.compile(r"[a-z][a-z0-9-]*")
CUSTOM_ID = re.compile(r"customfield_\d+")
# The names Atlassian documents for the change window fields (default form fields for change requests; Data Center's
# change start and completion dates), only to point the operator at candidates: never mapped without them.
WINDOW_NAMES = ("planned start", "planned start date", "planned end", "planned end date", "actual start",
                "actual end", "change start date", "change completion date")


def setting_pairs(text):
    """((name, value), ...) of a setting's '<name>=<value>, ...' text, and the parts that aren't one."""
    parts = [p.strip() for p in (text or "").split(",") if p.strip()]
    split = [(p, *(s.strip() for s in p.partition("=")[::2])) for p in parts]
    return (tuple((k, v) for p, k, v in split if "=" in p and k and v),
            tuple(f"`{p}` isn't <name>=<value>" for p, k, v in split if "=" not in p or not k or not v))


def _mapping(d, setting):
    pairs, problems = setting_pairs(setting_value(d, setting))
    twice = sorted({k for k, _ in pairs if sum(1 for x, _ in pairs if x == k) > 1})
    return pairs, (*(f"{setting.name}: {p}" for p in problems),
                   *(f"{setting.name}: `{k}` is mapped more than once (the first is used)" for k in twice))


def status_states(d):
    """({status id or exact name: neutral state}, problems) of jira-sm-status-states."""
    pairs, problems = _mapping(d, STATUS_STATES)
    bad = tuple(f"{STATUS_STATES.name}: `{k}={v}`: {v} isn't a ticket state ({', '.join(TICKET_STATES)})"
                for k, v in pairs if v not in TICKET_STATES)
    return {k: v for k, v in reversed(pairs) if v in TICKET_STATES}, (*problems, *bad)


def field_refs(d):
    """({role: field id or exact name}, problems) of jira-sm-change-fields."""
    pairs, problems = _mapping(d, CHANGE_FIELDS)
    bad = tuple(f"{CHANGE_FIELDS.name}: `{k}` isn't a role name (lowercase letters, digits and dashes)"
                for k, _ in pairs if not ROLE.fullmatch(k))
    return {k: v for k, v in reversed(pairs) if ROLE.fullmatch(k)}, (*problems, *bad)


def resolve_fields(refs, fields):
    """({role: field id}, problems): each reference the field list holds as an id, else the one field of that exact
    name; without a field list a customfield_N reference is kept as given and a name can't be resolved."""
    ids = {str(f.get("id")) for f in fields or () if f.get("id")}
    named = {}
    for f in fields or ():
        named.setdefault(str(f.get("name") or ""), []).append(str(f.get("id") or ""))

    def resolve(role, ref):
        if ref in ids or (fields is None and CUSTOM_ID.fullmatch(ref)):
            return ref, None
        if len(named.get(ref, ())) == 1:
            return named[ref][0], None
        if len(named.get(ref, ())) > 1:
            return None, (f"{CHANGE_FIELDS.name}: {role}: {len(named[ref])} fields are named `{ref}` "
                          f"({', '.join(sorted(named[ref]))}): map it by id")
        return None, (f"{CHANGE_FIELDS.name}: {role}: no field `{ref}`" +
                      (" in the site's field list" if fields is not None else
                       " (without the site's field list only a customfield_N id is read)"))
    done = {role: resolve(role, ref) for role, ref in sorted(refs.items())}
    return ({r: f for r, (f, _) in done.items() if f}, tuple(p for _, p in done.values() if p))


def neutral_state(status, states):
    """A status's neutral state by the operator's map (its id, then its exact name), or None."""
    status = status if isinstance(status, dict) else {}
    return states.get(str(status.get("id") or "")) or states.get(str(status.get("name") or ""))


def window_candidates(fields):
    """'<name> (<id>)' of the site's fields named like the documented change window fields."""
    return tuple(sorted(f"{f.get('name')} ({f.get('id')})" for f in fields or ()
                        if str(f.get("name") or "").strip().lower() in WINDOW_NAMES))
