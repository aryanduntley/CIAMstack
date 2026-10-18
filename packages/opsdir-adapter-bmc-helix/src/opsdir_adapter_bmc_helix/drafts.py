"""BMC Helix ITSM work-order drafts (Adapter.ticket_draft, connectors.handoff; decision 3415): a team's findings as
the body of a work-order create request, POST /api/arsys/v1/entry/WOI:WorkOrderInterface_Create, a file the team or an
admin posts with their own AR-JWT. opsdir never posts it and holds no BMC credential. Pure.

The body is {"values": {...}}, BMC's documented REST create example with the assignment, priority and deadline fields
of the work-order create mappings (the task 612 research):
  z1D_Action             CREATE
  Summary                the request's title
  Detailed Description   the findings as plain text (connectors.handoff.request_lines; correctly spelled, unlike the
                         incident interface's Detailed Decription)
  Status                 Assigned
  Support Company, Support Organization, Support Group Name
                         the team's support group, by bmc-helix-ticket-groups (names, as the foundation data has them)
  Priority               bmc-helix-ticket-fields' Priority when it gives one (Critical, High, Medium, Low), else High
                         when the findings hold a blocker and Medium otherwise
  Scheduled End Date     the end of the earliest do-by day, UTC, ISO 8601 (none: no finding has one); whether the
                         create interface takes it and passes it to the work order is unconfirmed (the README says so)
and the other fields bmc-helix-ticket-fields gives, among them the people and companies BMC's create example needs
(FOUNDATION): who submits and for whom, as the tenant's foundation data names them. Without the team's support group,
or without a FOUNDATION field, no draft is written (the server would refuse it) and the problem says which setting to
give. No field length is cut or checked: the form's limits weren't confirmed."""
import json
from urllib.parse import quote

from opsdir.connectors.handoff import request_lines
from opsdir.core.contract import Setting, TicketDraft
from opsdir.core.settings import setting_mapping

CREATE_FORM = "WOI:WorkOrderInterface_Create"
CREATE_PATH = f"/api/arsys/v1/entry/{quote(CREATE_FORM, safe='')}"
FOUNDATION = ("First Name", "Last Name", "Customer First Name", "Customer Last Name", "Company", "Customer Company",
              "Location Company")
GROUP_FIELDS = ("Support Company", "Support Organization", "Support Group Name")
OWNED = ("z1D_Action", "Summary", "Detailed Description", "Status", *GROUP_FIELDS, "Scheduled End Date")
PRIORITIES = ("Critical", "High", "Medium", "Low")
TICKET_GROUPS = Setting("bmc-helix-ticket-groups", "string", None,
                        "The BMC Helix support group each owning team's work orders are assigned to, as "
                        "comma-separated <team>=<Support Company>/<Support Organization>/<Support Group Name> (the "
                        "foundation data's names); a team without one gets no work-order draft")
TICKET_FIELDS = Setting("bmc-helix-ticket-fields", "string", None,
                        "The other values of every BMC Helix work-order draft, as comma-separated <field>=<value>: "
                        f"at least {', '.join(FOUNDATION)} (who submits the work order and for whom, as the "
                        "tenant's foundation data names them), and any the tenant's workflow requires (Priority, "
                        "Work Order Type, ...)")
HOW = (f"POST https://<ar-rest-host>{CREATE_PATH}",
       f"curl --request POST 'https://<ar-rest-host>{CREATE_PATH}' --header 'Authorization: AR-JWT <jwt>' "
       "--header 'Accept: application/json' --header 'Content-Type: application/json' --data-binary @<team>.json",
       "# <jwt>: your own AR System logon (POST /api/jwt/login); Scheduled End Date on the create interface is "
       "unconfirmed: check the work order's date after filing",
       "# the Work Order ID: WorkOrder_ID of the interface entry the answer's Location names (GET <Location>"
       "?fields=values(WorkOrder_ID)); link it as ciamTicketRef bmc-helix:<Work Order ID>")


def _setting_hint(setting, example):
    return f"`opsdir setting {setting.name} '{example}' --change <id>`"


def team_groups(d):
    """({team, lower case: (Support Company, Support Organization, Support Group Name)}, problems) of
    bmc-helix-ticket-groups; a value that isn't <company>/<organization>/<group> is named and left out."""
    pairs, problems = setting_mapping(d, TICKET_GROUPS)
    split = tuple((k, tuple(p.strip() for p in v.split("/", 2))) for k, v in pairs)
    bad = tuple(f"{TICKET_GROUPS.name}: `{k}={v}` isn't <team>=<company>/<organization>/<group>" for k, v in pairs
                if len([p for p in v.split("/", 2) if p.strip()]) != 3)
    return {k.lower(): g for k, g in reversed(split) if len(g) == 3 and all(g)}, (*problems, *bad)


def ticket_fields(d):
    """({field: value}, problems) of bmc-helix-ticket-fields (the first value of a field is used); fields opsdir
    sets itself (OWNED) are named and left out."""
    pairs, problems = setting_mapping(d, TICKET_FIELDS)
    owned = sorted({k for k, _ in pairs if k in OWNED})
    return ({k: v for k, v in reversed(pairs) if k not in OWNED},
            (*problems, *(f"{TICKET_FIELDS.name}: `{k}` is set by opsdir: left out" for k in owned)))


def due_time(day):
    """The end of a do-by day in UTC as an AR System ISO 8601 date-time (2026-11-01T23:59:59.000+0000), or None."""
    return None if day is None else f"{day.isoformat()}T23:59:59.000+0000"


def priority(request, fields):
    """(the work order's Priority, problems): bmc-helix-ticket-fields' Priority when it is one of PRIORITIES, else
    High when the findings hold a blocker and Medium otherwise."""
    given = fields.get("Priority")
    derived = "High" if any(i[0] == "blocker" for i in request.items) else "Medium"
    if given in PRIORITIES:
        return given, ()
    return derived, ((f"{TICKET_FIELDS.name}: Priority `{given}` isn't {', '.join(PRIORITIES)}: {derived} is used",)
                     if given else ())


def work_order_values(request, group, fields):
    """The create request's values of one TicketRequest: the given fields, then the ones opsdir sets (OWNED,
    Priority)."""
    level, _ = priority(request, fields)
    due = due_time(request.do_by)
    return {**fields, "z1D_Action": "CREATE", "Summary": request.title,
            "Detailed Description": "\n".join(request_lines(request)), "Status": "Assigned",
            **dict(zip(GROUP_FIELDS, group)), "Priority": level, **({"Scheduled End Date": due} if due else {})}


def ticket_draft(d, request):
    """TicketDraft of one team's findings: the work-order create body, or None with the problems saying which
    setting to give (no support group for the team, a FOUNDATION field missing)."""
    groups, group_problems = team_groups(d)
    fields, field_problems = ticket_fields(d)
    group = groups.get(request.team.lower())
    missing = tuple(f for f in FOUNDATION if not fields.get(f))
    blocking = (*((f"{TICKET_GROUPS.name} gives no support group for {request.team}: add "
                   f"`{request.team}=<company>/<organization>/<group>` to it, "
                   f"{_setting_hint(TICKET_GROUPS, '<team>=<company>/<organization>/<group>, ...')}",)
                  if group is None else ()),
                *((f"{TICKET_FIELDS.name} doesn't give {', '.join(missing)} (who submits the work order and for "
                   "whom, as the foundation data names them): "
                   f"{_setting_hint(TICKET_FIELDS, ', '.join(f'{f}=<value>' for f in FOUNDATION))}",)
                  if missing else ()))
    problems = (*group_problems, *field_problems, *priority(request, fields)[1], *blocking)
    if blocking:
        return TicketDraft(None, "json", HOW, problems)
    body = json.dumps({"values": work_order_values(request, group, fields)}, indent=2, ensure_ascii=False)
    return TicketDraft(body + "\n", "json", HOW, problems)
