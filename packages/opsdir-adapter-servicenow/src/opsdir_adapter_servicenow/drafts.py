"""ServiceNow work-ticket drafts (Adapter.ticket_draft, connectors.handoff): a team's findings as the Table API create
body of a record in the site-approved table derived from task that the operator names (servicenow-ticket-table), a file
a person posts with their own credentials. opsdir posts nothing and holds no credential. Pure.

The body is for POST /api/now/table/<table>?sysparm_input_display_value=false, raw values only:
  short_description   the ticket's title (the team, how many findings, the plan's source and target)
  description         plain text: the findings with their areas and do-by dates (connectors.handoff.request_lines);
                      never work_notes or comments, which are journal fields
  assignment_group    the team's group sys_id (servicenow-ticket-groups): a group's name would need display-value
                      input, which also reads date/times in the poster's time zone
  due_date            the earliest do-by date, to the end of that UTC day ('YYYY-MM-DD 23:59:59'); none without one
and the operator's defaults (servicenow-ticket-fields: impact, urgency, or what the table makes mandatory), never one of
the drafted fields. A filed ticket is linked on the change doing the work (ciamTicketRef servicenow:<number>) and read
back from the same table as a work ticket (changes.py)."""
import json
import re

from opsdir.connectors.handoff import request_lines
from opsdir.core.contract import Setting, TicketDraft
from opsdir.core.settings import setting_mapping
from .changes import TICKET_TABLE, instance_hosts, work_table

TICKET_GROUPS = Setting("servicenow-ticket-groups", "string", None,
                        "Each owning team's ServiceNow assignment group for its work-ticket drafts ('<team>=<group "
                        "sys_id>, ...'; the team as its ciamParty under ou=owners is named, any case)")
TICKET_FIELDS = Setting("servicenow-ticket-fields", "string", None,
                        "Fields every work-ticket draft also sets, as raw values ('<field>=<value>, ...', e.g. "
                        "impact=3, urgency=3, or what the work-ticket table makes mandatory); never a drafted field")
DRAFT_SETTINGS = (TICKET_GROUPS, TICKET_FIELDS)
DRAFTED = ("short_description", "description", "assignment_group", "due_date")
SYS_ID = re.compile(r"[0-9a-fA-F]{32}")


def _command(setting, value):
    return f"`opsdir setting {setting.name} '{value}' --change CHG-…`"


def ticket_body(r, group, defaults):
    """A TicketRequest's create body as JSON text: the operator's defaults ((field, value), ...: the first of a field
    is used; drafted fields left out), then the drafted fields."""
    fields = {**{k: v for k, v in reversed(tuple(defaults)) if k not in DRAFTED},
              "short_description": r.title, "description": "\n".join(request_lines(r)), "assignment_group": group,
              **({"due_date": f"{r.do_by.isoformat()} 23:59:59"} if r.do_by else {})}
    return json.dumps(fields, indent=1, sort_keys=True) + "\n"


def how_to_file(d, table):
    """How a person files a draft: the request line and a curl with placeholders for their own credential, run from
    the tickets folder (the instance's host when the record's tickets were read from one)."""
    hosts = instance_hosts(d)
    url = (f"https://{hosts[0] if len(hosts) == 1 else '<instance host>'}/api/now/table/{table}"
           "?sysparm_input_display_value=false")
    return (f"POST {url}",
            f"curl --request POST '{url}' --header 'Authorization: Bearer <access token>' --header 'Accept: "
            "application/json' --header 'Content-Type: application/json' --data-binary @servicenow/<team>.json",
            "(a password instead: --user '<user name>' in place of the Authorization header; curl asks for it)",
            "The answer's result.number is the ticket: link it on the change doing the work, ciamTicketRef "
            "servicenow:<number>.")


def ticket_draft(d, r):
    """TicketDraft of one team's findings: the create body, or None and why (no usable work-ticket table, no
    assignment group for the team, a group that isn't a sys_id), with the draft settings' problems."""
    table, table_problems = work_table(d)
    groups, group_problems = setting_mapping(d, TICKET_GROUPS)
    defaults, default_problems = setting_mapping(d, TICKET_FIELDS)
    group = next((v for k, v in groups if k.lower() == r.team.lower()), None)
    missing = (
        *table_problems,
        *((f"{TICKET_TABLE.name} isn't set: name the site-approved table derived from task that work tickets are "
           f"filed in, {_command(TICKET_TABLE, '<table>')}",) if table is None and not table_problems else ()),
        *((f"{TICKET_GROUPS.name} names no assignment group for {r.team}: add `{r.team}=<group sys_id>` to it, "
           f"{_command(TICKET_GROUPS, '<team>=<group sys_id>, ...')}",) if group is None else ()),
        *((f"{TICKET_GROUPS.name}: {r.team}'s group `{group}` isn't a sys_id (32 hex characters): drafts post raw "
           f"values, so give the group's sys_id, {_command(TICKET_GROUPS, '<team>=<group sys_id>, ...')}",)
          if group is not None and not SYS_ID.fullmatch(group) else ()))
    notes = (*group_problems, *default_problems,
             *(f"{TICKET_FIELDS.name}: `{k}` is drafted from the findings: its default is left out"
               for k in dict.fromkeys(k for k, _ in defaults if k in DRAFTED)))
    how = how_to_file(d, table) if table else ()
    if missing:
        return TicketDraft(None, "json", how, (*missing, *notes))
    return TicketDraft(ticket_body(r, group, defaults), "json", how, notes)
