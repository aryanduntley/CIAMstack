"""Jira work-ticket drafts (Adapter.ticket_draft, connectors.handoff; the user's decision 3415): one owning team's
findings as the body of a create-issue request a person posts with their own credentials, an issue of the project's
Task type (a plain issue, not a customer request: no request type or portal involved). opsdir files nothing and holds
no Jira credential. Pure.

The body is POST /rest/api/3/issue on Cloud (the description in Atlassian Document Format) or POST /rest/api/2/issue on
Data Center (the description a wiki-markup string), told apart by the site's base URL as the collector tells them
(collect.is_cloud). Its fields: project {key} and the team's routing field (mapped per team), issuetype {id}, summary
(the request's title), description (connectors.handoff.request_lines: where the findings come from, a Findings heading
and list, the link-back line), duedate (the earliest do-by, YYYY-MM-DD; absent when no finding has one) and the
operator's other defaults (priority by id, labels, components, ...).

What it needs, as estate settings without defaults (the site's own ids, never guessed):
  jira-sm-ticket-site        the site's base URL (https://<site>.atlassian.net, Government Cloud
                             https://<site>.atlassian-us-gov-mod.net, the gateway .../ex/jira/<cloudId>, or a Data
                             Center base URL with its context path)
  jira-sm-ticket-projects    '<team>=<project key>[/<team field value>], ...' (a team by name, any case)
  jira-sm-ticket-team-field  the field a team's routing value goes in (customfield_N, components), when one is given
  jira-sm-ticket-issue-type  (mapping.py) the work tickets' issue type id
  jira-sm-ticket-fields      '<field id>=<value>, ...' every work ticket is created with
A field value is text as it is, or '<shape>:<value>': id:3, value:High, name:IAM, key:..., accountId:... (an object of
that key), ids:/values:/names:/keys:a|b (a list of them), list:a|b (a list of text), number:5, text:<as is>.

What keeps a draft from being written (no site, no project for the team, no issue type, a team value without its
field) is a problem saying which setting to give; a malformed default is a problem and left out (the draft is
written)."""
import itertools
import json
import re
from typing import NamedTuple, Optional
from urllib.parse import urlsplit

from opsdir.connectors.handoff import request_lines
from opsdir.core.contract import Setting, TicketDraft
from opsdir.core.settings import setting_mapping, setting_value
from .collect import is_cloud
from .mapping import ISSUE_TYPE, PROJECT_KEY, issue_type_for, issue_types

SITE = Setting("jira-sm-ticket-site", "string", None,
               "The base URL of the Jira site work tickets are filed on (https://<site>.atlassian.net, "
               "https://<site>.atlassian-us-gov-mod.net, https://api.atlassian.com/ex/jira/<cloudId>, or a Data "
               "Center base URL): a Cloud site's drafts are REST v3 with an ADF description, any other Data "
               "Center's REST v2 with wiki markup")
PROJECTS = Setting("jira-sm-ticket-projects", "string", None,
                   "Which project each owning team's work tickets go to, as comma-separated <team>=<project "
                   "key>[/<team field value>] (the value goes in jira-sm-ticket-team-field, for a site that routes "
                   "by a team, component or select field)")
TEAM_FIELD = Setting("jira-sm-ticket-team-field", "string", None,
                     "The field a team's routing value from jira-sm-ticket-projects goes in, by id (customfield_N, "
                     "components)")
FIELDS = Setting("jira-sm-ticket-fields", "string", None,
                 "Other fields every work ticket is created with, as comma-separated <field id>=<value> (a value "
                 "is text, or <shape>:<value>: id:3, value:High, names:IAM|Directory, list:ciam|remediation, "
                 "number:5): priority=id:3, labels=list:ciam")
SETTINGS = (SITE, PROJECTS, TEAM_FIELD, FIELDS)
FIELD_ID = re.compile(r"customfield_\d+|[a-z][A-Za-z]*")
SET_BY_DRAFT = ("project", "issuetype", "summary", "description", "duedate")
OBJECT_SHAPES = ("id", "value", "name", "key", "accountId")
LIST_SHAPES = {"ids": "id", "values": "value", "names": "name", "keys": "key"}
WIKI_SPECIAL = re.compile(r"([\\\[\]{}|*_+^~!])")
GOV_SITE, GOV_GATEWAY = ".atlassian-us-gov-mod.net", "https://api.atlassian-us-gov-mod.com/ex/jira/<cloudId>"
FOLDER = "jira-sm"
SUMMARY_MAX = 255                  # Jira's limit on an issue's summary

# Where one team's tickets go: the project's key and the value its routing field takes (None: the project alone).
Route = NamedTuple("Route", [("project", str), ("team_value", Optional[str])])


def field_value(text):
    """(the JSON value of a field's '<shape>:<value>' text, or the text as it is; problem or None)."""
    shape, sep, rest = text.partition(":")
    if not sep or shape not in (*OBJECT_SHAPES, *LIST_SHAPES, "list", "number", "text"):
        return text, None
    parts = [p.strip() for p in rest.split("|") if p.strip()]
    if shape == "text":
        return rest, None
    if shape == "number":
        try:
            return (int(rest) if re.fullmatch(r"\s*-?\d+\s*", rest) else float(rest)), None
        except ValueError:
            return None, f"`{text}`: `{rest}` isn't a number"
    if shape == "list":
        return parts, None
    return ([{LIST_SHAPES[shape]: p} for p in parts] if shape in LIST_SHAPES else {shape: rest.strip()}), None


def team_routes(d):
    """({team name, lowercase: Route}, problems) of jira-sm-ticket-projects."""
    pairs, problems = setting_mapping(d, PROJECTS)
    split = tuple((k, *(s.strip() for s in v.partition("/")[::2])) for k, v in pairs)
    bad = tuple(f"{PROJECTS.name}: `{k}={p}`: {p} isn't a project key" for k, p, _ in split
                if not PROJECT_KEY.fullmatch(p))
    return ({k.lower(): Route(p, t or None) for k, p, t in reversed(split) if PROJECT_KEY.fullmatch(p)},
            (*problems, *bad))


def default_fields(d):
    """({field id: JSON value}, problems) of jira-sm-ticket-fields: fields the draft sets itself and malformed ones
    named and left out."""
    pairs, problems = setting_mapping(d, FIELDS)
    read = {k: field_value(v) for k, v in reversed(pairs) if FIELD_ID.fullmatch(k) and k not in SET_BY_DRAFT}
    return ({k: v for k, (v, why) in read.items() if why is None},
            (*problems,
             *(f"{FIELDS.name}: `{k}` isn't a field id (customfield_N, or a system field's id)" for k, _ in pairs
               if not FIELD_ID.fullmatch(k)),
             *(f"{FIELDS.name}: `{k}` is set by the draft itself (left out)" for k, _ in pairs if k in SET_BY_DRAFT),
             *(f"{FIELDS.name}: {k}: {why}" for k, (_, why) in sorted(read.items()) if why)))


def _paragraph(text):
    return {"type": "paragraph", "content": [{"type": "text", "text": text}]}


def _runs(lines):
    """(is a list run, its lines) of plain-text lines: each run of '- ' lines, and of the other non-empty lines."""
    return tuple((bullet, tuple(run)) for bullet, run in
                 itertools.groupby((ln for ln in lines if ln.strip()), key=lambda ln: ln.startswith("- ")))


def adf_description(lines):
    """An ADF document (Cloud v3's description) of plain-text lines: each run of '- ' lines a Findings heading and a
    bullet list, every other non-empty line a paragraph."""
    def blocks(bullet, run):
        if not bullet:
            return tuple(_paragraph(ln) for ln in run)
        return ({"type": "heading", "attrs": {"level": 2}, "content": [{"type": "text", "text": "Findings"}]},
                {"type": "bulletList", "content": [{"type": "listItem", "content": [_paragraph(ln[2:])]}
                                                   for ln in run]})
    return {"type": "doc", "version": 1, "content": [b for bullet, run in _runs(lines) for b in blocks(bullet, run)]}


def wiki_text(text):
    """Text with Jira wiki markup's special characters escaped (shown as they are, never as markup)."""
    return WIKI_SPECIAL.sub(r"\\\1", text)


def wiki_description(lines):
    """A wiki-markup string (Data Center v2's description) of plain-text lines: each run of '- ' lines an 'h2.
    Findings' heading and '*' items, every other non-empty line a paragraph."""
    def block(bullet, run):
        return ("h2. Findings\n" + "\n".join(f"* {wiki_text(ln[2:])}" for ln in run) if bullet else
                "\n\n".join(wiki_text(ln) for ln in run))
    return "\n\n".join(block(bullet, run) for bullet, run in _runs(lines))


def issue_fields(r, cloud, route, type_id, team_field, defaults):
    """The create request's fields for TicketRequest r: the operator's defaults, the team's routing value, then what
    the draft sets itself."""
    team = {team_field: field_value(route.team_value)[0]} if route.team_value and team_field else {}
    lines = request_lines(r)
    return {**defaults, **team, "project": {"key": route.project}, "issuetype": {"id": type_id},
            "summary": r.title[:SUMMARY_MAX],
            "description": adf_description(lines) if cloud else wiki_description(lines),
            **({"duedate": r.do_by.isoformat()} if r.do_by else {})}


def filing(site):
    """How to file a draft on the site: the request line and a curl with placeholders for the poster's own
    credential (Cloud: an account's email and API token, or a bearer token through the gateway; Data Center: a
    personal access token)."""
    cloud, host = is_cloud(site), (urlsplit(site).hostname or "").lower()
    api = f"{site}/rest/api/{3 if cloud else 2}/issue"
    auth = ("--header 'Authorization: Bearer <access-token>'" if "/ex/jira/" in urlsplit(site).path else
            "--user '<email>:<api-token>'" if cloud else "--header 'Authorization: Bearer <personal-access-token>'")
    said = "Jira Cloud, REST v3: the description is ADF" if cloud else "Jira Data Center, REST v2: wiki markup"
    return (f"POST {api} ({said})",
            f"curl --request POST '{api}' {auth} --header 'Accept: application/json' "
            f"--header 'Content-Type: application/json' --data-binary @{FOLDER}/<team>.json",
            *((f"Government Cloud: OAuth 2.0 apps call the gateway {GOV_GATEWAY} with a bearer token; whether an API "
               "token is taken on the site itself is unconfirmed",) if host.endswith(GOV_SITE) else ()),
            "The answer's key (for example ITOPS-42) is the ticket to link: ciamTicketRef jira-sm:<key>.")


def _site(d):
    """(the site's base URL, without a trailing slash, or None; problems)."""
    site = (setting_value(d, SITE) or "").strip().rstrip("/")
    u = urlsplit(site)
    if not site:
        return None, (f"no {SITE.name}: the base URL of the Jira site the tickets are filed on (`opsdir setting "
                      f"{SITE.name} https://<site>.atlassian.net --change <id>`)",)
    if u.scheme not in ("https", "http") or not u.hostname:
        return None, (f"{SITE.name}: `{site}` isn't a site's base URL (https://<host>[/<context>])",)
    return site, ()


def ticket_draft(d, r):
    """TicketDraft of TicketRequest r: the create-issue body for the team's project (None, with the problems saying
    which setting to give, when the site, the team's project, the issue type or the team's routing field isn't
    mapped), how to file it, and the mapping's problems."""
    site, site_problems = _site(d)
    routes, route_problems = team_routes(d)
    types, type_problems = issue_types(d)
    defaults, field_problems = default_fields(d)
    team_field = (setting_value(d, TEAM_FIELD) or "").strip() or None
    route = routes.get(r.team.lower())
    type_id = issue_type_for(types, route.project) if route else None
    missing = (
        *site_problems,
        *((f"{PROJECTS.name} names no project for {r.team} (`opsdir setting {PROJECTS.name} '<team>=<project "
           f"key>[/<team field value>], ...' --change <id>`, every team in one value)",) if route is None else ()),
        *((f"{ISSUE_TYPE.name} names no issue type for project {route.project} (its Task type's id, from GET "
           f"/rest/api/3/issue/createmeta/{route.project}/issuetypes: `opsdir setting {ISSUE_TYPE.name} <id> "
           "--change <id>`)",) if route is not None and type_id is None else ()),
        *((f"{r.team}'s value in {PROJECTS.name} needs its field: `opsdir setting {TEAM_FIELD.name} "
           "customfield_<n> --change <id>`",) if route is not None and route.team_value and not team_field else ()),
        *((f"{TEAM_FIELD.name}: `{team_field}` isn't a field id (customfield_N, components)",)
          if team_field and not FIELD_ID.fullmatch(team_field) else ()))
    body = None if missing else json.dumps(
        {"fields": issue_fields(r, is_cloud(site), route, type_id, team_field, defaults)}, indent=1, sort_keys=True)
    return TicketDraft(body, "json", filing(site) if site else (),
                       (*missing, *route_problems, *type_problems, *field_problems))
