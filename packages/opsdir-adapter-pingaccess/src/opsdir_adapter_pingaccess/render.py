"""PingAccess's configuration for one environment as Admin API requests, and what the render leaves to a person. Pure.

  pingaccess/admin-api/requests.json
      {"pingAccess": the version the environment's PingAccess servers run, "adminApi": "v3", "verified": false,
       "openApi": the installed schema to check the requests against, "problems": [...],
       "requests": [{"method", "path", "createWith", "body"}]}

Every object the record holds for PingAccess, except the environment-bound ones, as one request, in the order
PingAccess needs them (an object after those it names: api.COLLECTIONS): a settings object is a PUT to its path;
another a PUT to <collection>/${pingaccess-id:<collection>/<name>}, createWith the POST that creates it where it
doesn't exist yet. PingAccess assigns every object's id itself, so the operator's pipeline applies the requests in
order, keeps the id each object gets by its name, and replaces each ${pingaccess-id:<collection>/<name>} (in paths and
bodies) with that id; opsdir never writes to PingAccess. Hosts come from the environment's bindings (a virtual host's
service name, a site's application), UNBOUND:<role> where it binds none; a web session's client id from its
integration; secrets are never values: ${secret:<reference>} of the object's credential role, UNBOUND:<role>, or
${withheld} while no credential role is set.

Render notes (core.notes, as data): the requests are unverified against the version's own schema; environment-bound
objects (keys, trust, listeners, cluster nodes, agents) to create in the environment; the server profile data.json
and the nodes' files aren't rendered; secrets with no credential role.
"""
import json

from opsdir.core.directory import children, follow, get, one, rdn_of, rdn_value, values
from opsdir.core.environment import UNBOUND, bound, role_bindings
from opsdir.core.jsondata import WITHHELD, held_json
from opsdir.core.notes import note
from opsdir.domains.compute.workloads import recorded_versions
from .api import API, CLIENT_ID, COLLECTIONS, CONTEXT_ROOT, HOST, NAME, NAME_FIELDS, OPENAPI, TARGETS, collection
from .naming import KINDS, SERVER_ROLES, entry_dn, held_base, reference, resources_path
from .refs import placeholders
from .takeover import handed_over, requests, takeover_notes
from .withheld import credential_value, filled

OUTPUT = "pingaccess/admin-api/requests.json"
FORMATS = (("pingaccess/admin-api/*.json", "json"),)
AREA = "PingAccess"


def version(m):
    """The PingAccess version environment m's servers record (the admin node's, else an engine's), or None."""
    return next((v for r in SERVER_ROLES for v in recorded_versions(m, r)), None)


def _applications(d):
    """The record's PingAccess applications d has PingAccess enforce (not those whose protected application another
    role enforces there: takeover.handed_over)."""
    gone = handed_over(d)
    return tuple(a for a in children(d, KINDS["application"][0], "paApplication") if a.dn.lower() not in gone)


def entries_of(d, c):
    """The record's entries of a collection, in the record's order (an application's resources after it)."""
    if c.kind == "held":
        return children(d, held_base(c.path), "paHeld")
    if c.kind == "resource":
        return tuple(r for a in _applications(d) for r in children(d, a.dn, "paResource"))
    if c.kind == "application":
        return _applications(d)
    return children(d, KINDS[c.kind][0], KINDS[c.kind][1])


def site_targets(m, site):
    """A site's targets in environment m: host:port of each binding of its backend role, in host order (the port the
    site records, else the binding's), or UNBOUND:<role>[:port]."""
    role, port = one(site, "paBackendRole"), one(site, "paPort")
    found = tuple(f"{one(b, 'ciamFqdn')}:{port or one(b, 'ciamPort')}" for b in role_bindings(m, role)
                  if one(b, "ciamFqdn") and (port or one(b, "ciamPort")))
    return list(found) or [f"{UNBOUND}{role}" + (f":{port}" if port else "")]


def _client_id(d, session, body):
    integration = follow(d, session, "paIntegration")
    client = one(integration, "ciamClientId") if integration is not None else None
    if not client:
        return body
    credentials = body.get(CLIENT_ID[0]) if isinstance(body.get(CLIENT_ID[0]), dict) else {}
    return {**body, CLIENT_ID[0]: {CLIENT_ID[1]: client, **credentials}}


def body(m, c, e):
    """An entry's request body for environment m."""
    settings = filled(m, e, held_json(e, "paConfig"))
    named = {} if c.settings or c.kind == "virtual-host" else {NAME_FIELDS.get(c.path, NAME): rdn_value(e)}
    if c.kind == "virtual-host" and one(e, "paServiceRole"):
        named = {HOST: bound(m, one(e, "paServiceRole"), "ciamFqdn")}
    if c.kind == "site" and one(e, "paBackendRole"):
        named = {**named, TARGETS: site_targets(m, e)}
    if c.kind == "application" and one(e, "paContextRoot"):
        named = {**named, CONTEXT_ROOT: one(e, "paContextRoot")}
    full = {**named, **settings}
    return _client_id(m.d, e, full) if c.kind == "web-session" else full


def request(m, c, e):
    """One entry's request: a settings object's PUT, or an object's PUT creatable by POST."""
    if c.settings:
        return {"method": "PUT", "path": f"/{c.path}", "body": body(m, c, e)}
    path = resources_path(rdn_of(e.dn.split(",", 1)[1])) if c.kind == "resource" else c.path
    return {"method": "PUT", "path": f"/{path}/{reference(path, rdn_value(e))}", "createWith": f"POST /{path}",
            "body": body(m, c, e)}


def rendered(d):
    """((Collection, entry), ...) of what the requests hold: every collection but the environment-bound ones."""
    return tuple((c, e) for c in COLLECTIONS if not c.bound for e in entries_of(d, c))


def environment_bound(d):
    """((Collection, entries), ...) of the environment-bound objects the record holds (never rendered)."""
    return tuple((c, found) for c in COLLECTIONS if c.bound for found in (entries_of(d, c),) if found)


def missing_references(d, e):
    """The ${pingaccess-id:...} references in an entry's settings naming an object the record doesn't hold."""
    def held(path, name):
        c = collection(path)
        return c is not None and c.kind != "resource" and get(d, entry_dn(c.kind, name, c.path)) is not None
    return tuple(f"{p}/{n}" for p, n in placeholders(held_json(e, "paConfig")) if not held(p, n))


def problems(m, reqs):
    """What the requests can't do as rendered, in words."""
    d = m.d
    return (*(f"{c.path} {rdn_value(e)}: its secrets are withheld and no credential role (paCredentialRole) supplies "
              "them" for c, e in rendered(d) if values(e, "paWithheld") and credential_value(m, e) == WITHHELD),
            *(f"{c.path} {rdn_value(e)}: names {ref}, which the record doesn't hold" for c, e in rendered(d)
              for ref in missing_references(d, e)),
            *(f"role `{r}` isn't bound in {m.label}" for r in dict.fromkeys(
                v[len(UNBOUND):].split(":", 1)[0] for r in reqs for v in _strings(r["body"])
                if v.startswith(UNBOUND))))


def _strings(value):
    if isinstance(value, dict):
        return tuple(s for v in value.values() for s in _strings(v))
    if isinstance(value, list):
        return tuple(s for v in value for s in _strings(v))
    return (value,) if isinstance(value, str) else ()


def admin_api_files(m):
    """{pingaccess/admin-api/requests.json: text} for environment m (nothing when the record holds nothing for
    PingAccess to render)."""
    reqs = [r for c in COLLECTIONS if not c.bound
            for r in (*(request(m, c, e) for e in entries_of(m.d, c)), *requests(m, c.path))]
    if not reqs:
        return {}
    doc = {"pingAccess": version(m), "adminApi": API.rsplit("/", 1)[1], "verified": False, "openApi": OPENAPI,
           "problems": list(problems(m, reqs)), "requests": reqs}
    return {OUTPUT: json.dumps(doc, indent=2) + "\n"}


def render_env(m, services):
    """PingAccess's configuration for environment m."""
    return admin_api_files(m)


def render_notes(m, services):
    """What environment m's PingAccess render leaves to a person (core.notes)."""
    d = m.d
    taken = takeover_notes(m)
    if not rendered(d) and not environment_bound(d) and not taken:
        return ()
    at = version(m) or "the version the environment runs"
    return (
        *((note(AREA, "action", f"`{OUTPUT}`", f"the Admin API paths and fields follow Ping's documentation and are "
                f"unverified for {at}: check the requests against {OPENAPI} on the admin node before applying them",
                ("Fetch the OpenAPI document from the environment's admin node (an Auditor can read it).",
                 "Validate each request's path and body against it; report a difference so the adapter's api.py is "
                 "corrected.")),) if rendered(d) or taken else ()),
        *taken,
        *((note(AREA, "action", "environment-bound objects", "not rendered: create " + "; ".join(
            f"{c.path} " + ", ".join(f"`{rdn_value(e)}`" for e in found) for c, found in environment_bound(d))
            + f" in {m.label} before applying the requests",
            ("Create them from the environment's own key material, CAs, listeners and nodes (the record holds "
             "their settings, never their keys).",
             "The requests name them by ${pingaccess-id:...}: record each one's id in the pipeline before "
             "applying.")),) if environment_bound(d) else ()),
        *(note(AREA, "blocker", f"{c.path} `{rdn_value(e)}`", "its secrets are withheld and no credential role "
               "supplies them: the request carries ${withheld}",
               ("Set paCredentialRole to the secret role that holds them, and bind it in the environment, under an "
                "approved change, and re-render.",), e.dn)
          for c, e in rendered(d) if values(e, "paWithheld") and not one(e, "paCredentialRole")),
        note(AREA, "note", "server profile", "a server profile's data.json is not rendered: the export's envelope is "
             "unverified, and importing it replaces the whole configuration", ("Apply the requests instead.",)),
        note(AREA, "note", "node files", "run.properties, bootstrap.properties, pa.jwk, fips-mode.properties and "
             "the log configuration are not rendered", ("Capture them as config files (`opsdir capture`): their "
                                                        "secrets stay references.",)))
