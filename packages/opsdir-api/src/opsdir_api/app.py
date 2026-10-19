"""The HTTP API (create_app): the operations layer for people signed in at the identity provider. Each call presents
a bearer token (tokens.claims_of); its issuer and subject name a recorded person (operations.person_for_subject; no
auto-provisioning), its groups decide the teams mapped to identity provider groups and its azp/client_id is the API
client (tokens.membership_of; an incomplete group list is refused); a connection is opened as the API login and
everything runs inside store.postgres.requesting(person, groups, client), asked first of operations.authorize_command
with the catalog action and Area the command line would use; the connection is closed after. Handlers are plain
functions; the app and its routes are composed here."""
import datetime as dt
import json
import time
from collections.abc import Mapping
from typing import NamedTuple, Optional

import psycopg
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.concurrency import run_in_threadpool

from opsdir import operations as ops
from opsdir.cli import render_scope, render_targets
from opsdir.connectors.onboarding import report_document
from opsdir.core.environment import ENVIRONMENT
from opsdir.domains.governance.authorization import Area
from opsdir.domains.governance.imports import file_evidence
from opsdir.store import postgres as db

from .shapes import (CHANGE_STATUS, EDIT_ACTIONS, WHOLE_RECORD, applied_doc, archive_of, at_of, edit_of, entries_doc,
                     entry_area, environment_of, files_of, import_doc, keys_of, planned_doc, preview_doc,
                     rendered_doc, rows_doc, sources_of, status_of, texts_of)
from .tokens import UNKNOWN_KEY, claims_of, key_source, membership_of

API_VERSION = "1"
NO_PERSON = ("no recorded person for this identity (issuer {issuer}, subject {subject}; an administrator records it: "
             "opsdir person LOGIN --idp-subject ...)")
SCOPES = ("base", "one", "sub")

Wiring = NamedTuple("Wiring", [("config", object), ("connect", object), ("keys", object), ("clock", object)])
Caller = NamedTuple("Caller", [("issuer", str), ("subject", str), ("wiring", Wiring), ("groups", tuple),
                               ("client", Optional[str])])
Caller.__new__.__defaults__ = ((), None)
ImportAsk = NamedTuple("ImportAsk", [("importer", str), ("files", dict), ("skipped", tuple), ("at", object),
                                     ("change", Optional[str]), ("take", tuple), ("keep", tuple)])

BEARER = HTTPBearer(auto_error=False, description="An access token from the identity provider (OPSDIR_API_ISSUER) for "
                                                  "this API's audience (OPSDIR_API_AUDIENCE)")


# ------------------------------------------------------------------ identity
def _quoted(text):
    return text.replace("\\", "").replace('"', "'")


def unauthorized(why, error=None):
    """A 401 refusal with its WWW-Authenticate challenge (RFC 6750, 3)."""
    challenge = f'Bearer error="{error}", error_description="{_quoted(why)}"' if error else "Bearer"
    return HTTPException(401, why, headers={"WWW-Authenticate": challenge})


def _keys(wiring, refresh):
    try:
        return wiring.keys(refresh)
    except ValueError as e:
        raise HTTPException(503, str(e)) from None


def checked_token(wiring, token):
    """Effect (the provider's keys, refetched once for a kid they don't hold: a rotation): tokens.Checked."""
    checked = claims_of(token, _keys(wiring, False), wiring.config, wiring.clock())
    if checked.refusal == UNKNOWN_KEY:
        checked = claims_of(token, _keys(wiring, True), wiring.config, wiring.clock())
    return checked


def caller(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(BEARER)):
    """The dependency every /v1 call has: the accepted bearer token's issuer and subject, its identity provider groups
    and API client; 401 otherwise, 403 when its group list is incomplete (fail closed)."""
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials:
        raise unauthorized("a bearer token is required")
    wiring = request.app.state.wiring
    checked = checked_token(wiring, credentials.credentials)
    if checked.claims is None:
        raise unauthorized(checked.refusal, "invalid_token")
    member = membership_of(checked.claims, wiring.config.groups_claim)
    if member.refusal:
        raise HTTPException(403, member.refusal)
    return Caller(checked.claims["iss"], checked.claims["sub"], wiring, member.groups, member.client)


# ------------------------------------------------------------------ running an operation as the person
def store_refusal(e):
    """The HTTP refusal of a database error: 403 for a missing privilege, 503 when the database isn't reached, 409
    for the record's own rules (approval, separation, types), with the store's message."""
    diag = getattr(e, "diag", None)
    message = ((diag.message_primary if diag else None) or str(e)).strip()
    detail = f" ({diag.message_detail})" if diag and diag.message_detail else ""
    if isinstance(e, (psycopg.OperationalError, psycopg.InterfaceError)) and not getattr(e, "sqlstate", None):
        return HTTPException(503, f"the record's database isn't reachable: {message}")
    return HTTPException(403 if getattr(e, "sqlstate", None) == "42501" else 409,
                         f"REJECTED by the directory: {message}{detail}")


def _open(wiring):
    try:
        return wiring.connect()
    except SystemExit as e:
        raise HTTPException(503, f"the record's database isn't reachable: {e}") from None
    except psycopg.Error as e:
        raise store_refusal(e) from None


def _as_person(conn, who, action, area, work):
    person = ops.person_for_subject(conn, who.issuer, who.subject)
    if not person:
        raise HTTPException(403, NO_PERSON.format(issuer=who.issuer, subject=who.subject))
    with db.requesting(person, who.groups, who.client):
        try:
            ops.authorize_command(conn, action, area)
        except SystemExit as e:
            raise HTTPException(403, str(e)) from None
        try:
            return work(conn)
        except (ValueError, SystemExit) as e:
            raise HTTPException(status_of(str(e)), str(e)) from None


def run(who, action, area, work, as_of=None):
    """Effect: work(conn) on a new connection as the caller's recorded person (inside requesting(person, groups,
    client)), once authorize_command allows the action over the area; dates evaluated as of as_of (today); the
    connection closed after. Refusals as HTTP errors: 403 (no person, not permitted), 400/404/409 (status_of), the
    store's (store_refusal)."""
    conn = _open(who.wiring)
    try:
        db.set_as_of(conn, as_of or dt.date.today())
        return _as_person(conn, who, action, area, work)
    except psycopg.Error as e:
        raise store_refusal(e) from None
    except SystemExit as e:                         # never let an operation's exit stop the server
        raise HTTPException(status_of(str(e)), str(e)) from None
    finally:
        conn.close()


def parsed(parse, *args):
    """parse(*args), its ValueError a 400."""
    try:
        return parse(*args)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None


def _date(text):
    if not text:
        return None
    try:
        return dt.date.fromisoformat(text)
    except ValueError:
        raise ValueError(f"as_of {text}: give YYYY-MM-DD") from None


# ------------------------------------------------------------------ handlers
def health():
    """Whether the server is up (no token, no database)."""
    return {"status": "ok"}


def browse(who: Caller = Depends(caller)):
    """The areas of the record's schema."""
    return run(who, "read", WHOLE_RECORD, lambda c: rows_doc(ops.browse_areas(c)))


def browse_area(area: str, who: Caller = Depends(caller)):
    """The kinds (object classes) of an area with their entry counts."""
    return run(who, "read", WHOLE_RECORD, lambda c: rows_doc(ops.browse_kinds(c, area)))


def browse_kind(area: str, kind: str, who: Caller = Depends(caller)):
    """The entries holding one kind of an area."""
    return run(who, "read", WHOLE_RECORD, lambda c: rows_doc(ops.browse_entries(c, area, kind)))


def entry(dn: str, who: Caller = Depends(caller)):
    """An entry's fields, and the optional fields it may hold that are empty."""
    def work(c):
        rows, empty = ops.browse_entry(c, dn)
        return {**rows_doc(rows), "empty": list(empty)}
    return run(who, "read", WHOLE_RECORD, work)


def search(base: str, filter: str = "(objectClass=*)", scope: str = "sub", who: Caller = Depends(caller)):
    """The entries an LDAP filter matches under base (scope base, one or sub)."""
    if scope not in SCOPES:
        raise HTTPException(400, f"scope {scope}: give base, one or sub")
    return run(who, "read", WHOLE_RECORD, lambda c: entries_doc(ops.search(c, base, filter, scope)))


def report(name: str, dn: Optional[str] = None, as_of: Optional[str] = None, who: Caller = Depends(caller)):
    """A named report's rows (dn for the reports about one entry), dates as of as_of (YYYY-MM-DD; today)."""
    day = parsed(_date, as_of)
    return run(who, "read", WHOLE_RECORD, lambda c: rows_doc(ops.report(c, name, dn, day)), day)


def history(dn: Optional[str] = None, who: Caller = Depends(caller)):
    """The change history, of one entry or of all."""
    return run(who, "read", WHOLE_RECORD, lambda c: rows_doc(ops.history(c, dn)))


def _render_options(targets, keeper, kinds, bindings):
    try:
        return render_targets(targets) or None, render_scope(keeper, kinds, bindings)
    except SystemExit as e:                         # the command line's refusals of the same options
        raise ValueError(str(e).replace("--", "")) from None


def render(cloud: str, env: str, target: list[str] = Query([], description="ADAPTER=TARGET[,TARGET]; repeat"),
           keeper: Optional[str] = Query(None, description="only what a party keeps (its cn or DN)"),
           kind: list[str] = Query([], description="only infrastructure of an object class; repeat"),
           binding: list[str] = Query([], description="only named bindings; repeat"),
           archive: bool = Query(False, description="a zip archive of the files instead of JSON"),
           who: Caller = Depends(caller)):
    """A preview of an environment's rendered files (nothing is deployed or written to the record): every target of
    every adapter, or the targets named; the whole environment, or one keeper's, object class's or bindings'
    infrastructure (one of keeper, kind, binding). The render's manifest names the person who asked. JSON with the
    files as {path: text}, its notes and unbound roles; archive=true: the files as a zip."""
    spec = parsed(environment_of, cloud, env)
    targets, scope = parsed(_render_options, target, keeper, kind, binding)
    r = run(who, "render", Area(spec, scope), lambda c: ops.render(c, spec, targets, scope))
    if not archive:
        return rendered_doc(r)
    folder = r.label.replace("/", "-")
    return Response(archive_of(r.files, folder), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{folder}.zip"'})


def plan(cloud: str, env: str, to: str = Query(..., description="the target environment, CLOUD/ENV"),
         as_of: Optional[str] = None, mine: bool = False, who: Caller = Depends(caller)):
    """A preview of the plan for moving an environment to another (nothing is changed): blockers and actions with
    their owning teams, the plan as markdown and the request drafts to external parties; dates as of as_of
    (YYYY-MM-DD; today); mine: only the blockers and actions of the caller's teams."""
    src = parsed(environment_of, cloud, env)
    dst = parsed(environment_of, *(to.split("/", 1) if "/" in to else (to, "")))
    day = parsed(_date, as_of) or dt.date.today()
    return run(who, "plan", Area(dst, ENVIRONMENT, src), lambda c: planned_doc(ops.plan(c, src, dst, day, mine)),
               day)


EDIT_EXAMPLE = {"dn": "cn=portal,ou=applications,dc=ciam-ops", "set": {"description": ["Customer portal"]},
                "add": {}, "remove": {"seeAlso": []}, "mode": "propose", "change": "CHG-ACME-0042",
                "title": "Describe the portal"}


def edit(body: dict = Body(..., examples=[EDIT_EXAMPLE]), who: Caller = Depends(caller)):
    """One entry's fields edited: set replaces an attribute's values, add adds values, remove takes values out ([]:
    the whole attribute). mode preview (read), propose (records change for someone else to approve: propose) or
    apply (under an approved change: apply)."""
    e = parsed(edit_of, body)

    def work(c):
        p = ops.preview_edit(c, e.dn, e.sets, e.adds, e.removes)
        if e.mode == "preview":
            return {"mode": e.mode, **preview_doc(p)}
        if e.mode == "propose":
            ops.propose_edit(c, p, e.change, e.title)
            return {"mode": e.mode, **preview_doc(p), "change": e.change, "status": "proposed"}
        return {"mode": e.mode, **preview_doc(p), **applied_doc(ops.apply_preview(c, p, e.change))}
    return run(who, EDIT_ACTIONS[e.mode], entry_area(e.dn), work)


def _change_of(body):
    if not isinstance(body, dict) or not all(isinstance(body.get(k), str) and body[k].strip() for k in ("id", "title")):
        raise ValueError("give the change's id and title")
    ticket = body.get("ticket")
    if ticket is not None and not isinstance(ticket, str):
        raise ValueError("ticket: give the ticket's key as text")
    return body["id"].strip(), body["title"].strip(), ticket


def new_change(body: dict = Body(..., examples=[{"id": "CHG-ACME-0042", "title": "Rotate the portal's client"}]),
               who: Caller = Depends(caller)):
    """A proposed change (its author the caller), for someone else to approve."""
    change_id, title, ticket = parsed(_change_of, body)

    def work(c):
        ops.new_change(c, change_id, title, ticket)
        return {"change": change_id, "status": "proposed"}
    return run(who, "propose", WHOLE_RECORD, work)


def _moved(change_id, verb, who):
    status = CHANGE_STATUS[verb]

    def work(c):
        ops.change_status(c, change_id, status)
        held = ops.change_state(c, change_id)
        return {"change": change_id, "status": held.status, "approvals": list(held.approvers), "needed": held.needed}
    return run(who, "approve", WHOLE_RECORD, work)


def approve(change_id: str, who: Caller = Depends(caller)):
    """A change approved by the caller (never its author while approval-separation is on: the store checks)."""
    return _moved(change_id, "approve", who)


def reject(change_id: str, who: Caller = Depends(caller)):
    """A change rejected by the caller."""
    return _moved(change_id, "reject", who)


def apply_change(change_id: str, who: Caller = Depends(caller)):
    """The records an approved proposed change holds, applied; the change marked applied."""
    return run(who, "apply", WHOLE_RECORD, lambda c: applied_doc(ops.apply_proposed(c, change_id)))


def import_ask(importer, files, skipped, at, change, take, keep):
    """The ImportAsk of an import request's fields; ValueError for a malformed one."""
    if not isinstance(importer, str) or not importer.strip():
        raise ValueError("importer: give 'adapter[/importer]'")
    if change is not None and (not isinstance(change, str) or not change.strip()):
        raise ValueError("change: give the approved change's id")
    if not files:
        raise ValueError("give the export's files" + (f" (not UTF-8 text: {', '.join(skipped)})" if skipped else ""))
    return ImportAsk(importer.strip(), files, tuple(skipped), at_of(at), change or None, keys_of("take", take),
                     keys_of("keep", keep))


async def _import_fields(request):
    if request.headers.get("content-type", "").startswith("multipart/form-data"):
        config = request.app.state.wiring.config
        form = await request.form(max_files=config.max_files, max_fields=config.max_files + 16)
        uploads = tuple([(f.filename or "", await f.read()) for f in form.getlist("files") if hasattr(f, "read")])
        files, skipped = texts_of(uploads)
        return (form.get("importer"), files, skipped, form.get("at"), form.get("change") or None,
                form.getlist("take"), form.getlist("keep"))
    try:
        body = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("give a JSON object {importer, files: {relative path: text}, at?, change?, take?, keep?} or "
                         "a multipart form (importer, files, at, change, take, keep)") from None
    if not isinstance(body, dict):
        raise ValueError("give a JSON object {importer, files: {relative path: text}, ...}")
    return (body.get("importer"), files_of("files", body.get("files")), (), body.get("at"), body.get("change"),
            body.get("take"), body.get("keep"))


def _imported(ask):
    def work(c):
        plan = ops.preview_import(c, ask.importer, ask.files, ask.at)
        doc = import_doc(plan, ask.skipped)
        if not ask.change:
            return doc
        r = ops.apply_import(c, plan, ask.change, ask.take, ask.keep, file_evidence(ask.files))
        return {**doc, **applied_doc(r)}
    return work


IMPORT_BODY = {"requestBody": {"required": True, "content": {
    "multipart/form-data": {"schema": {"type": "object", "required": ["importer", "files"], "properties": {
        "importer": {"type": "string", "description": "adapter[/importer]"},
        "files": {"type": "array", "items": {"type": "string", "format": "binary"},
                  "description": "the export's files, each named by its path relative to the export's root"},
        "at": {"type": "string", "description": "when the export was taken, YYYYMMDDhhmmssZ (default now)"},
        "change": {"type": "string", "description": "apply under this approved change (preview without)"},
        "take": {"type": "array", "items": {"type": "string"}, "description": "conflicts: take the live value"},
        "keep": {"type": "array", "items": {"type": "string"}, "description": "conflicts: keep the record's"}}}},
    "application/json": {"schema": {"type": "object", "required": ["importer", "files"], "properties": {
        "importer": {"type": "string"},
        "files": {"type": "object", "additionalProperties": {"type": "string"}},
        "at": {"type": "string"}, "change": {"type": "string"},
        "take": {"type": "array", "items": {"type": "string"}},
        "keep": {"type": "array", "items": {"type": "string"}}}}}}}}


async def imports(request: Request, who: Caller = Depends(caller)):
    """A product's export imported: previewed (read), or with change applied under that approved change (apply), each
    conflict decided by take or keep (keys, or 'all'); the import run records each file's SHA-256."""
    try:
        ask = import_ask(*await _import_fields(request))
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    return await run_in_threadpool(run, who, "apply" if ask.change else "read", WHOLE_RECORD, _imported(ask))


def verify_onboarding(body: dict = Body(..., examples=[{"sources": [{"importer": "pingfederate", "files": {
        "data.json": "{...}"}}], "at": "20261018120000Z"}]), who: Caller = Depends(caller)):
    """Onboarding verification of the record against the operator's original exports: every environment rendered
    and read back; nothing written. The report document (status pass or fail, differences, diffs, notices)."""
    sources = parsed(sources_of, body)
    at = parsed(at_of, body.get("at"))
    return run(who, "read", WHOLE_RECORD, lambda c: report_document(ops.onboard_verify(c, sources, at)))


# ------------------------------------------------------------------ composition
ROUTES = (("GET", "/v1/browse", browse, {}),
          ("GET", "/v1/browse/{area}", browse_area, {}),
          ("GET", "/v1/browse/{area}/{kind}", browse_kind, {}),
          ("GET", "/v1/entries/{dn:path}", entry, {}),
          ("GET", "/v1/search", search, {}),
          ("GET", "/v1/reports/{name}", report, {}),
          ("GET", "/v1/history", history, {}),
          ("GET", "/v1/render/{cloud}/{env}", render, {"responses": {200: {"content": {"application/zip": {}}}}}),
          ("GET", "/v1/plan/{cloud}/{env}", plan, {}),
          ("POST", "/v1/edits", edit, {}),
          ("POST", "/v1/changes", new_change, {"status_code": 201}),
          ("POST", "/v1/changes/{change_id}/approve", approve, {}),
          ("POST", "/v1/changes/{change_id}/reject", reject, {}),
          ("POST", "/v1/changes/{change_id}/apply", apply_change, {}),
          ("POST", "/v1/imports", imports, {"openapi_extra": IMPORT_BODY}),
          ("POST", "/v1/onboard/verify", verify_onboarding, {}))


TOO_LARGE = "the request is larger than this API accepts ({limit} bytes: OPSDIR_API_MAX_UPLOAD_MB)"


def body_limit(app, limit):
    """ASGI middleware (effect at the edge): a request whose body is over limit bytes gets a 413, refused by its
    Content-Length before anything is read, else as soon as the bytes received pass the limit (a chunked upload)."""
    async def refuse(send):
        body = json.dumps({"detail": TOO_LARGE.format(limit=limit)}).encode()
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def guarded(scope, receive, send):
        if scope["type"] != "http":
            return await app(scope, receive, send)
        declared = dict(scope.get("headers") or ()).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            return await refuse(send)
        seen = [0]

        async def counted():
            message = await receive()
            if message["type"] == "http.request":
                seen[0] += len(message.get("body", b""))
                if seen[0] > limit:
                    raise HTTPException(413, TOO_LARGE.format(limit=limit))
            return message
        return await app(scope, counted, send)
    return guarded


def database_connection(config):
    """Effect: a connection to the record as the API login (OPSDIR_DSN), signing in with a cloud database token when
    OPSDIR_DB_AUTH names one, as the command line does."""
    from opsdir.cli import db_password
    return db.connect(config.dsn, db_password(config.dsn))


def _key_source(config, jwks):
    if jwks is None:
        return key_source(config)
    if isinstance(jwks, Mapping):
        return lambda refresh=False: jwks
    return jwks


def create_app(config, connect=None, jwks=None, clock=time.time):
    """The API's FastAPI app. config: config.Config; connect: () -> a connection as the API login (default
    database_connection); jwks: the provider's keys, a JWKS document or keys(refresh) -> one (default fetched and kept
    by tokens.key_source); clock: () -> seconds since the epoch, for token times."""
    app = FastAPI(title="opsdir API", version=API_VERSION,
                  description="The opsdir operations for people signed in at the identity provider: every call is a "
                              "recorded person's, checked against the record's grants.")
    app.state.wiring = Wiring(config, connect or (lambda: database_connection(config)), _key_source(config, jwks),
                              clock)
    app.add_middleware(body_limit, limit=config.max_upload)
    app.add_api_route("/health", health, methods=["GET"])
    for method, path, handler, extra in ROUTES:
        app.add_api_route(path, handler, methods=[method], **extra)
    return app
