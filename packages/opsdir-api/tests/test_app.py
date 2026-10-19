"""The HTTP API over a faked operations layer and connection: no token or a bad one is a 401 with its Bearer
challenge; an identity no person records is a 403; every call runs inside requesting(person), asks authorize_command
with the command line's action and Area first (a refusal is a 403 with its message), closes its connection, and maps
the operations' results to JSON (rows, LDIF previews, import plans, the verification document) and their refusals to
400/404/409."""
import contextlib
import datetime as dt
import io
import zipfile
from types import SimpleNamespace
from typing import NamedTuple

import pytest
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import RSAKey

from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.governance.authorization import Area
from opsdir.domains.governance.imports import file_evidence
from opsdir_api import app as api
from opsdir_api.config import Config

ISSUER, AUDIENCE, NOW = "https://idp.example.com/realms/ops", "opsdir-api", 1_800_000_000
KEY = RSAKey.generate_key(2048, parameters={"kid": "k1"})
JWKS = {"keys": [KEY.as_dict(private=False)]}
CONFIG = Config("postgresql://api@db/opsdir", ISSUER, AUDIENCE, None, ("RS256",), 60)
PEOPLE = {(ISSUER, "sub-alice"): "alice", (ISSUER, "sub-bob"): "bob"}
ENV_DN = "cn=idp-tls,ou=certificates,env=prod,cloud=aws,ou=environments,dc=ciam-ops"
RECORD = LdifRecord("cn=portal,ou=applications,dc=ciam-ops", "modify", {}, (("replace", "description", ("Portal",)),))

Rows = NamedTuple("Rows", [("headers", tuple), ("rows", tuple)])
Preview = NamedTuple("Preview", [("name", str), ("changes", tuple), ("notices", tuple)])
Applied = NamedTuple("Applied", [("change_id", str), ("lines", tuple)])
Conflict = NamedTuple("Conflict", [("key", str), ("dn", str), ("attr", str), ("held", tuple), ("live", tuple)])
Plan = NamedTuple("Plan", [("importer", str), ("changes", tuple), ("notices", tuple), ("conflicts", tuple),
                           ("scopes", tuple), ("at", object)])
Rendered = NamedTuple("Rendered", [("label", str), ("dn", str), ("provider", str), ("files", dict),
                                   ("unbound", tuple), ("notes", tuple)])
Note = NamedTuple("Note", [("severity", str), ("subject", str), ("text", str)])
Planned = NamedTuple("Planned", [("plan", object), ("markdown", str), ("drafts", dict)])


def rendered(spec, targets, scope):
    if spec.startswith("nowhere/"):
        raise SystemExit("no such environment: env=prod,cloud=nowhere,ou=environments,dc=ciam-ops")
    return Rendered(spec, f"env=prod,cloud={spec.split('/')[0]}", "azure",
                    {"terraform/main.tf": "resource {}\n", "MANIFEST.json": "{}"}, ("acl-ds",),
                    (Note("blocker", "acl-ds", "unbound"),))


def planned(src, dst, as_of, mine):
    p = SimpleNamespace(src=SimpleNamespace(label=src), dst=SimpleNamespace(label=dst), as_of=as_of,
                        cutover=dt.date(2027, 1, 15), blockers=(("Binding", "acl-ds unbound", "platform"),),
                        actions=(("Identity", "give the partner its secret", "partners", "fix-1"),), accepted=())
    return Planned(p, "# Plan\n", {"requests/partners.md": "Dear partners"})


def token(sub="sub-alice", **claims):
    body = {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "iat": NOW, "exp": NOW + 300, **claims}
    return jwt.encode({"alg": "RS256", "kid": "k1"}, body, KEY, algorithms=["RS256"])


def bearer(sub="sub-alice", **claims):
    return {"Authorization": f"Bearer {token(sub, **claims)}"}


@pytest.fixture
def world(monkeypatch):
    """The fakes: calls recorded as (operation, args, the person in effect); refused: what authorize refuses."""
    calls, state = [], {"as": None, "refuse": None, "opened": 0, "closed": 0}

    @contextlib.contextmanager
    def requesting(login, groups=(), client=None):
        calls.append(("requesting", (login,), None))
        state["as"], state["membership"] = login, (groups, client)
        try:
            yield
        finally:
            state["as"] = None

    def recorded(name, result=None):
        def operation(conn, *args):
            calls.append((name, args, state["as"]))
            return result(*args) if callable(result) else result
        return operation

    def authorize_command(conn, action, area, claimed=None):
        calls.append(("authorize_command", (action, area), state["as"]))
        if state["refuse"]:
            raise SystemExit(state["refuse"])

    def browse_entry(conn, dn):
        calls.append(("browse_entry", (dn,), state["as"]))
        if dn != RECORD.dn:
            raise ValueError(f"no entry {dn}")
        return Rows(("field", "value"), (("description", "Portal"),)), ("seeAlso",)

    def apply_import(conn, plan, change_id, take=(), keep=(), evidence=None):
        calls.append(("apply_import", (plan, change_id, take, keep, evidence), state["as"]))
        if plan.conflicts and not (take or keep):
            raise ValueError("1 conflict(s) undecided: take the live value or keep the record's for each")
        return Applied(change_id, ("modify cn=x", "add cn=run"))

    def change_status(conn, change_id, status):
        calls.append(("change_status", (change_id, status), state["as"]))
        state["moved"] = status
        if change_id == "CHG-ACME-9999":
            raise ValueError(f"no change {change_id}")
        return Applied(change_id, (f"modify cn={change_id}",))

    conflicts = (Conflict("k1", "cn=x", "mail", ("a@x",), ("b@x",)),)
    fake_ops = SimpleNamespace(
        person_for_subject=lambda conn, issuer, subject: PEOPLE.get((issuer, subject)),
        authorize_command=authorize_command,
        browse_areas=recorded("browse_areas", Rows(("area", "kinds"), (("pki", 3), ("federation", 5)))),
        browse_kinds=recorded("browse_kinds", Rows(("kind", "entries"), (("ciamCertificate", 2),))),
        browse_entries=recorded("browse_entries", Rows(("dn",), ((ENV_DN,),))),
        browse_entry=browse_entry,
        search=recorded("search", ()),
        report=recorded("report", Rows(("name", "expires"), (("idp-tls", dt.date(2027, 1, 1)),))),
        history=recorded("history", Rows(("when", "change"), ())),
        preview_edit=recorded("preview_edit", Preview("edit", (RECORD,), ())),
        propose_edit=recorded("propose_edit", Applied("CHG-ACME-0042", ("add cn=CHG-ACME-0042",))),
        apply_preview=recorded("apply_preview", lambda preview, change: Applied(change, ("modify cn=portal",))),
        new_change=recorded("new_change", Applied("CHG-ACME-0042", ())),
        change_status=change_status,
        change_state=lambda conn, change_id: SimpleNamespace(
            status=state.get("moved", "approved"), approvers=("bob",), needed=state.get("needed", 1)),
        apply_proposed=recorded("apply_proposed", lambda change: Applied(change, ("modify cn=portal",))),
        preview_import=recorded("preview_import", lambda spec, files, at: Plan(
            spec, (RECORD,), ("withheld: secret",), conflicts if "conflict.json" in files else (), ("cn=pf",), at)),
        apply_import=apply_import,
        render=recorded("render", rendered),
        plan=recorded("plan", planned),
        onboard_verify=recorded("onboard_verify", lambda sources, at: SimpleNamespace(status="pass", n=len(sources))))
    fake_db = SimpleNamespace(requesting=requesting, set_as_of=lambda conn, day: calls.append(("set_as_of", (day,),
                                                                                                None)))
    monkeypatch.setattr(api, "ops", fake_ops)
    monkeypatch.setattr(api, "db", fake_db)
    monkeypatch.setattr(api, "report_document", lambda v: {"status": v.status, "sources": v.n})

    def connect():
        state["opened"] += 1
        return SimpleNamespace(close=lambda: state.__setitem__("closed", state["closed"] + 1))
    client = TestClient(api.create_app(CONFIG, connect=connect, jwks=JWKS, clock=lambda: NOW))
    return SimpleNamespace(client=client, calls=calls, state=state)


def named(calls, name):
    return [c for c in calls if c[0] == name]


# ------------------------------------------------------------------ authentication and identity
def test_health_needs_no_token(world):
    assert world.client.get("/health").json() == {"status": "ok"}
    assert world.state["opened"] == 0


def test_no_token_is_401_with_a_bearer_challenge(world):
    r = world.client.get("/v1/browse")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert world.state["opened"] == 0


@pytest.mark.parametrize("headers", [{"Authorization": "Bearer not-a-jwt"},
                                     {"Authorization": "Basic YWxpY2U6cHc="}])
def test_a_bad_token_is_401(world, headers):
    r = world.client.get("/v1/browse", headers=headers)
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")


def test_an_expired_or_foreign_token_is_401_naming_why(world):
    r = world.client.get("/v1/browse", headers=bearer(exp=NOW - 120))
    assert r.status_code == 401 and 'error="invalid_token"' in r.headers["www-authenticate"]
    assert "expired" in r.json()["detail"]
    r = world.client.get("/v1/browse", headers=bearer(iss="https://other.example.com"))
    assert r.status_code == 401 and "issuer" in r.json()["detail"]


def test_an_identity_no_person_records_is_403(world):
    r = world.client.get("/v1/browse", headers=bearer("sub-service-client"))
    assert r.status_code == 403 and "no recorded person for this identity" in r.json()["detail"]
    assert "--idp-subject" in r.json()["detail"]
    assert not named(world.calls, "requesting") and not named(world.calls, "browse_areas")
    assert world.state["closed"] == world.state["opened"] == 1


def test_an_unknown_kid_refetches_the_keys_once():
    fetched = []
    other = RSAKey.generate_key(2048, parameters={"kid": "k2"})
    app = api.create_app(CONFIG, connect=lambda: None, clock=lambda: NOW,
                         jwks=lambda refresh=False: fetched.append(refresh) or JWKS)
    signed = jwt.encode({"alg": "RS256", "kid": "k2"}, {"iss": ISSUER, "aud": AUDIENCE, "sub": "s", "exp": NOW + 60},
                        other, algorithms=["RS256"])
    r = TestClient(app).get("/v1/browse", headers={"Authorization": f"Bearer {signed}"})
    assert r.status_code == 401 and fetched == [False, True]


def test_unreachable_keys_are_503():
    def keys(refresh=False):
        raise ValueError("the identity provider's keys can't be fetched: timed out")
    r = TestClient(api.create_app(CONFIG, connect=lambda: None, jwks=keys, clock=lambda: NOW)).get(
        "/v1/browse", headers=bearer())
    assert r.status_code == 503 and "can't be fetched" in r.json()["detail"]


# ------------------------------------------------------------------ reading
def test_browse_returns_rows_read_as_the_person(world):
    r = world.client.get("/v1/browse", headers=bearer())
    assert r.status_code == 200 and r.json() == {"headers": ["area", "kinds"], "rows": [["pki", 3], ["federation", 5]]}
    assert named(world.calls, "authorize_command") == [("authorize_command", ("read", Area("")), "alice")]
    assert named(world.calls, "browse_areas") == [("browse_areas", (), "alice")]
    assert world.state["opened"] == world.state["closed"] == 1


def test_browse_kinds_entries_and_an_entry(world):
    assert world.client.get("/v1/browse/pki", headers=bearer()).json()["rows"] == [["ciamCertificate", 2]]
    assert world.client.get("/v1/browse/pki/ciamCertificate", headers=bearer()).json()["rows"] == [[ENV_DN]]
    assert named(world.calls, "browse_entries")[0][1] == ("pki", "ciamCertificate")
    r = world.client.get(f"/v1/entries/{RECORD.dn}", headers=bearer())
    assert r.json() == {"headers": ["field", "value"], "rows": [["description", "Portal"]], "empty": ["seeAlso"]}
    r = world.client.get("/v1/entries/cn=nothing,dc=ciam-ops", headers=bearer())
    assert r.status_code == 404 and r.json()["detail"] == "no entry cn=nothing,dc=ciam-ops"


def test_search_report_and_history(world):
    assert world.client.get("/v1/search", params={"base": "dc=ciam-ops", "filter": "(cn=x)"},
                            headers=bearer()).json() == {"entries": []}
    assert named(world.calls, "search")[0][1] == ("dc=ciam-ops", "(cn=x)", "sub")
    assert world.client.get("/v1/search", params={"base": "dc=ciam-ops", "scope": "tree"},
                            headers=bearer()).status_code == 400
    r = world.client.get("/v1/reports/expiring", params={"as_of": "2026-10-18"}, headers=bearer())
    assert r.json() == {"headers": ["name", "expires"], "rows": [["idp-tls", "2027-01-01"]]}
    assert named(world.calls, "report")[0][1] == ("expiring", None, dt.date(2026, 10, 18))
    assert ("set_as_of", (dt.date(2026, 10, 18),), None) in world.calls
    assert world.client.get("/v1/reports/expiring", params={"as_of": "18/10"}, headers=bearer()).status_code == 400
    assert world.client.get("/v1/history", params={"dn": RECORD.dn}, headers=bearer()).json()["rows"] == []
    assert named(world.calls, "history")[0][1] == (RECORD.dn,)


def test_authorize_refusal_is_403_with_its_message(world):
    world.state["refuse"] = "alice may not read over the whole record"
    r = world.client.get("/v1/browse", headers=bearer())
    assert r.status_code == 403 and r.json()["detail"] == "alice may not read over the whole record"
    assert not named(world.calls, "browse_areas") and world.state["closed"] == 1


# ------------------------------------------------------------------ edits and changes
def test_an_edit_preview_is_a_read_returning_ldif(world):
    r = world.client.post("/v1/edits", headers=bearer(), json={"dn": RECORD.dn, "set": {"description": ["Portal"]}})
    assert r.status_code == 200
    assert r.json() == {"mode": "preview", "notices": [], "changes": [
        "dn: cn=portal,ou=applications,dc=ciam-ops\nchangetype: modify\nreplace: description\n"
        "description: Portal\n-\n"]}
    assert named(world.calls, "authorize_command")[0][1][0] == "read"
    assert named(world.calls, "preview_edit")[0][1] == (RECORD.dn, (("description", "Portal"),), (), ())


def test_an_edit_proposed_runs_as_the_person_with_action_propose(world):
    body = {"dn": ENV_DN, "set": {"description": ["TLS"]}, "add": {"seeAlso": ["cn=a", "cn=b"]},
            "remove": {"mail": [], "cn": ["old"]}, "mode": "propose", "change": "CHG-ACME-0042", "title": "Describe"}
    r = world.client.post("/v1/edits", headers=bearer(), json=body)
    assert r.status_code == 200 and r.json()["status"] == "proposed" and r.json()["change"] == "CHG-ACME-0042"
    assert named(world.calls, "requesting") == [("requesting", ("alice",), None)]
    assert named(world.calls, "authorize_command") == [("authorize_command", ("propose", Area("aws/prod")), "alice")]
    edit = named(world.calls, "preview_edit")[0]
    assert edit[1] == (ENV_DN, (("description", "TLS"),), (("seeAlso", "cn=a"), ("seeAlso", "cn=b")),
                       (("mail", None), ("cn", "old"))) and edit[2] == "alice"
    proposed = named(world.calls, "propose_edit")[0]
    assert proposed[1][1:] == ("CHG-ACME-0042", "Describe") and proposed[2] == "alice"


def test_an_edit_applied_is_action_apply(world):
    r = world.client.post("/v1/edits", headers=bearer(), json={"dn": RECORD.dn, "set": {"description": ["Portal"]},
                                                               "mode": "apply", "change": "CHG-ACME-0042"})
    assert r.json()["applied"] == ["modify cn=portal"] and r.json()["change"] == "CHG-ACME-0042"
    assert named(world.calls, "authorize_command")[0][1] == ("apply", Area(""))
    assert named(world.calls, "apply_preview")[0][2] == "alice"


@pytest.mark.parametrize("body, problem", [
    ({"set": {"description": ["x"]}}, "dn"),
    ({"dn": RECORD.dn, "mode": "propose", "change": "CHG-ACME-1"}, "title"),
    ({"dn": RECORD.dn, "mode": "apply"}, "needs change"),
    ({"dn": RECORD.dn, "mode": "delete"}, "preview, propose or apply"),
    ({"dn": RECORD.dn, "set": {"description": "x"}}, "list of non-empty strings"),
    ({"dn": RECORD.dn, "set": {"description": []}}, "at least one value")])
def test_malformed_edits_are_400(world, body, problem):
    r = world.client.post("/v1/edits", headers=bearer(), json=body)
    assert r.status_code == 400 and problem in r.json()["detail"]
    assert world.state["opened"] == 0


def test_changes_new_approve_reject_apply(world):
    r = world.client.post("/v1/changes", headers=bearer(), json={"id": "CHG-ACME-0042", "title": "Rotate"})
    assert r.status_code == 201 and r.json() == {"change": "CHG-ACME-0042", "status": "proposed"}
    assert named(world.calls, "new_change")[0] == ("new_change", ("CHG-ACME-0042", "Rotate", None), "alice")
    r = world.client.post("/v1/changes/CHG-ACME-0042/approve", headers=bearer("sub-bob"))
    assert r.json() == {"change": "CHG-ACME-0042", "status": "approved", "approvals": ["bob"], "needed": 1}
    assert named(world.calls, "change_status")[0] == ("change_status", ("CHG-ACME-0042", "approved"), "bob")
    assert world.client.post("/v1/changes/CHG-ACME-0043/reject", headers=bearer("sub-bob")).json()["status"] == \
        "rejected"
    r = world.client.post("/v1/changes/CHG-ACME-0042/apply", headers=bearer())
    assert r.json() == {"change": "CHG-ACME-0042", "applied": ["modify cn=portal"]}
    actions = [c[1][0] for c in named(world.calls, "authorize_command")]
    assert actions == ["propose", "approve", "approve", "apply"]
    assert [c[1][0] for c in named(world.calls, "requesting")] == ["alice", "bob", "bob", "alice"]


def test_change_refusals_map_to_404_and_400(world):
    r = world.client.post("/v1/changes/CHG-ACME-9999/approve", headers=bearer("sub-bob"))
    assert r.status_code == 404 and r.json()["detail"] == "no change CHG-ACME-9999"
    assert world.client.post("/v1/changes", headers=bearer(), json={"id": "CHG-ACME-1"}).status_code == 400


# ------------------------------------------------------------------ imports and verification
def test_an_import_upload_previewed(world):
    files = [("files", ("export/data.json", b'{"a": 1}')), ("files", ("export/old.bin", b"\xff\xfe"))]
    r = world.client.post("/v1/imports", headers=bearer(), files=files,
                          data={"importer": "pingfederate", "at": "20261018120000Z"})
    assert r.status_code == 200, r.text
    doc = r.json()
    assert doc["importer"] == "pingfederate" and doc["skipped"] == ["export/old.bin"]
    assert doc["notices"] == ["withheld: secret"] and doc["scopes"] == ["cn=pf"] and len(doc["changes"]) == 1
    previewed = named(world.calls, "preview_import")[0]
    assert previewed[1] == ("pingfederate", {"export/data.json": '{"a": 1}'},
                            dt.datetime(2026, 10, 18, 12, tzinfo=dt.timezone.utc)) and previewed[2] == "alice"
    assert named(world.calls, "authorize_command")[0][1] == ("read", Area(""))
    assert not named(world.calls, "apply_import")


def test_an_import_applied_under_a_change_records_file_evidence(world):
    files = {"conflict.json": "{}", "data.json": "[]"}
    r = world.client.post("/v1/imports", headers=bearer(), json={"importer": "pingfederate", "files": files,
                                                                 "change": "CHG-ACME-0042"})
    assert r.status_code == 409 and "undecided" in r.json()["detail"]
    r = world.client.post("/v1/imports", headers=bearer(), json={"importer": "pingfederate", "files": files,
                                                                 "change": "CHG-ACME-0042", "take": ["k1"]})
    assert r.status_code == 200 and r.json()["applied"] == ["modify cn=x", "add cn=run"]
    assert r.json()["conflicts"] == [{"key": "k1", "dn": "cn=x", "attribute": "mail", "record": ["a@x"],
                                      "live": ["b@x"]}]
    applied = named(world.calls, "apply_import")[-1]
    assert applied[1][1:] == ("CHG-ACME-0042", ("k1",), (), file_evidence(files)) and applied[2] == "alice"
    assert named(world.calls, "authorize_command")[-1][1] == ("apply", Area(""))


def test_an_import_multipart_apply_takes_keys(world):
    r = world.client.post("/v1/imports", headers=bearer(), files=[("files", ("conflict.json", b"{}"))],
                          data={"importer": "pingfederate", "change": "CHG-ACME-0042", "keep": ["all"]})
    assert r.status_code == 200 and named(world.calls, "apply_import")[0][1][2:4] == ((), ("all",))


@pytest.mark.parametrize("kwargs, problem", [
    ({"json": {"files": {"a": "b"}}}, "importer"),
    ({"json": {"importer": "pingfederate", "files": {}}}, "files"),
    ({"json": {"importer": "pingfederate", "files": {"a": "b"}, "at": "yesterday"}}, "YYYYMMDDhhmmssZ"),
    ({"content": b"not json", "headers": {"content-type": "application/json"}}, "JSON object"),
    ({"files": [("files", ("x.bin", b"\xff"))], "data": {"importer": "pingfederate"}}, "not UTF-8 text: x.bin")])
def test_malformed_imports_are_400(world, kwargs, problem):
    headers = {**bearer(), **kwargs.pop("headers", {})}
    r = world.client.post("/v1/imports", headers=headers, **kwargs)
    assert r.status_code == 400 and problem in r.json()["detail"]


def test_verify_returns_the_report_document(world):
    body = {"sources": [{"importer": "pingfederate", "files": {"data.json": "{}"}},
                        {"importer": "pingam/config", "files": {"a.json": "{}"}}], "at": "20261018120000Z"}
    r = world.client.post("/v1/onboard/verify", headers=bearer(), json=body)
    assert r.status_code == 200 and r.json() == {"status": "pass", "sources": 2}
    verified = named(world.calls, "onboard_verify")[0]
    assert verified[1][0] == (("pingfederate", {"data.json": "{}"}), ("pingam/config", {"a.json": "{}"}))
    assert named(world.calls, "authorize_command")[0][1] == ("read", Area(""))
    assert world.client.post("/v1/onboard/verify", headers=bearer(), json={"sources": []}).status_code == 400


def test_the_openapi_document_lists_the_endpoints(world):
    paths = world.client.get("/openapi.json").json()["paths"]
    assert {"/v1/browse", "/v1/entries/{dn}", "/v1/edits", "/v1/changes/{change_id}/approve", "/v1/imports",
            "/v1/onboard/verify"} <= set(paths)
    assert "multipart/form-data" in paths["/v1/imports"]["post"]["requestBody"]["content"]


def test_a_render_preview_as_json_or_a_zip(world):
    client, calls, state = world.client, world.calls, world.state
    r = client.get("/v1/render/target/prod", params={"target": "azure=terraform", "keeper": "platform"},
                   headers=bearer())
    assert r.status_code == 200, r.text
    doc = r.json()
    assert (doc["environment"], doc["unbound"], sorted(doc["files"]), doc["notes"][0]["severity"]) == (
        "target/prod", ["acl-ds"], ["MANIFEST.json", "terraform/main.tf"], "blocker")
    authorized = next(c for c in calls if c[0] == "authorize_command")
    assert authorized[1][0] == "render" and authorized[1][1].environment == "target/prod" and authorized[2] == "alice"
    args = next(c for c in calls if c[0] == "render")[1]
    assert args[0] == "target/prod" and args[1] == {"azure": ("terraform",)} and args[2].kind == "keeper"
    z = client.get("/v1/render/target/prod", params={"archive": "true"}, headers=bearer())
    assert z.headers["content-type"] == "application/zip" and 'filename="target-prod.zip"' in z.headers[
        "content-disposition"]
    with zipfile.ZipFile(io.BytesIO(z.content)) as archive:
        assert archive.namelist() == ["target-prod/MANIFEST.json", "target-prod/terraform/main.tf"]
    assert client.get("/v1/render/target/prod", params={"archive": "true"}, headers=bearer()).content == z.content


@pytest.mark.parametrize("path, params, status, message", [
    ("/v1/render/nowhere/prod", {}, 404, "no such environment"),
    ("/v1/render/tar get/prod", {}, 400, "give a cloud and an environment name"),
    ("/v1/render/target/prod", {"keeper": "platform", "kind": "ciamNetwork"}, 400, "render takes one of keeper"),
    ("/v1/render/target/prod", {"target": "azure"}, 400, "target takes ADAPTER=TARGET"),
    ("/v1/plan/source/prod", {"to": "target"}, 400, "give a cloud and an environment name"),
    ("/v1/plan/source/prod", {"to": "target/prod", "as_of": "tomorrow"}, 400, "give YYYY-MM-DD")])
def test_render_and_plan_refusals(world, path, params, status, message):
    client, calls, state = world.client, world.calls, world.state
    r = client.get(path, params=params, headers=bearer())
    assert r.status_code == status and message in r.text


def test_a_plan_preview(world):
    client, calls, state = world.client, world.calls, world.state
    r = client.get("/v1/plan/source/prod", params={"to": "target/prod", "as_of": "2026-09-23", "mine": "true"},
                   headers=bearer())
    assert r.status_code == 200, r.text
    assert r.json() == {"source": "source/prod", "target": "target/prod", "as_of": "2026-09-23",
                        "cutover": "2027-01-15", "accepted": 0, "markdown": "# Plan\n",
                        "blockers": [{"area": "Binding", "text": "acl-ds unbound", "owner": "platform"}],
                        "actions": [{"area": "Identity", "text": "give the partner its secret", "owner": "partners"}],
                        "requests": {"requests/partners.md": "Dear partners"}}
    authorized = next(c for c in calls if c[0] == "authorize_command")[1]
    assert authorized[0] == "plan" and (authorized[1].environment, authorized[1].source) == ("target/prod",
                                                                                             "source/prod")
    assert next(c for c in calls if c[0] == "plan")[1] == ("source/prod", "target/prod", dt.date(2026, 9, 23), True)


def test_render_and_plan_need_their_permission(world):
    client, calls, state = world.client, world.calls, world.state
    state["refuse"] = "alice may not render target/prod: no grant gives them render there"
    assert client.get("/v1/render/target/prod", headers=bearer()).status_code == 403
    assert client.get("/v1/plan/source/prod", params={"to": "target/prod"}, headers=bearer()).status_code == 403


def test_a_request_over_the_upload_limit_is_refused(monkeypatch):
    small = CONFIG._replace(max_upload=1000, max_files=2)
    client = TestClient(api.create_app(small, connect=lambda: None, jwks=JWKS, clock=lambda: NOW))
    big = client.post("/v1/imports", headers=bearer(), files=[("files", ("a.json", b"x" * 2000))],
                      data={"importer": "pingfederate"})
    assert big.status_code == 413 and "OPSDIR_API_MAX_UPLOAD_MB" in big.text
    edits = client.post("/v1/edits", headers=bearer(), json={"dn": "cn=x", "set": {"description": ["y" * 2000]}})
    assert edits.status_code == 413
    many = client.post("/v1/imports", headers=bearer(), data={"importer": "pingfederate"},
                       files=[("files", (f"{i}.json", b"{}")) for i in range(3)])
    assert many.status_code == 400 and "Too many files" in many.text
    assert client.get("/health").status_code == 200


def test_a_chunked_body_is_cut_off_at_the_limit():
    import asyncio

    async def app(scope, receive, send):
        while (await receive()).get("more_body"):
            pass
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"read"})

    def call(chunks):
        sent, queue = [], [{"type": "http.request", "body": c, "more_body": i < len(chunks) - 1}
                           for i, c in enumerate(chunks)]

        async def receive():
            return queue.pop(0)

        async def send(message):
            sent.append(message)
        try:
            asyncio.run(api.body_limit(app, 10)({"type": "http", "headers": []}, receive, send))
        except api.HTTPException as e:
            return e.status_code
        return sent[0]["status"]
    assert call([b"12345", b"12345"]) == 200
    assert call([b"12345", b"123456"]) == 413
