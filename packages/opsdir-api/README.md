# opsdir-api

The opsdir HTTP API: the operations layer (`opsdir.operations`, what the command line calls) over HTTP, for people who sign in at the estate's identity provider. Every call is a recorded person's and is checked against the record's grants, the same way the command line checks it. It is not an adapter: it registers no `opsdir.adapters` entry point. It provides the `opsdir-api` console script and `opsdir_api.app.create_app(config, connect=..., jwks=...)`.

Dependencies: opsdir, FastAPI, uvicorn, joserfc (token signatures), httpx (fetching the provider's keys) and python-multipart (uploads).

## Configuration

Set in the environment. `opsdir-api` doesn't start while any value is missing or invalid, and lists each problem.

| Variable | Meaning |
|---|---|
| `OPSDIR_DSN` | Connection string of the **API login** (below). `OPSDIR_DB_AUTH` cloud database tokens work as they do for the command line |
| `OPSDIR_API_ISSUER` | The identity provider's issuer, exactly as tokens carry it in `iss` (https; http only to localhost) |
| `OPSDIR_API_AUDIENCE` | The audience the provider puts in `aud` for this API |
| `OPSDIR_API_JWKS_URL` | The provider's JWKS URL (optional). When it isn't set, the URL is the `jwks_uri` of `<issuer>/.well-known/openid-configuration`, and that document must name the same issuer |
| `OPSDIR_API_ALGORITHMS` | Accepted signing algorithms, default `RS256,PS256,ES256`. Only asymmetric algorithms are accepted; `none` and `HS*` are refused |
| `OPSDIR_API_LEEWAY` | Clock skew allowed for `exp`, `nbf` and `iat`, in seconds (default 60, at most 300) |
| `OPSDIR_API_GROUPS_CLAIM` | The claim listing the person's identity provider groups (default `groups`; empty: groups aren't used) |
| `OPSDIR_API_HOST`, `OPSDIR_API_PORT` | Where it listens (default `127.0.0.1:8080`) |
| `OPSDIR_API_FORWARDED_ALLOW_IPS` | Proxies whose `X-Forwarded-*` headers are trusted (default `127.0.0.1`) |

The provider's keys are cached for 5 minutes. When a token names a key id (`kid`) the cache doesn't hold, the keys are fetched again, but at most every 30 seconds, so a key rotation is picked up.

## Tokens and identity

Each `/v1` call sends `Authorization: Bearer <access token>`. A token is accepted only when all of these hold:

- it is signed with an accepted algorithm by the JWKS key its `kid` names
- `iss` is the configured issuer, exactly
- `aud` contains the configured audience
- `exp` is present and hasn't passed, and `nbf` and `iat` (when present) are within the leeway
- `sub` is present

Otherwise the call gets a 401 with a `WWW-Authenticate: Bearer` challenge.

The token's issuer and subject must belong to a recorded person: their `ciamIdpSubject` is `'<issuer> <subject>'`, set by an administrator with `opsdir person LOGIN --idp-subject ...`. If no person has them, the call gets a 403. Nobody is created automatically. This also means a client-credentials token with no person behind it can't do anything, approval included: every call is a person's.

The token's groups claim (`OPSDIR_API_GROUPS_CLAIM`) decides the members of teams mapped to identity provider groups (`opsdir team NAME --idp-group '<issuer> <group id>'`): each value is taken as `'<iss> <value>'`, so configure the provider to emit immutable group IDs, not display names. When the provider says the list is incomplete (Entra ID's group overage: `_claim_names` names the claim, or `hasgroups` is set), the call gets a 403 rather than a guess: emit only the groups assigned to the application. The API client the token was issued to (`azp`, else `client_id`) is recorded in history beside the person.

## The API login

The server connects as one database login, the API login, and only the server holds its credentials. The record's `api-login` setting names that login. The store accepts "acting as person X" (`store.postgres.requesting`) only from the login that setting names. For each request the server:

1. opens a connection
2. finds the person for the token
3. runs everything inside `requesting(person, groups, client)`
4. asks `authorize_command` first, with the action the command line would use (`read` for reads; `propose`, `approve` or `apply` for writes) and its area (an edited entry's environment, otherwise the whole record)
5. closes the connection

Writes are recorded as that person, with the API client and the mapped teams they held, and the store's own checks apply: an approver is never the change's author while approval separation is on, and grants count the mapped teams the token's groups give.

## Endpoints

OpenAPI: `/openapi.json`, interactive docs at `/docs`.

| Method and path | Action | What |
|---|---|---|
| `GET /health` | (none, no token) | `{"status": "ok"}` |
| `GET /v1/browse` | read | The schema's areas, as `{"headers": [...], "rows": [[...]]}` |
| `GET /v1/browse/{area}` | read | An area's kinds and entry counts |
| `GET /v1/browse/{area}/{kind}` | read | The entries of one kind |
| `GET /v1/entries/{dn}` | read | An entry's fields (rows) and its empty optional fields (`empty`) |
| `GET /v1/search?base=&filter=&scope=` | read | Entries an LDAP filter matches (`scope` is base, one or sub; default sub) |
| `GET /v1/reports/{name}?dn=&as_of=` | read | A named report's rows (`as_of` YYYY-MM-DD) |
| `GET /v1/history?dn=` | read | Change history, of one entry or of all |
| `GET /v1/render/{cloud}/{env}?target=&keeper=&kind=&binding=&archive=` | render | A preview of an environment's rendered files (nothing deployed or recorded): `{environment, dn, provider, unbound, notes, files: {path: text}}`. `target=ADAPTER=TARGET[,TARGET]` (repeat) picks targets; one of `keeper` (a party's cn or DN), `kind` (repeat) or `binding` (repeat) scopes it, as `opsdir render`. The manifest names the person who asked. `archive=true` returns the files as a zip (`<cloud>-<env>/...`) |
| `GET /v1/plan/{cloud}/{env}?to=CLOUD/ENV&as_of=&mine=` | plan | A preview of the plan for moving the environment to `to`: `{source, target, as_of, cutover, blockers, actions, accepted, markdown, requests}`, findings as `{area, text, owner}`, the request drafts to external parties as `{path: text}`. `mine=true`: only the caller's teams' blockers and actions |
| `POST /v1/edits` | read / propose / apply | `{dn, set: {attr: [values]}, add: {...}, remove: {attr: [values] or []}, mode, change?, title?}`. `preview` returns `{"changes": [LDIF], "notices": [...]}`; `propose` records the edit as change `change` (needs `title`); `apply` applies it under an approved `change` |
| `POST /v1/changes` | propose | `{id, title, ticket?}`: a new proposed change (201) |
| `POST /v1/changes/{id}/approve` | approve | Approves a change |
| `POST /v1/changes/{id}/reject` | approve | Rejects a change |
| `POST /v1/changes/{id}/apply` | apply | Applies the records an approved proposed change holds |
| `POST /v1/imports` | read / apply | A product's export. Send either multipart (`importer`, `files` with relative paths as file names, `at?`, `change?`, `take`, `keep`) or JSON `{importer, files: {path: text}, at?, change?, take?, keep?}`. Without `change` it's a preview: change records as LDIF, notices, conflicts, scopes. With `change` it applies, deciding conflicts by `take`/`keep` (keys or `all`), and the import run records each file's SHA-256 |
| `POST /v1/onboard/verify` | read | `{sources: [{importer, files: {path: text}}], at?}`: the onboarding verification report (`opsdir onboard verify --json`'s document) |

Errors are `{"detail": "..."}` with the operation's message:

- 400: a malformed request
- 401: no token, or a token that isn't accepted
- 403: no person for the identity, a permission refused, or a missing database privilege
- 404: something that isn't there (an entry, area, kind, change or report)
- 409: something the record's state refuses: a change that already exists or can't move, undecided import conflicts, or the store's own rules
- 503: the identity provider's keys or the database can't be reached

## Running

```
OPSDIR_DSN=... OPSDIR_API_ISSUER=https://idp.example.com/realms/ops OPSDIR_API_AUDIENCE=opsdir-api opsdir-api
```

The server speaks plain HTTP on 127.0.0.1. Run it behind a reverse proxy that terminates TLS (nginx, HAProxy, a cloud load balancer) and forwards to it. Don't expose the port directly. The proxy should also limit request body size, since imports and verification upload exports.

## Not done yet

- syncing IdP groups to teams (team membership is still recorded with `opsdir person --team`)
- an MCP server for AI control
- a web console
