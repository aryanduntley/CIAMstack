# Running the HTTP API

The HTTP API (`opsdir-api`, in `packages/opsdir-api`) is how people reach the record in a company deployment. They sign in at the company's identity provider, and every call is checked against the record's grants as the command line checks it. The command line stays the server administrator's tool for setup, upgrades and break-glass work.

This guide covers running the API on the CIAMstack server. The record's database must already be set up as in [Running the record's database in production](RECORD-DATABASE.md). Endpoints, configuration variables and token rules are listed in the [package README](../packages/opsdir-api/README.md).

## How it fits together

```
people (browser, scripts, later the console and MCP)
   │  HTTPS, Authorization: Bearer <access token from the company IdP>
   ▼
reverse proxy (TLS)  ──►  opsdir-api on 127.0.0.1:8080  ──►  record database (TLS, as opsdir_api)
                               │
                               └─ fetches the IdP's signing keys (HTTPS, JWKS)
```

- The API listens on the server's loopback address in plain HTTP. A reverse proxy on the same host terminates TLS in front of it.
- It connects to the database as one login of its own, `opsdir_api`, and tells the database which recorded person each write is for. The database believes that only from the login the record's `api-login` setting names. Author, approver, approval separation, grants and history then apply to the person.
- Only the API server holds `opsdir_api`'s credentials. People never connect to the database.
- The API holds no provider credentials. People collect exports with their own provider access and upload them (`POST /v1/imports`).

## 1. The API's database login

1. Add the login when the roles are created: `opsdir db-roles --api-login opsdir_api …` prints it with the other roles. For an existing record, the DBA runs only the script's lines for `opsdir_api` (its role and `pg_hba.conf` line). It is a member of `opsdir_app` (rows only, no schema rights). The DBA runs the script and adds the `pg_hba.conf` line it prints, narrowed to the CIAMstack server's address.
2. Choose how it signs in, as for the other logins: a client certificate (`sslcert`, `sslkey`), a password file (`PGPASSFILE`, mode 0600), a Kerberos ticket, or a cloud database token (`OPSDIR_DB_AUTH=aws-rds-iam` or `azure-entra`). Never a password in the environment or in a unit file.
3. Name it in the record, under an approved change: `opsdir setting api-login opsdir_api --change <code>-…`. Until this setting names the login, the API's writes are attributed to `opsdir_api` itself, which holds no grants and isn't a person, so it can approve and apply nothing once people and grants are recorded.

## 2. Registering the API at the identity provider

Register the API as a protected resource (an API, not a web application) at the company's identity provider, and decide which clients may get tokens for it.

- **Access tokens must be signed JWTs.** The API checks each token's signature locally against the provider's published keys (JWKS). Opaque or reference tokens that need an introspection call aren't accepted. With PingFederate, use an access token manager that issues JWTs. With Okta, use a custom authorization server for the API.
- **Issuer (`OPSDIR_API_ISSUER`)** and **audience (`OPSDIR_API_AUDIENCE`)**: copy them from a real access token for the API (its `iss` and `aud` claims). The issuer is compared exactly, including any trailing slash and the token version's form. Government clouds have their own sign-in hosts and registrations (Azure Government uses `login.microsoftonline.us`), and their tokens aren't interchangeable with commercial ones.
- **Keys**: by default the API reads `jwks_uri` from `<issuer>/.well-known/openid-configuration`, and that document must name the same issuer. Set `OPSDIR_API_JWKS_URL` only when discovery isn't available. Keys are cached for 5 minutes and refetched when a token names an unknown key, so key rotation needs nothing on the CIAMstack side.
- **Signing algorithms (`OPSDIR_API_ALGORITHMS`)**: asymmetric ones only (default `RS256,PS256,ES256`). `none` and the HMAC family are refused.
- **Groups**: if teams are to follow the provider's groups (below), configure the provider to put the person's groups in the access token, as **immutable group IDs** (object IDs, not display names), in the claim `OPSDIR_API_GROUPS_CLAIM` names (default `groups`). Emit only the groups assigned to the application where the provider supports it. When a provider leaves the list out because the person has too many groups (Entra ID's overage marker, `_claim_names` or `hasgroups`), the call is refused rather than guessed.
- **Clock**: token times are checked with `OPSDIR_API_LEEWAY` seconds of tolerance (default 60). Keep the server's clock synchronized (NTP).

## 3. Recording people and teams

Nobody is created automatically. A token whose issuer and subject belong to no recorded person gets a 403, and so does a client-credentials token with no person behind it. An administrator records each person on the server:

```bash
opsdir person alice --name "Alice Ng" --idp-subject "<issuer> <subject>" --change <code>-…
```

The subject is the token's `sub` claim for that person, exactly. Then either give people recorded teams (`--team`), or map teams to the provider's groups so that membership follows the provider:

```bash
opsdir team sre --idp-group "<issuer> <group id>" --change <code>-…
```

A mapped team's members are whoever the provider puts in the group, request by request. Removal from the group takes effect with the person's next token. Recorded memberships of a mapped team are ignored. Mapping a team needs the `settings` action, like editing people. Grants (`opsdir grant`) then give teams and people their actions; see [Permissions](../opsdir/README.md#permissions).

## 4. Configuration

Keep the configuration in a root-owned file read by the service manager, for example `/etc/opsdir-api/env` (mode 0640, group `opsdir-api`). It holds no secret:

```bash
OPSDIR_DSN="host=db.example.internal dbname=opsdir user=opsdir_api sslmode=verify-full sslrootcert=/etc/opsdir-api/db-ca.pem sslcert=/etc/opsdir-api/api.crt sslkey=/etc/opsdir-api/api.key"
OPSDIR_API_ISSUER="https://login.example.com/<tenant>/v2.0"
OPSDIR_API_AUDIENCE="<the API's audience>"
OPSDIR_API_GROUPS_CLAIM="groups"
OPSDIR_API_MAX_UPLOAD_MB="100"
OPSDIR_API_HOST="127.0.0.1"
OPSDIR_API_PORT="8080"
OPSDIR_API_FORWARDED_ALLOW_IPS="127.0.0.1"
```

The client key (or the password file) is readable by the API's service user only. `opsdir-api` refuses to start while any value is missing or invalid, and lists each problem.

## 5. TLS in front of it

Put a reverse proxy on the same host (nginx, HAProxy, or a cloud load balancer reaching the host privately) and keep the API on `127.0.0.1`.

- **Forwarded headers**: the API trusts `X-Forwarded-For` and `X-Forwarded-Proto` only from `OPSDIR_API_FORWARDED_ALLOW_IPS` (default `127.0.0.1`, the local proxy). Don't widen it to addresses clients can reach directly.
- **Request size**: the API refuses a request body over `OPSDIR_API_MAX_UPLOAD_MB` (default 100) with a 413, and a multipart upload of more than `OPSDIR_API_MAX_FILES` files (default 10000). Set both to fit the largest export people upload (`POST /v1/imports`, `POST /v1/onboard/verify`), and set the same body limit at the proxy so oversized requests stop there.
- **Timeouts**: a full render or plan of a large estate takes seconds. Allow a few minutes for reads from the API.
- **TLS**: TLS 1.2 or later, a certificate the company's clients trust, and HSTS. Where the deployment's authorization requires FIPS-validated cryptography, terminate TLS with the platform's validated module.

An nginx example:

```nginx
server {
    listen 443 ssl;
    server_name ciamstack.example.com;
    ssl_certificate     /etc/ssl/ciamstack/fullchain.pem;
    ssl_certificate_key /etc/ssl/ciamstack/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 100m;         # the same as OPSDIR_API_MAX_UPLOAD_MB
    proxy_read_timeout 300s;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 6. Running it as a service

Run it as its own unprivileged user under the service manager. A systemd example:

```ini
[Unit]
Description=opsdir HTTP API
After=network-online.target
Wants=network-online.target

[Service]
User=opsdir-api
Group=opsdir-api
EnvironmentFile=/etc/opsdir-api/env
ExecStart=/opt/ciamstack/opsdir/.venv/bin/opsdir-api
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

The API keeps no files: renders and plans are built in memory for the request, and an uploaded file larger than 1 MB is spooled to a temporary file until the request ends (`PrivateTmp` keeps those private to the service). The upload is read only after the token is accepted. It opens one database connection per request and closes it afterwards, so leave room in the database's connection limit for concurrent requests.

## 7. Checking it

1. `curl -s http://127.0.0.1:8080/health` on the server returns `{"status": "ok"}`. It needs no token and doesn't touch the database.
2. Through the proxy, with a real person's token: `curl -s -H "Authorization: Bearer $TOKEN" https://ciamstack.example.com/v1/browse` returns the schema's areas. A 401 names what's wrong with the token. A 403 says the person isn't recorded, isn't allowed, or the group list was incomplete.
3. Propose a change as one person and approve it as another. `opsdir history` on the server shows each write with the person (`by`), the API client the token was issued to (`client`), and any mapped teams they held (`teams`).
4. `opsdir posture` as the runtime login stays `ok`.

The interactive API documentation is at `/docs`, and the OpenAPI document at `/openapi.json`.

## 8. Upgrading

Upgrade the API together with the rest of CIAMstack, as in [Upgrading](RECORD-DATABASE.md#upgrading): stop the API, take the logical backup, install the release, run `opsdir upgrade` as the migration login, start the API, then run the checks above.

## Checklist

- [ ] `opsdir_api` created by `opsdir db-roles --api-login`, allowed in `pg_hba.conf` from the CIAMstack server only, signing in without a password in the environment
- [ ] `opsdir setting api-login opsdir_api` applied under an approved change
- [ ] The API registered at the identity provider with signed JWT access tokens; issuer and audience copied from a real token
- [ ] Groups emitted as immutable IDs, if teams follow the provider's groups
- [ ] People recorded with `--idp-subject`; teams recorded or mapped; grants given
- [ ] The API on `127.0.0.1`, the proxy terminating TLS with HSTS and the same body limit as `OPSDIR_API_MAX_UPLOAD_MB`, forwarded headers trusted from the proxy only
- [ ] Running as its own user under the service manager, configuration without secrets
- [ ] Health, a real token call, an approval round trip and `opsdir posture` checked
