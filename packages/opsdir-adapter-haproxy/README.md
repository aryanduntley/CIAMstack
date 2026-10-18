# opsdir-adapter-haproxy

opsdir load-balancer add-on: an environment's service names fronted by HAProxy on its own load-balancer servers, configured by Ansible. It is the open-source option beside the F5 BIG-IP add-on (`opsdir-adapter-f5`; milestone 5.3, decision 2230), for on-prem sites (or any servers) without an appliance.

**Applies to** environments whose stack declares it (`ciamStackRole: load-balancer`, `ciamAdapter: haproxy`), beside `opsdir-adapter-ansible` (its play runs on that inventory's group of the servers with `ciamServerRole: load-balancer`). With it declared, the on-prem provider's planner check (`opsdir-adapter-onprem`, `keepers.py`) no longer asks the site's team for these load balancers. The distribution's `haproxy` package, whatever its version (client certificate checking: the HAProxy 3.x configuration manual; checked with HAProxy 3.2 and 3.4). Its `applies` is that declaration (never inferred from data): applying is what lets the product adapters read how it forwards a verified client certificate (`cert_forwarding`, below).

**Depends on** `opsdir` (the edge domain's traffic policies, `opsdir.domains.edge.resolve`; the PKI domain's recorded PEM and trust policies, `opsdir.domains.pki.trust`) and `opsdir-adapter-ansible` (Ansible names, the YAML writer, run-time secret lookups, the pinned Galaxy requirements). At run time: `ansible.posix` and the collections of the key lookups the play uses.

## What it renders

Per environment, nothing environment-neutral:

| File | Content |
|---|---|
| `ansible/files/haproxy.cfg` | A header, then `global` (`log /dev/log local0`, `maxconn 20000`, `ssl-default-bind-options ssl-min-ver TLSv1.2`) and `defaults` (`timeout connect 5s`, `timeout client`/`server` 60s); per service name and `ciamPort` a frontend `fe_<service name>_<port>` and a backend `be_<service name>_<port>` (`balance roundrobin`). Format `haproxy-cfg` (`#` comments), registered under `opsdir.formats` |
| `ansible/haproxy.yml` | One play on the hosts of server role `load-balancer` (`become`): HAProxy installed (the distribution's `haproxy` package); when SELinux is enabled, `haproxy_connect_any` on (`ansible.posix.seboolean`, persistent: the service names' ports aren't SELinux's http ports); an assert that stops the play when a TLS bundle can't be completed; `/etc/haproxy/certs` (mode `0700`) and the TLS bundles; `/etc/haproxy/trust` and the client CA bundles of the edge trust policies (below), when there are any; `haproxy.cfg` copied to `/etc/haproxy/haproxy.cfg`, checked with `haproxy -c -f` before it replaces the running one; HAProxy enabled and started, reloaded by a handler when a bundle or the configuration changes |
| `ansible/requirements-haproxy.yml` | The Galaxy collections the play names, pinned by `opsdir-adapter-ansible`: `ansible.posix` and the key lookups' (`amazon.aws`, `community.hashi_vault`, …) |

| From the record | haproxy.cfg |
|---|---|
| Service name `ciamFrontendIp`, `ciamPort` | `bind <address>:<port>`; without a frontend address, `*:<port>` (every address) |
| Servers of the service name's `ciamTargetRole` | `server <name> <ciamPrivateIp, else ciamHostname>:<port> check`. A server with neither is a comment, `UNBOUND:<server>-address`; no server of the role, `# no <role> servers recorded` |
| No traffic policy, or `ciamTlsMode: passthrough` (the default) | `mode tcp`, a TCP connect check |
| `ciamTlsMode: terminate` | `mode http`, `bind … ssl crt /etc/haproxy/certs/<service name>.pem ssl-min-ver TLSv<ciamTlsMinVersion, default 1.2>`, `option forwardfor` |
| `ciamTlsMode: reencrypt` | as `terminate`, and `server … ssl verify required ca-file @system-ca` (the system trust store, where the host config adds the record's CAs); `verify none` when `ciamBackendValidation` is `none`, which is the default when the policy doesn't set it |
| Health check: `ciamHealthProtocol`, `ciamHealthPath`, else the product's declared health endpoint (over `http` when terminating, `https` when re-encrypting; on the product's own health port, `Endpoint.port`, when it declares one and the policy names no path) | `option httpchk GET <path>`; `ciamHealthIntervalSeconds` as `inter <n>s`; the product's health port as `check port <n>`. With TLS passed through, `check-ssl` (the servers speak TLS on that port), verified as `ciamBackendValidation` says |
| `ciamStickiness: cookie` | On a terminating or re-encrypting front (`mode http`), `cookie SERVERID insert indirect nocache`, `cookie s<n>` per server. With TLS passed through (`mode tcp`) none: HAProxy can't insert a cookie there |
| `ciamStickiness: source-ip` | `balance source` (else `balance roundrobin`) |
| `ciamIdleTimeoutSeconds` | `timeout client` on the frontend, `timeout server` on the backend |

A frontend that would bind an address and port an earlier service name's frontend binds (one without a frontend address binds every address, so it clashes with any address on that port) isn't rendered: a comment names the service name it clashes with, and the planner blocks.

The TLS bundle of a terminating or re-encrypting frontend is the certificate's recorded PEM (`ciamCertificatePem` of the service name's `ciamTlsCertificate`, only when it is nothing but PEM certificates) followed by its private key, read when the play runs from the environment's binding of the certificate's `ciamKeyRole` (that secret must hold the PEM private key): written to `/etc/haproxy/certs/<service name>.pem` mode `0600` with `no_log`, never in a file opsdir renders. A bundle the record can't complete stops the play, naming what to record: no certificate with its PEM, no binding of the key role in the environment, or a key reference no installed adapter can read.

Not rendered: the protection policy (request inspection), the policies' stickiness duration, draining and health thresholds.

## Client certificates (trust policies checked at the edge)

A trust policy checked at the edge (`ciamTrustEnforcedAt: edge`, core `opsdir.domains.pki.trust`) whose accepting role (`ciamAcceptedByRole`) a service name's `ciamTargetRole` is, on a terminating or re-encrypting frontend:

| From the record | Rendered |
|---|---|
| The policy's bundle (`policy_bundle`: its approved anchors' PEM and the followed bundles' subordinate CAs chaining to them; public certificates) | `ansible/files/trust/<policy>.pem` (no header: PEM has no comments; its MANIFEST entry records it), copied by the play to `/etc/haproxy/trust/<policy>.pem` (`0644`) before `haproxy.cfg` is checked |
| The service name's frontend | `bind … ca-file /etc/haproxy/trust/<policy>.pem verify required`: no handshake without a certificate that bundle validates |
| The verified certificate | `http-request del-header X-SSL-Client-Cert`, then `http-request set-header X-SSL-Client-Cert %[ssl_c_der,base64]`: the client's certificate as DER (`ssl_c_der`), base64 (`base64`), one line: encoding `der-base64` |
| `cert_forwarding` (the Adapter hook the product adapters read through `Services`) | `CertForwarding("X-SSL-Client-Cert", "der-base64", "leaf", sources)`: sources each load-balancer server's `ciamPrivateIp` as a `/32` (`/128`), else its subnet's `ciamCidr` |

Render notes (`NOTES.md`): a **blocker** when no anchor of the policy records its PEM, or a service name under it passes TLS through (`mode tcp`: nothing checks the certificate; also a `# NOTE:` above its frontend), and nothing is checked there; an **action** when the policy checks revocation (`ciamRevocationMode` other than `none`): HAProxy checks client certificates only against CRL files (`crl-file`, a CRL for every CA in the chain; client-certificate OCSP isn't documented) and the record holds no CRLs, so no `crl-file` is rendered; a **note** that HAProxy checks the chain only (the policy's certificate policies, key usages and identity mapping are the product's, on the forwarded certificate).

## Planner checks

`check_hosts`: a target that declares HAProxy but records no server of role `load-balancer` is a blocker (area "Load balancer"): its service names would have no load balancer.

`check_binds`: per service name whose frontend would listen on an address and port an earlier one listens on, a blocker naming both (HAProxy would split connections between unrelated backends): record a frontend address (`ciamFrontendIp`) for each.

The edge domain's `check_stickiness` (any front, the clouds' too) makes an action of each service name whose traffic policy asks for cookie stickiness while TLS passes through: no cookie is rendered; terminate or re-encrypt TLS, or use `source-ip`.

The infrastructure domain's `check_appliance_sources` (`ciamApplianceSource` of load-balancer appliances) doesn't cover HAProxy: it reads `ciamAppliance` entries, and HAProxy's hosts are `ciamServer`s (role `load-balancer`); the firewall rules admitting them to the servers behind them are recorded like any other rule.

It adds no required roles, importers, reference schemes, vocabulary, schema or secret patterns. Its formats: `ansible/files/haproxy.cfg` (`haproxy-cfg`), `ansible/files/trust/*.pem` PEM, `ansible/*.yml` YAML. Its render notes: the client certificate ones above (`Adapter.notes`).

## Known limits

- **Not yet run against live servers.** The play passes ansible-core's syntax check and ansible-lint (marker `ansible`); `haproxy.cfg` is checked by HAProxy itself only when the play runs (`validate`), the tests check its text. Running it is part of the testing plan (milestone 7.2). The client certificate configuration was checked by hand (task 590) with `haproxy -c` of HAProxy 3.2.26 and 3.4.7, and run once with 3.4.7: a certificate the bundle validates passed (the header held its DER, base64, replacing the client's own), an untrusted one and none were refused in the handshake.
- The protection policy's request inspection (WAF, rate limits, address and country rules) isn't rendered: HAProxy is the load balancer, not a web application firewall.
- Cookie stickiness needs TLS terminated at HAProxy: on a passthrough (`mode tcp`) backend none is rendered (the edge domain's planner check names it).

## Tests

`tests/test_haproxy.py`: a terminating front with cookie stickiness and an HTTP check; passthrough without a policy, and with an HTTPS check over TLS (`check-ssl`); a product's own health port (`check port`); no cookie on a passthrough backend and `balance source` for source-ip; two names on the same address and port (the later not rendered, blocked) and a server without an address; the package, SELinux and the pinned requirements; the play's bundles with keys read at run time; a bundle the record can't complete stopping the play; the planner check without load-balancer servers; an edge trust policy checked at the bind with the verified certificate forwarded (the client's copy removed), its bundle beside the configuration and copied before the check, none without a policy, the `cert_forwarding` it declares only where a stack declares it (and none for a passthrough frontend), sources from a server's subnet, the revocation action and chain note, the blocker (and `# NOTE:`) for a passthrough frontend or a policy without an anchor PEM; and (marker `ansible`, skipped without `tools/ansible`) the play through ansible-core and ansible-lint.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-haproxy/tests` (unit), and with `-m ansible` for the tool checks (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry points `opsdir.adapters`: `haproxy`; `opsdir.formats`: `haproxy-cfg`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
