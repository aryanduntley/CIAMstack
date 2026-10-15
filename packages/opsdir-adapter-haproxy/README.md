# opsdir-adapter-haproxy

opsdir load-balancer add-on: an environment's service names fronted by HAProxy on its own load-balancer servers, configured by Ansible. It is the open-source option beside the F5 BIG-IP add-on (`opsdir-adapter-f5`; milestone 5.3, decision 2230), for on-prem sites (or any servers) without an appliance.

**Applies to** environments whose stack declares it (`ciamStackRole: load-balancer`, `ciamAdapter: haproxy`), beside `opsdir-adapter-ansible` (its play runs on that inventory's group of the servers with `ciamServerRole: load-balancer`). With it declared, the on-prem provider's planner check (`opsdir-adapter-onprem`, `keepers.py`) no longer asks the site's team for these load balancers. The distribution's `haproxy` package, whatever its version.

**Depends on** `opsdir` (the edge domain's traffic policies, `opsdir.domains.edge.resolve`; the PKI domain's recorded PEM) and `opsdir-adapter-ansible` (Ansible names, the YAML writer, run-time secret lookups, the pinned Galaxy requirements). At run time: `ansible.posix` and the collections of the key lookups the play uses.

## What it renders

Per environment, nothing environment-neutral:

| File | Content |
|---|---|
| `ansible/files/haproxy.cfg` | A header, then `global` (`log /dev/log local0`, `maxconn 20000`, `ssl-default-bind-options ssl-min-ver TLSv1.2`) and `defaults` (`timeout connect 5s`, `timeout client`/`server` 60s); per service name and `ciamPort` a frontend `fe_<service name>_<port>` and a backend `be_<service name>_<port>` (`balance roundrobin`). Format `haproxy-cfg` (`#` comments), registered under `opsdir.formats` |
| `ansible/haproxy.yml` | One play on the hosts of server role `load-balancer` (`become`): HAProxy installed (the distribution's `haproxy` package); when SELinux is enabled, `haproxy_connect_any` on (`ansible.posix.seboolean`, persistent: the service names' ports aren't SELinux's http ports); an assert that stops the play when a TLS bundle can't be completed; `/etc/haproxy/certs` (mode `0700`) and the TLS bundles; `haproxy.cfg` copied to `/etc/haproxy/haproxy.cfg`, checked with `haproxy -c -f` before it replaces the running one; HAProxy enabled and started, reloaded by a handler when a bundle or the configuration changes |
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

## Planner checks

`check_hosts`: a target that declares HAProxy but records no server of role `load-balancer` is a blocker (area "Load balancer"): its service names would have no load balancer.

`check_binds`: per service name whose frontend would listen on an address and port an earlier one listens on, a blocker naming both (HAProxy would split connections between unrelated backends): record a frontend address (`ciamFrontendIp`) for each.

The edge domain's `check_stickiness` (any front, the clouds' too) makes an action of each service name whose traffic policy asks for cookie stickiness while TLS passes through: no cookie is rendered; terminate or re-encrypt TLS, or use `source-ip`.

The infrastructure domain's `check_appliance_sources` (`ciamApplianceSource` of load-balancer appliances) doesn't cover HAProxy: it reads `ciamAppliance` entries, and HAProxy's hosts are `ciamServer`s (role `load-balancer`); the firewall rules admitting them to the servers behind them are recorded like any other rule.

It adds no required roles, importers, reference schemes, vocabulary, schema or secret patterns. Its formats: `ansible/files/haproxy.cfg` (`haproxy-cfg`), `ansible/*.yml` YAML.

## Known limits

- **Not yet run against live servers.** The play passes ansible-core's syntax check and ansible-lint (marker `ansible`); `haproxy.cfg` is checked by HAProxy itself only when the play runs (`validate`), the tests check its text. Running it is part of the testing plan (milestone 7.2).
- The protection policy's request inspection (WAF, rate limits, address and country rules) isn't rendered: HAProxy is the load balancer, not a web application firewall.
- Cookie stickiness needs TLS terminated at HAProxy: on a passthrough (`mode tcp`) backend none is rendered (the edge domain's planner check names it).

## Tests

`tests/test_haproxy.py`: a terminating front with cookie stickiness and an HTTP check; passthrough without a policy, and with an HTTPS check over TLS (`check-ssl`); a product's own health port (`check port`); no cookie on a passthrough backend and `balance source` for source-ip; two names on the same address and port (the later not rendered, blocked) and a server without an address; the package, SELinux and the pinned requirements; the play's bundles with keys read at run time; a bundle the record can't complete stopping the play; the planner check without load-balancer servers; and (marker `ansible`, skipped without `tools/ansible`) the play through ansible-core and ansible-lint.

From the repository root: `opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-haproxy/tests` (unit), and with `-m ansible` for the tool checks (`opsdir/scripts/fetch-tools.sh` first).

Installing the package registers it with opsdir (entry points `opsdir.adapters`: `haproxy`; `opsdir.formats`: `haproxy-cfg`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
