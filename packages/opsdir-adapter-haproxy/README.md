# opsdir-adapter-haproxy

opsdir load-balancer add-on: an environment's service names fronted by HAProxy on its own load-balancer servers, configured by Ansible. It is the open-source option beside the F5 BIG-IP add-on (milestone 5.3, decision 2230), for on-prem sites (or any servers) without an appliance.

**Applies to** environments whose stack declares it (`ciamStackRole: load-balancer`, `ciamAdapter: haproxy`), beside `opsdir-adapter-ansible` (its play uses that inventory). With it declared, the on-prem provider's planner check no longer asks the site's team for these load balancers. **Depends on** `opsdir` (the edge domain's traffic policies, PKI) and `opsdir-adapter-ansible`.

## What it renders

| File | Content |
|---|---|
| `ansible/files/haproxy.cfg` | Per service name and port: a frontend on its `ciamFrontendIp` (else every address) and a backend of its target role's servers (`ciamPrivateIp`, else host name, on the same port) |
| `ansible/haproxy.yml` | The play on the hosts of server role `load-balancer`: the TLS bundles, `haproxy.cfg` (checked with `haproxy -c -f` before it replaces the running one), HAProxy enabled and reloaded |

Each frontend follows the service name's traffic policy (the core edge domain's `EdgeSpec`, as every cloud's front):

| Policy | haproxy.cfg |
|---|---|
| none, or `ciamTlsMode: passthrough` | `mode tcp`, a TCP connect check |
| `terminate` | `mode http`, `bind … ssl crt /etc/haproxy/certs/<service name>.pem ssl-min-ver TLSv<min>`, `option forwardfor` |
| `reencrypt` | as `terminate`, and `server … ssl verify required ca-file @system-ca` (the system trust store, where the host config adds the record's CAs), or `verify none` when `ciamBackendValidation: none` |
| `ciamHealthProtocol` http/https, `ciamHealthPath` | `option httpchk GET <path>`; `ciamHealthIntervalSeconds` as `inter` |
| `ciamStickiness: cookie` | `cookie SERVERID insert indirect nocache`, a cookie per server |
| `ciamIdleTimeoutSeconds` | `timeout client` / `timeout server` |

The TLS bundle of a terminating frontend is the certificate's recorded PEM (`ciamCertificatePem` of the service name's `ciamTlsCertificate`) followed by its private key, read when the play runs from the environment's binding of the certificate's `ciamKeyRole` (that secret must hold the PEM private key): written mode `0600` with `no_log`, never in a file opsdir renders. A bundle the record can't complete stops the play, naming what to record.

## Planner check

`check_hosts`: a target that declares HAProxy but records no server of role `load-balancer` is a blocker (its service names would have no load balancer).

## Known limits

- The protection policy's request inspection (WAF, rate limits) isn't rendered: HAProxy is the load balancer, not a web application firewall.
- `haproxy.cfg` is checked by HAProxy itself only when the play runs (`validate`); the tests check its text and the play.

## Tests

`tests/test_haproxy.py`: a terminating front with cookie stickiness and an HTTP check; passthrough without a policy; the play's bundles with keys read at run time; a bundle the record can't complete; the planner check; the play through the real Ansible tools (marker `ansible`).
