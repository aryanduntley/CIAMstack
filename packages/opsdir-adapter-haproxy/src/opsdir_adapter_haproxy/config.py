"""haproxy.cfg for an environment's service names: per service name and port a frontend on its address (or every
address) and a backend of its target role's servers, shaped by the service name's traffic policy as every cloud's
front is (the core edge domain's EdgeSpec): TLS passed through (mode tcp, a TCP connect check, or the policy's HTTP(S)
check over TLS to the servers, check-ssl, since they speak TLS on that port), or terminated (mode http,
X-Forwarded-For) and re-encrypted to the servers when the policy says so (their certificates checked against the
system trust store, where the host config adds the record's CAs, unless the policy says none); the health check, the
minimum TLS version, cookie stickiness and the idle timeout. A terminating frontend presents the bundle the playbook
writes to /etc/haproxy/certs/<service name>.pem.

Two frontends can't share an address and port (HAProxy would split connections between unrelated backends): the
later is left out, commented, and the planner check (checks.py) names it. A server with no address or host name
recorded is commented, UNBOUND:<server>-address. Pure."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, servers_with_role
from opsdir.domains.edge.resolve import service_edge

CERTS = "/etc/haproxy/certs"
GLOBAL = ("global", "    log /dev/log local0", "    maxconn 20000", "    ssl-default-bind-options ssl-min-ver TLSv1.2",
          "", "defaults", "    log global", "    timeout connect 5s", "    timeout client 60s",
          "    timeout server 60s", "")


def _name(svc, port):
    return f"{rdn_value(svc)}_{port}".replace("-", "_")


def _verify(spec):
    return " verify none" if spec is not None and spec.backend_validation == "none" \
        else " verify required ca-file @system-ca"


def _server(s, port, spec, i):
    address = one(s, "ciamPrivateIp") or one(s, "ciamHostname")
    if address is None:
        return f"    # {UNBOUND}{rdn_value(s)}-address: server {rdn_value(s)} has no address or host name recorded"
    reencrypt = spec is not None and spec.mode == "reencrypt"
    http_check = spec is not None and spec.health is not None and spec.health.protocol != "tcp"
    tls = f" ssl{_verify(spec)}" if reencrypt else ""
    check_tls = f" check-ssl{_verify(spec)}" if http_check and not spec.layer7 else ""   # passthrough: TLS servers
    cookie = f" cookie s{i}" if spec is not None and spec.stickiness == "cookie" else ""
    health = f" inter {spec.health.interval}s" if spec is not None and spec.health and spec.health.interval else ""
    return f"    server {rdn_value(s)} {address}:{port} check{health}{check_tls}{tls}{cookie}"


def binds(m):
    """((service name, address, port), ...) of environment m's frontends, in record order ('*': every address)."""
    return tuple((svc, one(svc, "ciamFrontendIp") or "*", port)
                 for svc in of_class(m, "ciamServiceName") for port in values(svc, "ciamPort"))


def clashes(m):
    """((service name, port, the service name it clashes with), ...): frontends binding an address and port an
    earlier one binds (or every address against a specific one, on the same port)."""
    found = binds(m)
    return tuple((svc, port, other) for i, (svc, address, port) in enumerate(found)
                 for other in (next((o for o, a, p in found[:i]
                                     if p == port and (a == address or "*" in (a, address))), None),) if other)


def _service(m, svc, endpoints, skipped):
    spec = service_edge(m, svc, endpoints)
    layer7 = spec is not None and spec.layer7
    mode = "http" if layer7 else "tcp"
    address = one(svc, "ciamFrontendIp") or "*"
    servers = servers_with_role(m, one(svc, "ciamTargetRole"))
    idle = spec.idle_timeout if spec is not None and spec.idle_timeout else None
    for port in values(svc, "ciamPort"):
        n = _name(svc, port)
        if port in skipped:
            yield from (f"# frontend fe_{n} not rendered: {address}:{port} is {skipped[port]}'s", "")
            continue
        tls = f" ssl crt {CERTS}/{rdn_value(svc)}.pem ssl-min-ver TLSv{spec.tls_min}" if layer7 else ""
        health = spec.health if spec is not None else None
        check = (f"    option httpchk GET {health.path}",) if health is not None and health.protocol != "tcp" else ()
        sticky = ("    cookie SERVERID insert indirect nocache",) if spec is not None and spec.stickiness == "cookie" \
            else ()
        yield from (f"frontend fe_{n}", f"    bind {address}:{port}{tls}", f"    mode {mode}",
                    *(("    option forwardfor",) if layer7 else ()),
                    *((f"    timeout client {idle}s",) if idle else ()), f"    default_backend be_{n}", "",
                    f"backend be_{n}", f"    mode {mode}", "    balance roundrobin", *check, *sticky,
                    *((f"    timeout server {idle}s",) if idle else ()),
                    *(_server(s, port, spec, i) for i, s in enumerate(servers)),
                    *(() if servers else (f"    # no {one(svc, 'ciamTargetRole')} servers recorded",)), "")


def haproxy_cfg(m, endpoints=()):
    """haproxy.cfg's text for environment m's service names."""
    found = clashes(m)
    taken = {dn: {port: rdn_value(other) for s, port, other in found if s.dn == dn} for dn in {s.dn for s, *_ in found}}
    return "\n".join((*GLOBAL, *(line for svc in of_class(m, "ciamServiceName")
                                 for line in _service(m, svc, endpoints, taken.get(svc.dn, {})))))
