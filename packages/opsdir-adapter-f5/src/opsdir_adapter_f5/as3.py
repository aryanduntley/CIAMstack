"""An environment's service names as an F5 AS3 declaration (schema 3.54.0, the AS3 LTS): one tenant (the appliance's
scope, else opsdir_<cloud>_<env>), an application per service name, and per port a virtual server shaped by the service
name's traffic and protection policies as every cloud's front is (the core edge domain's EdgeSpec):

  passthrough, or no policy   Service_TCP over a pool of the target role's servers, a TCP monitor
  terminate / reencrypt       Service_HTTPS (no port-80 redirect) presenting the service name's certificate as the
                              BIG-IP holds it (Certificate {bigip: /Common/<certificate>.crt and .key}: keys never in
                              a declaration), TLS versions under the policy's minimum off; reencrypt adds serverTLS
                              (TLS_Client validating the servers' certificates unless the policy says none); an
                              HTTP(S) monitor sending the health path with the service name as Host
  stickiness cookie           persistenceMethods cookie
  request inspection          policyWAF: the BIG-IP's WAF policy named after the protection policy
                              (/Common/<protection policy>)

A value the record can't give (a frontend address, a server address) is UNBOUND:<what>: AS3 refuses the
declaration, naming it. Pure."""
import re

from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.environment import UNBOUND, of_class, servers_with_role
from opsdir.domains.edge.resolve import inspected, service_edge

SCHEMA_VERSION = "3.54.0"
TLS_VERSIONS = ("1.0", "1.1", "1.2", "1.3")


def _id(text):
    """An AS3 object name: letters, digits and underscores, starting with a letter."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", text)
    return name if name[:1].isalpha() else f"x{name}"


def tenant(m, appliance=None):
    """The AS3 tenant of environment m: the appliance's scope, else opsdir_<cloud>_<env>."""
    scope = one(appliance, "ciamApplianceScope") if appliance is not None else None
    return _id(scope or f"opsdir_{rdn_value(m.cloud)}_{rdn_value(m.env)}")


def _tls_off(minimum):
    """{tls1_xEnabled: False} for the versions under a minimum."""
    return {f"tls{v.replace('.', '_')}Enabled": False for v in TLS_VERSIONS[:TLS_VERSIONS.index(minimum)]} \
        if minimum in TLS_VERSIONS else {}


def _monitor(svc, spec):
    if spec is None or spec.health.protocol == "tcp":
        return None
    return {"class": "Monitor", "monitorType": spec.health.protocol,
            "send": f"GET {spec.health.path} HTTP/1.1\\r\\nHost: {one(svc, 'ciamFqdn')}\\r\\n"
                    "Connection: close\\r\\n\\r\\n",
            "receive": "HTTP/1\\.1 (2|3)", **({"interval": spec.health.interval} if spec.health.interval else {})}


def _pool(m, svc, port, monitor):
    role = one(svc, "ciamTargetRole")
    addresses = [one(s, "ciamPrivateIp") or f"{UNBOUND}{rdn_value(s)}-address" for s in servers_with_role(m, role)]
    return {"class": "Pool", "monitors": [{"use": "monitor"}] if monitor else ["tcp"],
            "members": [{"servicePort": int(port),
                         "serverAddresses": addresses or [f"{UNBOUND}{role}-servers"]}]}


def _application(m, svc, endpoints):
    spec = service_edge(m, svc, endpoints)
    layer7 = spec is not None and spec.layer7
    monitor = _monitor(svc, spec) if layer7 else None
    address = one(svc, "ciamFrontendIp") or f"{UNBOUND}{one(svc, 'ciamBindingRole')}-frontend-ip"
    cert = get(m.d, one(svc, "ciamTlsCertificate")) if one(svc, "ciamTlsCertificate") else None
    cert_name = rdn_value(cert) if cert is not None else f"{UNBOUND}{one(svc, 'ciamBindingRole')}-certificate"
    app = {"class": "Application", "template": "generic", "label": one(svc, "ciamFqdn")}
    for port in values(svc, "ciamPort"):
        pool = f"pool_{port}"
        common = {"virtualAddresses": [address], "virtualPort": int(port), "pool": pool,
                  **({"persistenceMethods": ["cookie"]} if spec is not None and spec.stickiness == "cookie" else {})}
        if layer7:
            reencrypt = spec.mode == "reencrypt"
            app[f"vs_{port}"] = {"class": "Service_HTTPS", "redirect80": False, "serverTLS": "tls_server", **common,
                                 **({"clientTLS": "tls_client"} if reencrypt else {}),
                                 **({"policyWAF": {"bigip": f"/Common/{rdn_value(spec.protection)}"}}
                                    if inspected(spec) and spec.protection is not None else {})}
        else:
            app[f"vs_{port}"] = {"class": "Service_TCP", **common}
        app[pool] = _pool(m, svc, port, monitor)
    if layer7:
        app["tls_server"] = {"class": "TLS_Server", "certificates": [{"certificate": "certificate"}],
                             **_tls_off(spec.tls_min)}
        app["certificate"] = {"class": "Certificate", "certificate": {"bigip": f"/Common/{cert_name}.crt"},
                              "privateKey": {"bigip": f"/Common/{cert_name}.key"}}
        if spec.mode == "reencrypt":
            app["tls_client"] = {"class": "TLS_Client", "validateCertificate": spec.backend_validation != "none",
                                 **_tls_off(spec.tls_min)}
        if monitor:
            app["monitor"] = monitor
    return app


def declaration(m, endpoints=(), appliance=None):
    """The AS3 request deploying environment m's service names (class AS3, action deploy, its ADC declaration)."""
    apps = {_id(rdn_value(svc)): _application(m, svc, endpoints) for svc in of_class(m, "ciamServiceName")}
    return {"class": "AS3", "action": "deploy", "persist": True,
            "declaration": {"class": "ADC", "schemaVersion": SCHEMA_VERSION, "id": f"opsdir-{tenant(m, appliance)}",
                            tenant(m, appliance): {"class": "Tenant", **apps}}}
