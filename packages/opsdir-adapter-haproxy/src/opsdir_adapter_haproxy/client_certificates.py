"""Client certificates checked at HAProxy (core pki trust policies enforced at the edge, milestone 122, decision 3302;
research docs/research m120 section 5, HAProxy 3.x configuration manual). Pure.

A trust policy checked at the edge (ciamTrustEnforcedAt edge) whose accepting role a service name of this environment
reaches through a terminating or re-encrypting HAProxy frontend gets:
  ansible/files/trust/<policy>.pem   the policy's bundle (core trust.policy_bundle: its approved anchors and the
                                     followed bundles' subordinate CAs chaining to them; public certificates), copied
                                     by the play to TRUST/<policy>.pem
  bind ... ca-file <that file> verify required
                                     HAProxy verifies the client's certificate against it and aborts the handshake
                                     without a valid one
  http-request del-header / set-header HEADER %[ssl_c_der,base64]
                                     the verified certificate (ssl_c_der: the client's certificate, DER; the base64
                                     converter: der-base64, core CERT_ENCODINGS) passed to the servers, any copy the
                                     client sent removed first (the products trust that header only from the HAProxy
                                     servers: cert_forwarding)
What HAProxy can't do from the record is a note: revocation (crl-file needs a CRL for every CA in the chain, which the
record doesn't hold; client-certificate OCSP isn't documented), and the policy's certificate policies, key usages and
identity mapping (the product checks them on the forwarded certificate). A policy with no anchor PEM, or a service name
under it whose TLS passes through HAProxy (mode tcp: nothing checks the certificate), is a blocker."""
import ipaddress

from opsdir.core.contract import CertForwarding
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import servers_with_role, subnet_of
from opsdir.core.notes import note
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.pki.trust import accepting_services, edge_policies, edge_policy_for, policy_bundle
from opsdir_adapter_ansible.names import ansible_name

AREA = "Trust"
TRUST = "/etc/haproxy/trust"           # where the play puts the policies' bundles (public certificates)
HEADER = "X-SSL-Client-Cert"
ENCODING = "der-base64"                # %[ssl_c_der,base64]: the certificate's DER, base64 (core CERT_ENCODINGS)


def trust_file(policy):
    """The file name of a policy's bundle (in ansible/files/trust/ and TRUST on the HAProxy servers)."""
    return f"{ansible_name(rdn_value(policy))}.pem"


def verifying_policy(m, svc, spec):
    """The edge trust policy HAProxy checks a service name's client certificates under (spec: its EdgeSpec), or None:
    none applies, its frontend passes TLS through, or no anchor records a PEM."""
    p = edge_policy_for(m, svc)
    return p if p is not None and spec is not None and spec.layer7 and policy_bundle(m.d, p) is not None else None


def bind_options(m, svc, spec):
    """The bind line's client certificate options for a service name ('' when nothing is checked there)."""
    p = verifying_policy(m, svc, spec)
    return f" ca-file {TRUST}/{trust_file(p)} verify required" if p is not None else ""


def forwarding_lines(m, svc, spec):
    """The frontend's lines passing the verified certificate on, any client-supplied copy removed first (() when nothing
    is checked there)."""
    if verifying_policy(m, svc, spec) is None:
        return ()
    return (f"    http-request del-header {HEADER}", f"    http-request set-header {HEADER} %[ssl_c_der,base64]")


def trust_files(m, endpoints=()):
    """{file name: PEM text} of the bundles environment m's frontends check client certificates against."""
    return {trust_file(p): policy_bundle(m.d, p) for p in edge_policies(m)
            if any(verifying_policy(m, s, service_edge(m, s, endpoints)) is not None
                   for s in accepting_services(m, p))}


def _host_cidr(address):
    """address/32 (/128) for an IP address, None for anything else (a host name)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    return f"{ip}/{ip.max_prefixlen}"


def sources(m, hosts):
    """The CIDRs HAProxy's requests reach the servers from: each server of role hosts by its address (ciamPrivateIp),
    else its subnet's ciamCidr."""
    def of(s):
        own = _host_cidr(one(s, "ciamPrivateIp") or "")
        subnet = subnet_of(m, s)
        return (own,) if own else tuple(values(subnet, "ciamCidr")) if subnet is not None else ()
    return tuple(dict.fromkeys(c for s in servers_with_role(m, hosts) for c in of(s)))


def cert_forwarding(m, svc, hosts):
    """Adapter cert_forwarding (hosts: the server role HAProxy runs on, bound by the adapter): the CertForwarding of the
    HAProxy frontend verifying a service name's client certificates (the leaf, der-base64, from the HAProxy servers),
    or None when none does."""
    if verifying_policy(m, svc, service_edge(m, svc, ())) is None:
        return None
    return CertForwarding(HEADER, ENCODING, "leaf", sources(m, hosts))


def _lacking(m, p):
    """What a policy's frontends lack for HAProxy to check its certificates."""
    plain = [one(s, "ciamFqdn") or rdn_value(s) for s in accepting_services(m, p)
             if (spec := service_edge(m, s, ())) is None or not spec.layer7]
    return (*(("an anchor recording its certificate (ciamCertificatePem)",) if policy_bundle(m.d, p) is None else ()),
            *((f"TLS terminated at HAProxy for {', '.join(plain)} (it passes through: mode tcp)",) if plain else ()))


def blocked_note(m, p):
    """The blocker of an edge policy HAProxy can't check, or None."""
    lacking = _lacking(m, p)
    if not lacking:
        return None
    return note(AREA, "blocker", f"trust policy {rdn_value(p)}",
                f"not enforced at {m.label}'s HAProxy load balancers: it needs {'; '.join(lacking)}",
                ("Record what is missing (ciamTlsMode terminate or reencrypt on the service name's traffic policy), or "
                 "check the certificates at the product (ciamTrustEnforcedAt product)",), p.dn, m.label)


def client_certificate_notes(m, services):
    """Render notes (Adapter.notes) per edge trust policy of environment m: a blocker when HAProxy can't check it;
    else what HAProxy leaves to people or products (revocation, the policy's restrictions)."""
    def of(p):
        blocker = blocked_note(m, p)
        if blocker is not None:
            return (blocker,)
        where, mode = f"trust policy {rdn_value(p)}", one(p, "ciamRevocationMode") or "none"
        return (
            *((note(AREA, "action", where, "HAProxy checks client certificate revocation only against CRL files on its "
                    "servers (crl-file, a CRL for every CA in the chain; no OCSP), and the record holds no CRLs: "
                    f"revocation ({mode}, the policy's) isn't checked at the load balancer",
                    ("Check revocation at the product, or place the CAs' CRLs on the HAProxy servers, keep them "
                     "current and add crl-file to the bind (outside opsdir's render)",), p.dn, m.label),)
              if mode != "none" else ()),
            note(AREA, "note", where, "HAProxy checks the chain only: the policy's certificate policies, key usages "
                 f"and identity mapping are checked by the product on the certificate HAProxy forwards ({HEADER}, "
                 f"{ENCODING})", (), p.dn, m.label))
    return tuple(n for p in edge_policies(m) for n in of(p))
