"""Client certificates checked at an Application Gateway (core pki trust policies enforced at the edge, milestone 122,
decision 3302; research docs/research m120 section 5). Pure.

A trust policy checked at the edge (ciamTrustEnforcedAt edge) whose accepting role a service name of this environment
fronts with an Application Gateway v2 gets, on that gateway:
  trusted_client_certificate   the policy's chains (core trust.anchor_chains: per approved anchor, the anchor and the
                               followed bundles' subordinate CAs chaining to it; public certificates) as PEM files of
                               at most FILE_LIMIT bytes, each starting with its anchor (the gateway takes chains with
                               their root)
  ssl_profile                  those certificates, client_authentication_mode Strict, OCSP checking when the policy's
                               revocation mode starts with OCSP, and the gateway's TLS policy; named on the service's
                               listeners
  rewrite_rule_set             the verified certificate (server variable client_certificate) passed to the backends
                               in CLIENT_CERT_HEADER on the service's routing rules (the products trust that header only
                               from the gateway: their render's)
What the gateway can't do is a note: revocation only by OCSP (no CRLs), the chain only (the policy's certificate
policies, key usages and identity mapping are the product's to check), and more than CHAIN_LIMIT chains on a profile. A
policy with no anchor PEM, or a service name under it whose TLS passes through a load balancer, is a blocker. In Azure
Government, whose pages don't state Application Gateway mutual TLS (research m120 section 5), confirming it is an
action.
"""
import base64
from functools import reduce

from opsdir.core.directory import one, rdn_value
from opsdir.core.notes import note
from opsdir.domains.pki.trust import accepting_services, anchor_chains, edge_policies, edge_policy_for, policy_bundle
from opsdir_format_terraform.hcl import Block, tf_name
from .account import unstated_note

AREA = "Trust"
FILE_LIMIT = 25_000      # bytes per trusted client certificate file (Application Gateway mTLS limits: 25 KB)
CHAIN_LIMIT = 100        # trusted client CA certificate chains per SSL profile
CLIENT_CERT_HEADER = "X-Client-Cert"
CLIENT_CERT_ENCODING = "pem"     # the server variable client_certificate as the rewrite passes it (core CERT_ENCODINGS)
REWRITE_SET = "client-certificate"


def _pem(c):
    return one(c, "ciamCertificatePem").strip() + "\n"


def _packed(root, pems):
    """root followed by pems, in files of at most FILE_LIMIT bytes, each starting with root."""
    def add(files, p):
        return (*files[:-1], files[-1] + p) if len(files[-1]) + len(p) <= FILE_LIMIT else (*files, root + p)
    return reduce(add, pems, (root,))


def chain_files(d, policy):
    """((name, PEM text), ...): the policy's chains as the gateway's trusted client certificate files, anchors without a
    PEM left out (the core's check names them)."""
    return tuple((f"{tf_name(rdn_value(policy))}-{tf_name(rdn_value(a))}-{i}", text)
                 for a, subordinates in anchor_chains(d, policy) if one(a, "ciamCertificatePem")
                 for i, text in enumerate(_packed(_pem(a), tuple(_pem(c) for c in subordinates
                                                                 if one(c, "ciamCertificatePem"))), 1))


def profile_name(policy):
    return f"mtls-{tf_name(rdn_value(policy))}"


def _checks_ocsp(policy):
    return (one(policy, "ciamRevocationMode") or "none").startswith("ocsp")


def client_authentication(m, svc, ssl_policy):
    """(gateway body, listener body, routing rule body) checking a service name's client certificates under its edge
    trust policy with the gateway's TLS policy (a Block); ((), (), ()) when it has none or no anchor has a PEM."""
    p = edge_policy_for(m, svc)
    if p is None or policy_bundle(m.d, p) is None:
        return (), (), ()
    files = chain_files(m.d, p)
    certificates = tuple(("trusted_client_certificate", Block((("name", n),
                                                               ("data", base64.b64encode(text.encode()).decode()))))
                         for n, text in files)
    profile = ("ssl_profile", Block((
        ("name", profile_name(p)), ("trusted_client_certificate_names", [n for n, _ in files]),
        ("client_authentication_mode", "Strict"),
        *((("verify_client_certificate_revocation", "OCSP"),) if _checks_ocsp(p) else ()),
        ("ssl_policy", Block(tuple(kv for kv in ssl_policy.body if kv[0] != "#"))))))
    forward = ("rewrite_rule_set", Block((("name", REWRITE_SET), ("rewrite_rule", Block((
        ("name", "forward-client-certificate"), ("rule_sequence", 100),
        ("request_header_configuration", Block((("header_name", CLIENT_CERT_HEADER),
                                                ("header_value", "{var_client_certificate}"))))))))))
    return ((*certificates, profile, forward), (("ssl_profile_name", profile_name(p)),),
            (("rewrite_rule_set_name", REWRITE_SET),))


def client_certificate_notes(m, gateways):
    """Per edge trust policy of environment m, given the service names it fronts with an Application Gateway
    (gateways): a blocker when no anchor has a PEM or a service name under it passes TLS through (a load balancer can't
    check certificates); else what the gateways leave to people or products."""
    names = {s.dn for s in gateways}
    def of(p):
        where = f"trust policy {rdn_value(p)}"
        plain = [one(s, "ciamFqdn") or rdn_value(s) for s in accepting_services(m, p) if s.dn not in names]
        lacking = (*(("an anchor recording its certificate (ciamCertificatePem)",) if policy_bundle(m.d, p) is None
                     else ()),
                   *((f"an application gateway in front of {', '.join(plain)} (TLS passes through a load balancer)",)
                     if plain else ()))
        if lacking:
            return (note(AREA, "blocker", where, f"not enforced at {m.label}'s edge: it needs {'; '.join(lacking)}",
                         ("Record what is missing, terminate TLS at the edge, or check the certificates at the "
                          "product (ciamTrustEnforcedAt product)",), p.dn, m.label),)
        count = len(chain_files(m.d, p))
        mode = one(p, "ciamRevocationMode") or "none"
        return (
            *((note(AREA, "action", where, f"the application gateways check revocation only by OCSP (no CRLs): {mode} "
                    "is the policy's", ("Check revocation at the product, or make the policy's mode OCSP",),
                    p.dn, m.label),) if mode not in ("none", "ocsp") else ()),
            note(AREA, "note", where, "the application gateways check the chain only: the policy's certificate "
                 "policies, key usages and identity mapping are checked by the product on the certificate the "
                 f"gateway forwards ({CLIENT_CERT_HEADER})", (), p.dn, m.label),
            *((note(AREA, "action", where, f"its chains make {count} trusted client certificates; an SSL profile "
                    f"takes {CHAIN_LIMIT}", ("Split the policy, or check the certificates at the product",),
                    p.dn, m.label),) if count > CHAIN_LIMIT else ()))
    found = tuple(n for p in edge_policies(m) for n in of(p))
    gov = unstated_note(m, "Application Gateway mutual TLS (client certificate checking)") \
        if any(n.severity != "blocker" for n in found) else None
    return (*found, *((gov,) if gov is not None else ()))
