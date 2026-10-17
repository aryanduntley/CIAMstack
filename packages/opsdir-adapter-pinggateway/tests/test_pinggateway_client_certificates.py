"""Client certificates at PingGateway (milestone 122, task 580): an edge-enforced trust policy guards every route so
the forwarded header is admitted only from the edge's sources, with decoding guidance; a product-enforced one is
admin.json's HTTPS connector requiring client certificates against the policy's bundle; what isn't established are
actions, an edge forwarding nothing a blocker; and the render still reads back unchanged."""
import json
from pathlib import Path
from types import SimpleNamespace

from opsdir.connectors.importing import preview_import
from opsdir.connectors.registry import core_fragments
from opsdir.connectors.roundtrip import read_back
from opsdir.core.contract import CertForwarding
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pinggateway.adapter import ADAPTER
from opsdir_adapter_pinggateway.client_certificates import GUARD, guard_condition, unguarded
from opsdir_adapter_pinggateway.render import gateway_notes, render_env
from opsdir_adapter_pinggateway.schema import FRAGMENT
import mini_estate
from pki_samples import edge_trust_records
from support import build_directory

CONFIG = Path(__file__).resolve().parent / "gateway-config"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
PEM = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"
SVC = (f"dn: cn=svc-ig,ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: ciamServiceName\ncn: svc-ig\n"
       "ciamBindingRole: ig-service\nciamFqdn: ig.example.test\nciamPort: 443\nciamTargetRole: ig\n")
ALB = CertForwarding("X-Amzn-Mtls-Clientcert-Leaf", "url-pem", "leaf", ("10.1.2.0/24", "10.1.3.0/24"))
SERVICES = SimpleNamespace(cert_forwarding=lambda m, svc: ALB)
NONE_FORWARDED = SimpleNamespace(cert_forwarding=lambda m, svc: None)


def _files(root):
    return {p.relative_to(root).as_posix(): p.read_text() for p in sorted(root.rglob("*")) if p.is_file()}


def _alpha(edge=True, extra=""):
    trust = edge_trust_records(PEM, store=None, role="ig", extra=extra)
    if not edge:
        trust = (*trust[:-1], trust[-1].replace("ciamTrustEnforcedAt: edge", "ciamTrustEnforcedAt: product"))
    records = lambda: parse("\n".join((mini_estate.LDIF, SVC, *trust)))   # noqa: E731
    changes, _ = preview_import(build_directory(REGISTRY, records(), ()), "pinggateway", _files(CONFIG), (ADAPTER,))
    d = build_directory(REGISTRY, records(), changes)
    return d, env_model(d, "alpha/prod")


def test_an_edge_policy_guards_every_route_and_the_render_reads_back_unchanged():
    d, m = _alpha()
    files = render_env(m, SERVICES)
    portal = json.loads(files["pinggateway/routes/portal.json"])
    assert portal["handler"]["name"] == GUARD
    (enforce,) = portal["handler"]["config"]["filters"]
    assert enforce == {"type": "ConditionEnforcementFilter", "config": {"condition": (
        "${empty request.headers['X-Amzn-Mtls-Clientcert-Leaf'] or ipMatch(contexts.client.remoteAddress, "
        "'10.1.2.0/24') or ipMatch(contexts.client.remoteAddress, '10.1.3.0/24')}")}}
    plain = json.loads(render_env(m, None)["pinggateway/routes/portal.json"])
    assert portal["handler"]["config"]["handler"] == plain["handler"]
    (rt,) = read_back(d, ADAPTER, files, (ADAPTER,))
    assert rt.files and rt.changes == ()
    notes = gateway_notes(m, SERVICES)
    assert {n.severity for n in notes} == {"action"}
    assert any("urlDecodePathElement(request.headers['X-Amzn-Mtls-Clientcert-Leaf'][0])" in n.text for n in notes)


def test_an_edge_forwarding_nothing_is_a_blocker_and_leaves_the_routes_as_they_are():
    _, m = _alpha()
    assert GUARD not in render_env(m, NONE_FORWARDED)["pinggateway/routes/portal.json"]
    (blocker,) = gateway_notes(m, NONE_FORWARDED)
    assert blocker.severity == "blocker" and "ig.example.test" in blocker.text


def test_a_product_policy_is_admin_json_tls_requiring_client_certificates_against_its_bundle():
    d, m = _alpha(edge=False, extra="ciamRevocationMode: ocsp\nciamRequiredEku: 1.3.6.1.5.5.7.3.2\n")
    files = render_env(m, SERVICES)
    assert files["pinggateway/secrets/client-ca/cac-users/cac-users.client-ca.pem"] == PEM
    fragment = json.loads(files["pinggateway/admin-tls/cac-users.json"])
    (store,) = fragment["heap"][0]["config"]["stores"]
    assert store == {"type": "FileSystemSecretStore", "config": {
        "directory": "&{ig.instance.dir}/secrets/client-ca/cac-users", "suffix": ".pem", "format": "PLAIN",
        "mappings": [{"secretId": "cac-users.client-ca", "format": {"type": "PemPropertyFormat"}}]}}
    (connector,) = fragment["connectors"]
    assert connector["port"] == 8443 and connector["tls"]["config"]["clientAuth"] == "REQUIRED"
    assert connector["tls"]["config"]["trustManager"] == {"type": "SecretsTrustManager", "config": {
        "certificateVerificationSecretId": "cac-users.client-ca", "secretsProvider": "cac-users-client-ca",
        "checkRevocation": True}}
    assert GUARD not in files["pinggateway/routes/portal.json"]
    notes = gateway_notes(m, SERVICES)
    assert sorted(n.severity for n in notes) == ["action", "action", "note"]
    (rt,) = read_back(d, ADAPTER, files, (ADAPTER,))
    assert rt.changes == () and not any("admin-tls" in n or "secrets" in n for n in rt.notices)


def test_several_headers_each_need_their_own_sources_and_unguarded_restores_the_route():
    other = CertForwarding("X-Client-Cert", "pem", "leaf", ())
    assert guard_condition((ALB, other)).endswith("and (empty request.headers['X-Client-Cert'])}")
    route = {"name": "r", "handler": {"name": GUARD, "type": "Chain", "config": {"filters": [], "handler": "h"}}}
    assert json.loads(unguarded({"routes/r.json": json.dumps(route), "admin-tls/x.json": "{}"})["routes/r.json"]) == \
        {"name": "r", "handler": "h"}
