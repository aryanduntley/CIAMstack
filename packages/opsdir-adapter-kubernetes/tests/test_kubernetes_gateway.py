"""The in-cluster gateway behind a cloud's front: per cluster gateway binding, the Gateway (Istio by default, Envoy
Gateway by the binding or the estate setting) with the cloud's plug, and per fronted service name its HTTPRoute from the
kits' routes, backend TLS and cookie stickiness; its Secrets delivered like a workload's; valid Kubernetes."""
import pathlib
import subprocess

import yaml

from opsdir.connectors.registry import services
from opsdir.core.contract import GatewayPlug, K8sIdentity, Route
from opsdir.core.directory import one
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.settings import setting_dn
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.edge.naming import EDGE_POLICIES
from opsdir_adapter_hashicorp_vault.adapter import ADAPTER as VAULT
from opsdir_adapter_kubernetes.adapter import ADAPTER
from opsdir_adapter_kubernetes.gateway import CHOICES, SETTING
from opsdir_adapter_kubernetes.render import render
import mini_estate
from pki_samples import CA_PEM, CERTIFICATES, ca_records
from mini_estate import FAKE
from support import REGISTRY, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
ROOT = pathlib.Path(__file__).resolve().parents[3]


def _workload(name, role):
    return (f"dn: {workload_dn(name)}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: {name}\n"
            f"ciamWorkloadKind: deployment\nciamTargetRole: {role}\nciamClusterRole: k8s\nciamNamespace: identity\n"
            f"ciamWorkloadRole: {name}-workload\n")


def _binding(cn, oc, role, extra=""):
    return (f"dn: cn={cn},ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\n"
            f"ciamBindingRole: {role}\n{extra}")


def _service(cn, role, fqdn, target):
    return _binding(cn, "ciamServiceName", role, f"ciamFqdn: {fqdn}\nciamPort: 443\nciamTargetRole: {target}\n")


GATEWAY = _binding("edge-gw", "ciamClusterGateway", "k8s-gateway",
                   "ciamClusterRole: k8s\nciamNamespace: edge\nciamFrontendIp: 10.1.9.10\nciamServiceAccount: edge\n"
                   "ciamWorkloadSecret: edge-gw-tls/tls.crt <- gw-cert\n"
                   "ciamWorkloadSecret: edge-gw-tls/tls.key <- gw-key\n")
RECORDS = (
    f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
    _workload("am", "am"), _workload("ig", "ig"), _workload("pf-engine", "pf-engine"),
    _binding("k8s", "ciamCluster", "k8s", "ciamProviderRef: cluster-1\n"),
    *(_binding(n, "ciamWorkloadBinding", f"{n}-workload") for n in ("am", "ig", "pf-engine")),
    _service("svc-login", "login-service", "login.example.test", "am"),
    _service("svc-apps", "apps-service", "apps.example.test", "ig"),
    _service("svc-sso", "sso-service", "sso.example.test", "pf-engine"),
    f"dn: {EDGE_POLICIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
    f"dn: cn=sign-on,{EDGE_POLICIES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamTrafficPolicy\n"
    "cn: sign-on\nciamServiceRole: login-service\nciamServiceRole: sso-service\nciamTlsMode: reencrypt\n"
    "ciamStickiness: cookie\nciamStickinessSeconds: 3600\n",
    _binding("gw-cert", "ciamSecretRef", "gw-cert", "ciamRefUri: vault://secret/ciam/gw/crt\n"),
    _binding("gw-key", "ciamSecretRef", "gw-key", "ciamRefUri: vault://secret/ciam/gw/key\n"),
    _binding("vault", "ciamSecretStore", "secret-store-vault",
             "ciamRefScheme: vault\nciamStoreEndpoint: https://vault.example.test:8200\nciamStoreAuthRole: ciam\n"))
ROUTES = (Route("am", "/am", "prefix", "am", 80), Route("am", "/am/XUI", "prefix", "login-ui", 8080),
          Route("ig", "/ig", "prefix", "ig", 80, "/"), Route("pf-engine", "/", "prefix", "pf-engine", 9031, None, True))
CLOUD = FAKE._replace(
    listeners=lambda m: (), routes=lambda m: ROUTES,
    workload_identity=lambda m, b: K8sIdentity((("cloud.example.test/identity", one(b, "ciamProviderRef")),), ()),
    gateway_plug=lambda m, gw, service: GatewayPlug(
        (("cloud.example.test/internal-ip", one(gw, "ciamFrontendIp")),),
        ({"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{service[0]}-plug", "namespace": "edge"},
          "data": {"ports": ",".join(map(str, service[1]))}},), "LoadBalancer"))
INSTALLED = (CLOUD, ADAPTER, VAULT)


def model(*extra):
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORDS, *extra)))))
    return env_model(d, "alpha/prod")


def _docs(files, path):
    return [x for x in yaml.safe_load_all(files[path]) if x is not None]


def _kinds(docs):
    return {(d["kind"], d["metadata"]["name"]): d for d in docs}


def test_no_gateway_no_gateway_objects():
    files = render(model(), services(INSTALLED))
    assert not any(p.endswith(("gateway.yaml", "routes.yaml")) for p in files)


def test_an_istio_gateway_behind_the_clouds_front_by_default():
    files = render(model(GATEWAY), services(INSTALLED), ("external-secrets",))
    assert SETTING.default == "istio" and CHOICES == ("istio", "envoy-gateway")
    edge = _kinds(_docs(files, "kubernetes/edge/gateway.yaml"))
    gw = edge[("Gateway", "edge-gw")]
    assert gw["spec"]["gatewayClassName"] == "istio" and ("GatewayClass", "istio") not in edge   # istiod's own
    assert gw["metadata"]["annotations"] == {"opsdir.io/cluster-role": "k8s", "opsdir.io/gateway-role": "k8s-gateway",
                                             "gateway.istio.io/name-override": "edge-gw",
                                             "networking.istio.io/service-type": "LoadBalancer"}
    assert gw["spec"]["infrastructure"]["annotations"] == {
        "cloud.example.test/internal-ip": "10.1.9.10",
        "proxy.istio.io/config": "gatewayTopology:\n  numTrustedProxies: 1\n"}
    http, https = gw["spec"]["listeners"]
    assert (http["name"], http["port"], https["name"], https["port"]) == ("http", 80, "https", 443)
    assert https["tls"]["certificateRefs"] == [{"kind": "Secret", "name": "edge-gw-tls"}]
    assert http["allowedRoutes"]["namespaces"]["selector"]["matchExpressions"][0]["values"] == ["identity"]
    assert edge[("ConfigMap", "edge-gw-plug")]["data"] == {"ports": "80,443"}         # the cloud's plug
    # its Secrets are delivered like a workload's
    assert "kubernetes/edge/externalsecrets.yaml" in files and "kubernetes/edge/secrets-required.yaml" in files
    assert ("ServiceAccount", "edge") in _kinds(_docs(files, "kubernetes/edge/serviceaccounts.yaml"))
    assert _docs(files, "kubernetes/edge/kustomization.yaml")[0]["resources"][-1] == "gateway.yaml"


def test_routes_backend_tls_and_stickiness_in_the_roles_namespace():
    routes = _kinds(_docs(render(model(GATEWAY), services(INSTALLED)), "kubernetes/identity/routes.yaml"))
    login = routes[("HTTPRoute", "svc-login")]["spec"]
    assert login["hostnames"] == ["login.example.test"]
    assert login["parentRefs"] == [{"name": "edge-gw", "namespace": "edge", "sectionName": "https"}]   # reencrypt
    assert [r["matches"][0]["path"]["value"] for r in login["rules"]] == ["/am", "/am/XUI"]
    apps = routes[("HTTPRoute", "svc-apps")]["spec"]
    assert apps["parentRefs"][0]["sectionName"] == "http"                                  # no policy: terminate
    assert apps["rules"][0]["filters"] == [{"type": "URLRewrite", "urlRewrite": {"path": {
        "type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}}}]
    tls = routes[("BackendTLSPolicy", "pf-engine-tls")]["spec"]
    assert tls["validation"] == {
        "caCertificateRefs": [{"group": "", "kind": "ConfigMap", "name": "edge-gw-backend-ca"}],
        "hostname": "pf-engine.identity.svc.cluster.local"}
    assert routes[("ConfigMap", "edge-gw-backend-ca")]["data"] == {"ca.crt": "UNBOUND:gateway-ca-pem"}  # no CA trusted
    cookie = routes[("DestinationRule", "am-affinity")]["spec"]
    assert cookie["host"] == "am.identity.svc.cluster.local"
    assert cookie["trafficPolicy"]["loadBalancer"]["consistentHash"]["httpCookie"] == {
        "name": "route", "ttl": "3600s", "path": "/"}
    assert ("DestinationRule", "ig-affinity") not in routes                             # no stickiness asked


def test_the_backend_ca_bundle_holds_the_pems_of_the_cas_the_gateway_trusts():
    trusting = GATEWAY + f"ciamTrustsCertificate: cn=internal-ca,{CERTIFICATES}\n"
    routes = _kinds(_docs(render(model(trusting, *ca_records()), services(INSTALLED)),
                          "kubernetes/identity/routes.yaml"))
    assert routes[("ConfigMap", "edge-gw-backend-ca")] == {
        "apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": "edge-gw-backend-ca", "namespace": "identity"},
        "data": {"ca.crt": CA_PEM}}
    routes = _kinds(_docs(render(model(trusting, *ca_records(pem=None)), services(INSTALLED)),
                          "kubernetes/identity/routes.yaml"))
    assert routes[("ConfigMap", "edge-gw-backend-ca")]["data"] == {"ca.crt": "UNBOUND:internal-ca-pem"}


def test_envoy_gateway_by_the_binding_or_the_estate_setting():
    envoy = GATEWAY + "ciamGatewayImplementation: envoy-gateway\n"
    setting = (f"dn: ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: settings\n",
               f"dn: {setting_dn(SETTING.name)}\nobjectClass: top\nobjectClass: ciamEstateSetting\n"
               f"cn: {SETTING.name}\nciamEstateValue: envoy-gateway\n")
    for m in (model(envoy), model(GATEWAY, *setting)):
        files = render(m, services(INSTALLED))
        edge = _kinds(_docs(files, "kubernetes/edge/gateway.yaml"))
        assert edge[("GatewayClass", "envoy")]["spec"]["controllerName"] == \
            "gateway.envoyproxy.io/gatewayclass-controller"
        assert edge[("Gateway", "edge-gw")]["spec"]["infrastructure"] == {
            "parametersRef": {"group": "gateway.envoyproxy.io", "kind": "EnvoyProxy", "name": "edge-gw-proxy"}}
        service = edge[("EnvoyProxy", "edge-gw-proxy")]["spec"]["provider"]["kubernetes"]["envoyService"]
        assert service == {"name": "edge-gw", "type": "LoadBalancer",
                           "annotations": {"cloud.example.test/internal-ip": "10.1.9.10"}}
        assert edge[("ClientTrafficPolicy", "edge-gw-client-ip")]["spec"]["clientIPDetection"] == {
            "xForwardedFor": {"numTrustedHops": 1}}
        routes = _kinds(_docs(files, "kubernetes/identity/routes.yaml"))
        assert routes[("BackendTrafficPolicy", "svc-login-affinity")]["spec"]["loadBalancer"]["consistentHash"] == {
            "type": "Cookie", "cookie": {"name": "route", "ttl": "3600s", "attributes": {"Path": "/"}}}


def test_a_rendered_gateway_reads_back_as_the_same_binding():
    from opsdir.connectors.importing import preview_import
    from opsdir.core.directory import get
    files = render(model(GATEWAY), services(INSTALLED))
    base = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORDS)))))
    changes, _ = preview_import(base, "kubernetes/workloads", {"alpha/prod/edge/gateway.yaml":
                                                               files["kubernetes/edge/gateway.yaml"]}, (ADAPTER,))
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORDS)))), changes)
    gw = get(d, f"cn=edge-gw,ou=bindings,{ALPHA}")
    assert (one(gw, "ciamClusterRole"), one(gw, "ciamNamespace"), one(gw, "ciamGatewayImplementation"),
            one(gw, "ciamBindingRole")) == ("k8s", "edge", "istio", "k8s-gateway")


def test_the_gateway_render_is_valid_kubernetes(tmp_path):
    for i, extra in enumerate((GATEWAY, GATEWAY + "ciamGatewayImplementation: envoy-gateway\n")):
        for path, text in render(model(extra), services(INSTALLED), ("external-secrets",)).items():
            (tmp_path / str(i) / path).parent.mkdir(parents=True, exist_ok=True)
            (tmp_path / str(i) / path).write_text(text)
    done = subprocess.run([str(ROOT / "opsdir" / "scripts" / "validate-kubernetes.sh"), str(tmp_path)],
                          capture_output=True, text=True)
    assert done.returncode == 0, done.stdout + done.stderr
