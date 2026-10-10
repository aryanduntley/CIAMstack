"""Application Insights standard web tests rendered from the record: a GET of the health or login page from the
cloud's own test locations, named as the canary binding; an oidc-token check or an internal service is named."""
from opsdir.core.contract import Endpoint
from opsdir.domains.observability.naming import CANARIES
from opsdir_adapter_azure.canaries import render_tests
from network_fixtures import BETA, entry, model

ENDPOINTS = (Endpoint("health", "/pf/heartbeat.ping", "web"), Endpoint("token", "/as/token.oauth2", "web"))


def _canary(cn, **attrs):
    return entry(CANARIES, cn, "ciamCanary", **attrs).replace("objectClass: ciamCanary",
                                                               "objectClass: ciamObject\nobjectClass: ciamCanary")


TREE = (f"dn: {CANARIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: canaries\n",
        _canary("sso-alive", ciamCheckedService="sso", ciamCanaryFlow="health", ciamInterval="7m"),
        _canary("sso-token", ciamCheckedService="sso", ciamCanaryFlow="oidc-token", ciamUsesRole="client"))
BINDINGS = (entry(BETA, "svc-sso", "ciamServiceName", ciamBindingRole="sso", ciamFqdn="sso.example.test",
                  ciamTargetRole="web", ciamFrontendIp="203.0.113.10"),
            entry(BETA, "client", "ciamSecretRef", ciamBindingRole="client", ciamRefUri="azkv://kv/canary"),
            entry(BETA, "sso-login", "ciamCanaryBinding", ciamBindingRole="canary-sso-alive",
                  ciamRealizes="sso-alive", ciamProviderRef="/subscriptions/0/x/webtests/sso-login"))


def test_a_health_check_runs_from_the_clouds_test_locations():
    _, _, beta = model(beta=BINDINGS, tree=TREE)
    out = render_tests(beta, ENDPOINTS)
    text = "\n".join(out)
    assert 'resource "azurerm_application_insights_standard_web_test" "sso_login" {' in text
    assert "application_insights_id = var.application_insights_id" in text
    assert '"us-va-ash-azr"' in text and "frequency               = 600" in text           # 7m raised to 10m
    assert 'url       = "https://sso.example.test/pf/heartbeat.ping"' in text
    assert "expected_status_code = 200" in text and 'Realizes    = "sso-alive"' in text
    assert out[-1].startswith('variable "application_insights_id"')
    assert [x for x in out if x.startswith("#")] == [
        "# NOTE: canary sso-token: not rendered: a standard web test sends one request and can't read credentials "
        "when it runs: an oidc-token check would hold its secret in the test"]


def test_azure_government_tests_from_its_own_locations():
    _, _, beta = model(beta=BINDINGS, tree=TREE)
    gov = beta._replace(cloud=beta.cloud._replace(attrs={**beta.cloud.attrs, "ciamRegion": ("usgovvirginia",)}))
    assert '"usgov-va-azr"' in "\n".join(render_tests(gov, ENDPOINTS))
