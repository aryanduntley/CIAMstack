"""Synthetic checks on Azure (core observability: domains/observability/canaries) as Application Insights standard
web tests. Pure.

Each canary the environment can run whose request the record describes (canary_specs), for the flows one GET
answers (health, login-page), as an azurerm_application_insights_standard_web_test named as its canary binding: a GET
of its URL expecting 200, the TLS certificate checked, retries on, every 5, 10 or 15 minutes (its interval, raised to
the next), from the five test locations of its cloud (Azure Government's when the cloud's region is a US Gov or DoD
region: usgov-va-azr, usgov-phx-azr, usgov-tx-azr, usgov-ddeast-azr, usgov-ddcentral-azr; else five US ones), tagged
Realizes and BindingRole so the inventory reads it back. The workspace-based Application Insights resource the tests
belong to is the root's input application_insights_id (the record doesn't name it).

Not rendered, and said so: what canary_specs names; an oidc-token check (a standard test sends one request and has no
way to read a secret when it runs: its credentials would sit in the test); a service name that isn't internet-facing
(the test locations reach only public endpoints). A test someone else keeps, or an overlay inherits from its base, is
named with its keeper.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.domains.edge.exposure import service_exposure
from opsdir.domains.observability.canaries import canary_specs
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .account import government, tagged
from .identities import LOC, RG

TEST = "azurerm_application_insights_standard_web_test"
INPUT = "application_insights_id"
FREQUENCIES = (300, 600, 900)
PUBLIC_LOCATIONS = ("us-va-ash-azr", "us-il-ch1-azr", "us-tx-sn1-azr", "us-ca-sjc-azr", "us-fl-mia-edge")
GOVERNMENT_LOCATIONS = ("usgov-va-azr", "usgov-phx-azr", "usgov-tx-azr", "usgov-ddeast-azr", "usgov-ddcentral-azr")
GET_FLOWS = ("health", "login-page")


def _why(m, spec):
    if spec.why:
        return spec.why
    if spec.flow not in GET_FLOWS:
        return ("a standard web test sends one request and can't read credentials when it runs: an oidc-token check "
                "would hold its secret in the test")
    svc = one_role(m, one(spec.canary, "ciamCheckedService"))
    if service_exposure(svc) != "internet":
        return f"service name {rdn_value(svc)} isn't recorded as internet-facing: test locations reach public endpoints"
    return None


def _test(m, spec):
    cn, why = rdn_value(spec.canary), _why(m, spec)
    if why:
        return (f"# NOTE: canary {cn}: not rendered: {why}",)
    if spec.keeper is not None:
        return (f"# Availability test {spec.name} ({cn}): kept by {spec.keeper}, not rendered here",)
    frequency = next((f for f in FREQUENCIES if f >= spec.every), FREQUENCIES[-1])
    return (block("resource", [TEST, tf_name(spec.name)], [
        ("name", spec.name), ("resource_group_name", RG), ("location", LOC),
        ("application_insights_id", ref(f"var.{INPUT}")),
        ("geo_locations", list(GOVERNMENT_LOCATIONS if government(m) else PUBLIC_LOCATIONS)),
        ("frequency", frequency), ("timeout", 30), ("enabled", True), ("retry_enabled", True),
        ("request", Block((("url", spec.url), ("http_verb", "GET")))),
        ("validation_rules", Block((("expected_status_code", 200), ("ssl_check_enabled", True)))),
        ("tags", tagged(m, {"Realizes": cn, "BindingRole": one(spec.binding, "ciamBindingRole")
                            if spec.binding is not None else f"canary-{cn}"}))]),)


def render_tests(m, endpoints):
    """HCL (and comments) for environment m's availability tests, and the input they need when there is one."""
    out = tuple(x for s in canary_specs(m, endpoints) for x in _test(m, s))
    needs = any(x.startswith("resource") for x in out)
    return (*out, *((block("variable", [INPUT], [
        ("description", "The workspace-based Application Insights resource the availability tests belong to"),
        ("type", ref("string"))]),) if needs else ()))
