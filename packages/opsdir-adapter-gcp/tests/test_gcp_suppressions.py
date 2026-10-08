"""Suppressions on Google Cloud: a Security Command Center mute rule (STATIC) of the exception's categories, named
after it, its expiry in a comment (the provider takes none); read back from state with the exception."""
from opsdir_adapter_gcp.suppressions import render_suppressions, suppression_resources
from network_fixtures import ALPHA, entry, model

EXC = "cn=EXC-7,ou=exceptions,dc=ciam-ops"
TREE = ("dn: ou=exceptions,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: exceptions\n",
        f"dn: {EXC}\nobjectClass: top\nobjectClass: ciamRiskException\ncn: EXC-7\nciamExceptionKind: false-positive\n"
        "ciamExceptionStatus: approved\nciamAffectedEnvironment: env=prod,cloud=alpha,ou=environments,dc=ciam-ops\n"
        "ciamExpiresAt: 20270331000000Z\n")


def test_a_suppression_renders_a_static_mute_rule_of_its_categories():
    s = entry(ALPHA, "exc-EXC-7", "ciamSuppression", ciamBindingRole="suppression-EXC-7", ciamExceptionRef=EXC,
              ciamFindingRef=("gcp:scc:OPEN_FIREWALL", "gcp:scc:PUBLIC_IP_ADDRESS", "aws:securityhub:IAM.6"))
    _, alpha, _ = model(alpha=(s,), tree=TREE)
    out = "\n\n".join(render_suppressions(alpha))
    assert 'resource "google_scc_v2_project_mute_config" "exc_exc_7"' in out
    assert 'mute_config_id = "exc-exc-7"' in out and 'type           = "STATIC"' in out
    assert 'filter         = "category=\\"OPEN_FIREWALL\\" OR category=\\"PUBLIC_IP_ADDRESS\\""' in out
    assert 'description    = "exception EXC-7, until 2027-03-31"' in out
    assert "# exc-EXC-7: the google provider takes no expiry for a mute rule: remove it on 2027-03-31" in out
    assert out.endswith("# exc-EXC-7: not Google Cloud's (not rendered here): aws:securityhub:IAM.6")


def test_mute_rules_are_read_back_with_their_exception():
    pairs = [("google_scc_v2_project_mute_config", {
        "name": "projects/p/locations/global/muteConfigs/exc-exc-7", "mute_config_id": "exc-exc-7",
        "description": "exception EXC-7, until 2027-03-31", "filter": 'category="OPEN_FIREWALL" OR category="X"'})]
    (found,) = suppression_resources(pairs)
    assert (found.name, dict(found.attrs)) == ("exc-exc-7", {
        "ciamFindingRef": ("gcp:scc:OPEN_FIREWALL", "gcp:scc:X"), "ciamExceptionRef": ("EXC-7",)})
