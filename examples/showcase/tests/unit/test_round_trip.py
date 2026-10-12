"""Round trip (files >> db >> files): every environment of the synthetic estate, rendered as `opsdir render` writes it,
reads back through the adapters' own importers (Adapter.reads_back), before and after the approved changes. A
product's render is a projection of the record: it reads back without changing it. A cloud's is the record's intent
(ReadBack.intent): it reads back as the bindings it came from (no copies), what applying it would record where the
record still holds what was observed, and rendering again gives the same files (decision on milestone 89). What an
importer withholds (secrets) is in its notices, never a change."""
import pytest

from opsdir.connectors.registry import ADAPTERS, environment, environment_specs, services
from opsdir.connectors.render import render_parts
from opsdir.connectors.roundtrip import fixed_point, read_back, round_trip
from opsdir_adapter_aws.terraform import render_files as aws
from opsdir_adapter_azure.terraform import render_files as azure
from opsdir_adapter_gcp.terraform import render_files as gcp

# The cloud renderers' Terraform as data (milestone 5.5d): what each adapter's render() writes as text
AS_DATA = {"aws": aws, "azure": azure, "gcp": gcp}

INTENT = {f"{a.name}/{rb.importer}" for a in ADAPTERS for rb in a.reads_back if rb.intent}
# What a render can't express yet, so reading it back drops it: (DN, attribute) -> why
KNOWN = {("cn=cloudtrail,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops", "ciamAuditEvents"):
         "CloudTrail data events aren't rendered yet (milestone 5.7, note 1950): the trail renders control-plane only"}


@pytest.mark.parametrize("state", ["before", "after"])
def test_every_environment_reads_back_unchanged(estate, state):
    d = estate[state]
    trips = {spec: round_trip(d, spec) for spec in environment_specs(d)}
    changed = [(spec, rt.importer, [(c.changetype, c.dn) for c in (rt.drift if rt.importer in INTENT else rt.changes)])
               for spec, rts in trips.items() for rt in rts if (rt.drift if rt.importer in INTENT else rt.changes)]
    unread = [(spec, rt.importer, rt.notices) for spec, rts in trips.items() for rt in rts if not rt.files]
    assert (changed, unread) == ([], [])


@pytest.mark.parametrize("state", ["before", "after"])
def test_every_environment_render_is_a_fixed_point(estate, state):
    """What the read-backs record leaves every environment's render as it was."""
    d = estate[state]
    assert {spec: fixed_point(d, spec, known=KNOWN) for spec in environment_specs(d)} == \
        {spec: () for spec in environment_specs(d)}


def test_every_declared_read_back_runs_somewhere(estate):
    """Each read-back declared by an installed adapter that applies to an environment of the estate is exercised
    (optional ones included: the estate renders what they read somewhere, the native ones when a render chooses that
    form), so a passing round trip is never vacuous."""
    d = estate["after"]
    applying = {f"{a.name}/{rb.importer}" for spec in environment_specs(d) for a in environment(d, spec)[1]
                for rb in a.reads_back}
    exercised = {rt.importer for spec in environment_specs(d)
                 for wanted in (None, *({cloud: (target,)} for cloud, (target, _) in NATIVE.items()
                                        if cloud in {a.name for a in environment(d, spec)[1]}))
                 for rt in round_trip(d, spec, wanted=wanted)}
    declared = {f"{a.name}/{rb.importer}" for a in ADAPTERS for rb in a.reads_back}
    assert applying and exercised == applying <= declared


@pytest.mark.parametrize("state", ["before", "after"])
def test_a_cloud_render_reads_back_the_same_from_its_blocks_as_from_its_text(estate, state):
    """The round trip run on the renderers' blocks directly (each .tf file's TfFile, before any text is written)
    agrees with the one run on the text they write (5.5d): same files, changes, notices and drift."""
    d, found = estate[state], services(ADAPTERS)
    compared = []
    for spec in environment_specs(d):
        m, adapters, _, specific, _ = render_parts(d, spec)
        for a in (a for a in adapters if a.name in AS_DATA):
            data = {p: f for p, f in AS_DATA[a.name](m, found).items() if p.endswith(".tf") and p in specific}
            assert data, f"{spec}: {a.name} rendered no Terraform"
            compared.append((spec, a.name))
            assert read_back(m.d, a, {**specific, **data}, ADAPTERS, None, spec) == \
                read_back(m.d, a, specific, ADAPTERS, None, spec)
    assert {cloud for _, cloud in compared} == set(AS_DATA)


# Each cloud's native render (5.6c): its render target and the importer reading it back
NATIVE = {"aws": ("cloudformation", "aws/cloudformation"), "azure": ("arm", "azure/arm")}
# Where a native read-back still sees the showcase differently from the Terraform read-back of the same record:
# (environment, which read-back alone records it, the change ('add', 'modify': its attributes) or 'unreported' (the
# binding is in the record but not in what was read), the binding's cn, attributes). The native readers' gaps, closed
# by milestone 5.6c's tasks (c) AWS, (d) Azure, (e) the CLI: IAM grants, guardrails, the CDN/WAF edge, security
# services and egress on AWS; managed identities, WAF policies and the edge, alerts, flow logs, private zones, budgets
# and exemptions on Azure, PostgreSQL's size and deletion protection as ARM writes them.
NATIVE_GAPS = {
    ('source/prod', 'native only', 'unreported', 'config', ()),
    ('source/prod', 'native only', 'unreported', 'egress-pf', ()),
    ('source/prod', 'native only', 'unreported', 'guardduty', ()),
    ('source/prod', 'native only', 'unreported', 'security-hub', ()),
    ('source/prod', 'terraform only', 'unreported', 'ds-disk-free', ()),
    ('source/stage', 'terraform only', 'unreported', 'pf-discovery', ()),
    ('target/prod', 'native only', 'modify', 'psql-ciam-prod-pf-grants',
     ('ciamDbDeletionProtection', 'ciamInstanceSize')),
    ('target/prod', 'native only', 'modify', 'psql-ciam-prod-pf-grants', ('ciamInstanceSize',)),
    ('target/prod', 'native only', 'unreported', 'identity-ci', ()),
    ('target/prod', 'native only', 'unreported', 'identity-ds', ()),
    ('target/prod', 'native only', 'unreported', 'identity-pf', ()),
    ('target/prod', 'native only', 'unreported', 'snet-aks', ()),
    ('target/prod', 'native only', 'unreported', 'snet-edge', ()),
    ('target/prod', 'native only', 'unreported', 'svc-apps', ()),
    ('target/prod', 'native only', 'unreported', 'svc-login', ()),
    ('target/prod', 'native only', 'unreported', 'svc-sso', ()),
    ('target/prod', 'terraform only', 'add', 'waf-ciam-prod-svc_login', ()),
    ('target/prod', 'terraform only', 'add', 'waf-ciam-prod-svc_sso', ()),
    ('target/prod', 'terraform only', 'modify', 'ds-replication-lag', ('ciamNotifies',)),
    ('target/prod', 'terraform only', 'modify', 'exc-EXC-2026-03', ('ciamProviderRef',)),
    ('target/prod', 'terraform only', 'modify', 'flow-vnet', ('ciamProviderRef',)),
    ('target/prod', 'terraform only', 'modify', 'identity-ci', ('ciamGrant', 'ciamIdentityClientId')),
    ('target/prod', 'terraform only', 'modify', 'identity-ds', ('ciamGrant', 'ciamIdentityClientId')),
    ('target/prod', 'terraform only', 'modify', 'identity-pf', ('ciamGrant', 'ciamIdentityKind', 'ciamTrustedBy')),
    ('target/prod', 'terraform only', 'modify', 'monthly-spend', ('ciamProviderRef',)),
    ('target/prod', 'terraform only', 'modify', 'svc-apps', ('ciamEdgeFact', 'ciamExposure')),
    ('target/prod', 'terraform only', 'modify', 'svc-login', ('ciamEdgeFact', 'ciamExposure')),
    ('target/prod', 'terraform only', 'modify', 'svc-sso', ('ciamEdgeFact', 'ciamExposure')),
    ('target/prod', 'terraform only', 'modify', 'zone-private', ('ciamProviderRef',)),
    ('target/prod', 'terraform only', 'unreported', 'defender-identity', ()),
    ('target/prod', 'terraform only', 'unreported', 'pf-login-failures', ()),
    ('target/prod', 'terraform only', 'unreported', 'resource-changes', ()),
    ('target/prod', 'terraform only', 'unreported', 'zone-public', ()),
}


def _facts(trips, importer):
    """What a read-back records: its changes and the bindings it says the cloud doesn't report."""
    rts = [rt for rt in trips if rt.importer == importer]
    return ({(c.changetype, c.dn.split(",", 1)[0][3:], tuple(sorted({m[1] for m in c.mods}))
              if c.changetype == "modify" else ()) for rt in rts for c in rt.changes} |
            {("unreported", n.split(": ", 1)[1].split(" (")[0], ()) for rt in rts for n in rt.notices
             if "is in the record but not in what" in n})


@pytest.mark.parametrize("state", ["before", "after"])
def test_a_render_chosen_in_a_native_form_reads_back_through_its_native_importer(estate, state):
    """A cloud environment rendered only as CloudFormation or Bicep/ARM holds no terraform/*.tf (that read-back reads
    nothing and says so); its native importer reads the templates and the Terraform root kept beside them, as applying
    them would record, with no drift."""
    d = estate[state]
    for spec in environment_specs(d):
        for cloud, (target, importer) in NATIVE.items():
            if cloud in {a.name for a in render_parts(d, spec)[1]}:
                trips = {rt.importer: rt for rt in round_trip(d, spec, wanted={cloud: (target,)})}
                assert trips[f"{cloud}/terraform-state"].notices == ("nothing rendered matches terraform/*.tf",)
                assert trips[importer].files and trips[importer].drift == (), (spec, importer)


def test_native_read_backs_differ_from_the_terraform_ones_only_by_the_known_gaps(estate):
    found = set()
    for d in estate.values():
        for spec in environment_specs(d):
            for cloud, (target, importer) in NATIVE.items():
                if cloud in {a.name for a in render_parts(d, spec)[1]}:
                    t = _facts(round_trip(d, spec, wanted={cloud: ("terraform",)}), f"{cloud}/terraform-state")
                    n = _facts(round_trip(d, spec, wanted={cloud: (target,)}), importer)
                    found |= {(spec, "terraform only", *x) for x in t - n} | {(spec, "native only", *x) for x in n - t}
    assert found == NATIVE_GAPS
