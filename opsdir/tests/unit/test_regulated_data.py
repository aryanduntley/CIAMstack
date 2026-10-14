"""Regulated data (core estate, 5.7b i): what an environment holds by regime (ITAR, EAR, CJIS, HIPAA, IRS 1075), on the
environment and brought by its reporting obligations; the source's carried to the target (else a blocker); what
export-controlled data asks of the customer whatever the cloud and the restricted classification (actions); an
environment holding it must rely on an authorization; the report; the adapters' verdicts as findings."""
from opsdir.core.findings import findings
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.domains.estate.authorizations import check_authorization, check_regulated_data
from opsdir.domains.estate.regulated import placement_findings, regulated_data, regulated_rows, regulated_sources
from network_fixtures import ALPHA, BETA, context, model

OBLIGATIONS = "ou=reporting-obligations,dc=ciam-ops"
TREE = ("dn: ou=reporting-obligations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\n"
        "ou: reporting-obligations\n",
        f"dn: cn=dfars-7012,{OBLIGATIONS}\nobjectClass: top\nobjectClass: ciamReportingObligation\ncn: dfars-7012\n"
        "ciamReportingHours: 72\nciamRegulatedData: ear\n")


def holds(env, data=(), obligation=False, met=(), classification=None):
    return LdifRecord(env, "modify", {}, (
        ("add", "objectClass", ("ciamEnvironmentPlacement",)),
        *((("replace", "ciamRegulatedData", tuple(data)),) if data else ()),
        *((("replace", "ciamReportingObligationRef", (f"cn=dfars-7012,{OBLIGATIONS}",)),) if obligation else ()),
        *((("replace", "ciamConfigurationMet", tuple(met)),) if met else ()),
        *((("replace", "ciamDataClassification", (classification,)),) if classification else ())))


def _ctx(*changes):
    d, a, b = model(tree=TREE, changes=changes)
    return context(d, a, b, cutover="2026-12-01"), d


def test_nothing_when_neither_environment_holds_regulated_data():
    assert check_regulated_data(_ctx()[0]) == findings()


def test_an_obligation_brings_regulated_data_and_the_report_says_where_from():
    ctx, d = _ctx(holds(ALPHA, ("itar", "cjis"), obligation=True))
    assert regulated_data(ctx.src) == ("itar", "ear", "cjis")                 # REGULATED_DATA order
    assert regulated_sources(ctx.src, "ear") == ("dfars-7012",)
    assert regulated_sources(ctx.src, "itar") == ("environment",)
    assert [r[:3] for r in regulated_rows(d)] == [("alpha/prod", "itar", "environment"),
                                                  ("alpha/prod", "ear", "dfars-7012"),
                                                  ("alpha/prod", "cjis", "environment")]


def test_the_source_s_regulated_data_the_target_doesn_t_record_blocks_the_move():
    ctx, _ = _ctx(holds(ALPHA, ("itar", "hipaa")), holds(BETA, ("hipaa",), classification="restricted"))
    assert [b[1] for b in check_regulated_data(ctx).blockers] == [
        "alpha/prod holds itar data and beta/prod doesn't record it (ciamRegulatedData): record what the target will "
        "hold, so the planner checks where it may be held."]


def test_export_controlled_data_asks_for_us_location_and_us_persons_and_a_restricted_classification():
    ctx, _ = _ctx(holds(BETA, ("itar",), met=("us-data-location",), classification="confidential"))
    f = check_regulated_data(ctx)
    assert [a[1] for a in f.actions] == [
        "beta/prod holds itar data and doesn't record us-person-support (ciamConfigurationMet): export-controlled "
        "technical data stays in the US and only US persons, or those an export authorization covers, may reach it; "
        "that is the customer's to configure, whatever the cloud.",
        "beta/prod holds itar data and its data is classified confidential: classify it restricted "
        "(ciamDataClassification)."]
    assert {a[3] for a in f.actions} == {"2026-12-01"}
    ok = check_regulated_data(_ctx(holds(BETA, ("itar",), met=("us-data-location", "us-person-support"),
                                         classification="restricted"))[0])
    assert ok.ok == ("beta/prod records the itar data it holds and what it needs in place.",) and not ok.actions


def test_an_environment_holding_regulated_data_must_rely_on_an_authorization():
    ctx, _ = _ctx(holds(BETA, ("cjis",)))
    assert check_authorization(ctx).blockers[0][1] == (
        "beta/prod relies on no cloud authorization while it holds cjis data: record the authorization of the "
        "offering it runs on (ciamAuthorizationRef).")


def test_an_adapter_s_verdicts_become_findings_for_the_target():
    ctx, _ = _ctx()
    f = placement_findings(ctx, (("itar", "blocker", "not here."), ("hipaa", "action", "sign the BAA.")))
    assert [b[1] for b in f.blockers] == ["beta/prod holds itar data: not here."]
    assert [(a[1], a[3]) for a in f.actions] == [("beta/prod holds hipaa data: sign the BAA.", "2026-12-01")]
