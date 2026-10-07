"""The estate domain's tag policy: which tags every resource rendered for an environment carries and the value each
takes there (owner, the owner's cost center, data classification, environment, cloud, literal); a tag an environment
can give no value is a planner action; the tags report; import notices for reported resources that lack a required
tag, run by every import through the domains' import checks."""
from opsdir.core.inventory import environment_groups, resource
from opsdir.domains.estate.checks import check_tags
from opsdir.domains.estate.reports import tag_rows
from opsdir.domains.estate.tags import missing_tags, required_tags, tag_notices
from estate_fixtures import estate as _pair, rule as _rule


def test_the_tags_an_environment_s_resources_carry():
    _, d, alpha, beta = _pair()
    assert required_tags(alpha) == {"Cloud": "alpha", "CostCenter": "CC-1234", "DataClass": "confidential",
                                    "Environment": "alpha/prod", "Estate": "example", "Owner": "platform"}
    assert [(r.dn.split(",")[0], why) for r, why in missing_tags(beta)] == [
        ("cn=classification", "beta/prod has no data classification (ciamDataClassification)")]


def test_a_tag_without_a_value_is_an_action_and_shows_in_the_report():
    ctx, d, *_ = _pair(cost_center=None)
    texts = [a[1] for a in check_tags(ctx).actions]
    assert texts == [
        "Tag `CostCenter` (tag rule cost-center) has no value in alpha/prod: alpha/prod's owner platform has no cost "
        "center (ciamCostCenter). Resources rendered for it go without the tag.",
        "Tag `CostCenter` (tag rule cost-center) has no value in beta/prod: beta/prod's owner platform has no cost "
        "center (ciamCostCenter). Resources rendered for it go without the tag.",
        "Tag `DataClass` (tag rule classification) has no value in beta/prod: beta/prod has no data classification "
        "(ciamDataClassification). Resources rendered for it go without the tag."]
    rows = tag_rows(d)
    assert ("beta/prod", "DataClass", "classification",
            "none: beta/prod has no data classification (ciamDataClassification)") in rows
    assert ("alpha/prod", "Owner", "owner", "platform") in rows
    assert tag_rows(_pair(rules=())[1]) == []


def test_import_notices_name_resources_without_a_required_tag():
    _, d, *_ = _pair()
    tagged = {"Owner": "platform", "CostCenter": "CC-1234", "DataClass": "internal", "Environment": "alpha/prod",
              "Cloud": "alpha", "Estate": "example"}
    resources = (resource("server", "i-1", name="ds-1", tags=tagged),
                 *(resource("server", f"i-{n}", name=f"ds-{n}", tags={"Role": "ds"}) for n in range(2, 7)),
                 resource("secret", "arn:1", name="no-tags-known"))            # the source gives no tags: not judged
    notices = tag_notices(d, "alpha/prod", resources)
    assert notices == ("alpha/prod: 5 resource(s) lack the required tags Cloud, CostCenter, DataClass, Environment, "
                       "Estate, Owner (server ds-2, server ds-3, server ds-4 and 2 more)",)
    assert tag_notices(d, "alpha/prod", resources[:1]) == ()
    assert tag_notices(d, "alpha/prod", (resource("server", "i-8", name="ds-8", tags={k: v for k, v in tagged.items()
                                                                                    if k != "Owner"}),)) == (
        "alpha/prod: 1 resource(s) lack the required tag Owner (server ds-8)",)


def test_an_import_runs_the_domains_import_checks_on_what_it_places():
    _, d, *_ = _pair(rules=(_rule("owner", "Owner", "owner"),))
    reported = (resource("server", "i-1", {"ciamHostname": "ds-1.example.test"}, name="ds-1", role="ds",
                         tags={"Role": "ds"}),
                resource("server", "i-9", {"ciamHostname": "elsewhere.example.test"}, name="stray", tags={}))
    _, notices = environment_groups(d, "alpha/prod", reported)
    assert "alpha/prod: 1 resource(s) lack the required tag Owner (server ds-1)" in notices   # the stray isn't placed
    assert not any("stray" in n for n in notices if "required tag" in n)
