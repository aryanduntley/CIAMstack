"""AWS's rendered Terraform as the state applying it would record (the round trip, 5.5c): a block realizing a binding
the record holds gets that binding's provider reference as the importer reads it; other resources get AWS-shaped ids
and ARNs in the root's partition, region and account; tags_all carries the provider's default tags; the data sources
AWS answers from the account itself are answered."""
import json

from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_aws.rendered_state import REALIZES, provider_facts, reference_attributes, rendered_states
from opsdir_format_terraform.realized import realized
from opsdir_format_terraform.hcl import Block, TfBlock, block, ref
import mini_estate
from support import build_directory

ENV = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
EXTRA = "\n".join(
    f"dn: cn={cn},ou=bindings,{ENV}\nobjectClass: top\nobjectClass: {oc}\ncn: {cn}\nciamBindingRole: {role}\n"
    + (f"ciamProviderRef: {ref_}\n" if ref_ else "")
    for cn, oc, role, ref_ in (("rt-private", "ciamRouteTable", "routes-private", "rtb-0abc"),
                               ("fwd-corp-ad", "ciamDnsForwarder", "fwd-corp", "rslvr-rr-0001"),
                               ("guardduty", "ciamSecurityService", "threat-detection",
                                "arn:aws:guardduty:us-east-1:111122223333:detector/6ec9"),
                               ("inspector", "ciamSecurityService", "scanning", "inspector2:111122223333"),
                               ("acl-new", "ciamNetworkAcl", "acl-new", None)))
PROVIDER = TfBlock("provider", ("aws",), (
    ("region", "us-gov-west-1"), ("allowed_account_ids", ("111122223333",)),
    ("default_tags", Block((("tags", {"Owner": "ciam", "Environment": "alpha/prod"}),)))))


def _m():
    d = build_directory(mini_estate.REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + EXTRA)))
    return d, env_model(d, ENV)


def test_the_provider_block_gives_partition_region_account_and_default_tags():
    assert provider_facts((PROVIDER,)) == ("aws-us-gov", "us-gov-west-1", "111122223333",
                                           {"Owner": "ciam", "Environment": "alpha/prod"})
    assert provider_facts(())[0] == "aws"


def test_references_are_given_back_as_the_importer_reads_them():
    assert reference_attributes("arn:aws:guardduty:us-east-1:1:detector/6ec9") == {
        "arn": "arn:aws:guardduty:us-east-1:1:detector/6ec9", "id": "6ec9"}
    assert reference_attributes("inspector2:111122223333") == {"id": "111122223333"}
    assert reference_attributes("rtb-0abc") == {"id": "rtb-0abc"}


def test_a_block_realizes_the_binding_its_name_comes_from():
    _, m = _m()
    assert realized(m, REALIZES, "aws_route_table", "rt_private").dn.startswith("cn=rt-private,")
    assert realized(m, REALIZES, "aws_route53_resolver_rule", "fwd_corp_ad_0").dn.startswith("cn=fwd-corp-ad,")
    assert realized(m, REALIZES, "aws_subnet", "rt_private") is None          # not a type REALIZES knows
    assert realized(m, REALIZES, "aws_route_table", "rt_public") is None


def test_the_states_hold_the_records_references_and_what_aws_assigns():
    d, _ = _m()
    main = "\n\n".join(block(*b) for b in (
        PROVIDER, TfBlock("resource", ("aws_route_table", "rt_private"), (("tags", {"Role": "routes-private"}),)),
        TfBlock("resource", ("aws_guardduty_detector", "guardduty"), (("enable", True),)),
        TfBlock("resource", ("aws_network_acl", "acl_new"), ()),
        TfBlock("resource", ("aws_lb", "svc_sso"), (("name", "ciam-prod-svc-sso"),)),
        TfBlock("resource", ("aws_iam_openid_connect_provider", "gh"),
                (("url", "https://token.actions.githubusercontent.com"),)),
        TfBlock("resource", ("aws_route53_record", "sso"), (("alias", Block((("name", ref("aws_lb.svc_sso.dns_name")),
                                                                              ))),)),
        TfBlock("data", ("aws_partition", "current"), ()))) + "\n"
    states = rendered_states({"alpha/prod/main.tf": main, "alpha/prod/landing-zone/net.tf": block(*PROVIDER)}, d,
                             "alpha/prod")
    assert sorted(states) == ["alpha/prod/landing-zone.tfstate", "alpha/prod/terraform.tfstate"]
    found = {(r["mode"], r["type"]): r["instances"][0]["attributes"]
             for r in json.loads(states["alpha/prod/terraform.tfstate"])["resources"]}
    table = found[("managed", "aws_route_table")]
    assert (table["id"], table["tags_all"]) == ("rtb-0abc", {"Owner": "ciam", "Environment": "alpha/prod",
                                                             "Role": "routes-private"})
    assert found[("managed", "aws_guardduty_detector")]["arn"] == \
        "arn:aws:guardduty:us-east-1:111122223333:detector/6ec9"
    assert found[("managed", "aws_network_acl")]["id"] == "aws_network_acl.acl_new"      # designed, not created yet
    assert found[("managed", "aws_route53_record")]["alias"] == [{"name": "svc-sso-0.us-gov-west-1.elb.amazonaws.com"}]
    assert found[("managed", "aws_iam_openid_connect_provider")]["arn"] == \
        "arn:aws-us-gov:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
    assert found[("data", "aws_partition")]["partition"] == "aws-us-gov"
