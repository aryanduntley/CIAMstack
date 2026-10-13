"""The state builder: a root's blocks as `terraform apply` would record them, read back by read_state; what the
configuration doesn't say comes from the caller's assigned(), and what can't be evaluated is named, never guessed."""
import json

from opsdir_format_terraform.hcl import Block, TfBlock, TfFile, comment, jsonencoded, ref, tf_block, written
from opsdir_format_terraform.state import read_state
from opsdir_format_terraform.state_builder import root_states, synthetic, tf_state

TERRAFORM = TfBlock("terraform", (), (("required_providers", Block((("aws", {"source": "hashicorp/aws"}),))),))
VPC = TfBlock("data", ("aws_vpc", "main"), (("id", "vpc-1"),))
SG = TfBlock("resource", ("aws_security_group", "am"), (
    ("name", "ciam-prod-am"), ("vpc_id", ref("data.aws_vpc.main.id")), ("#", "a comment"),
    ("tags", {'"kubernetes.io/role"': "x", "ManagedBy": "opsdir"}), ("depends_on", (ref("aws_kms_key.disk"),)),
    ("ingress", Block((("from_port", 443), ("cidr_blocks", ("10.0.0.0/8",))))),
    ("ingress", Block((("from_port", 8443), ("cidr_blocks", ())))),
    ("lifecycle", Block((("ignore_changes", (ref("tags"),)),)))))
RULE = TfBlock("resource", ("aws_vpc_security_group_ingress_rule", "r"), (
    ("count", 2), ("security_group_id", ref("aws_security_group.am.id")), ("from_port", ref("count.index")),
    ("description", ref('"rule ${count.index} of ${aws_security_group.am.name} (${var.flag})"')),
    ("provider", ref("aws.copy_us_west_2"))))
POLICY = TfBlock("resource", ("aws_iam_policy", "p"), (
    ("policy", jsonencoded({"Version": "2012-10-17", "Statement": [{"Effect": "Allow"}]})),
    ("trust", jsonencoded({"Principal": {"Federated": "${aws_vpc_security_group_ingress_rule.r[0].id}"}})),
    ("first", ref("tolist(aws_vpc_security_group_ingress_rule.r[1].description)")),
    ("subnet", ref("tolist(data.aws_vpc.main.cidrs)[0]")), ("port", ref("tostring(var.port)"))))
VARIABLES = (TfBlock("variable", ("flag",), (("default", True),)),
             TfBlock("variable", ("port",), (("type", ref("number")),)))


def _instances(text):
    resources, problem = read_state(text)
    assert problem is None
    return {(r.mode, r.type, r.name): r.attributes for r in resources}, json.loads(text)


def test_configured_attributes_are_recorded_as_the_state_keeps_them():
    text, notices = tf_state((TERRAFORM, VPC, SG))
    found, _ = _instances(text)
    assert found[("managed", "aws_security_group", "am")] == {
        "id": "aws_security_group.am", "name": "ciam-prod-am", "vpc_id": "vpc-1",
        "tags": {"kubernetes.io/role": "x", "ManagedBy": "opsdir"},
        "ingress": [{"from_port": 443, "cidr_blocks": ["10.0.0.0/8"]}, {"from_port": 8443, "cidr_blocks": []}]}
    assert found[("data", "aws_vpc", "main")] == {"id": "vpc-1"} and notices == ()



def test_a_nested_block_named_like_a_meta_argument_is_an_attribute():
    """Meta-arguments are the resource's own: a backup rule's lifecycle block is configuration, recorded."""
    plan = TfBlock("resource", ("aws_backup_plan", "daily"), (
        ("rule", Block((("rule_name", "daily"), ("lifecycle", Block((("delete_after", 35),)))))),
        ("lifecycle", Block((("prevent_destroy", True),)))))
    found, _ = _instances(tf_state((plan,))[0])
    assert found[("managed", "aws_backup_plan", "daily")] == {
        "id": "aws_backup_plan.daily", "rule": [{"rule_name": "daily", "lifecycle": [{"delete_after": 35}]}]}

def test_counts_templates_variables_and_providers():
    text, notices = tf_state((TERRAFORM, VPC, SG, RULE, *VARIABLES))
    _, doc = _instances(text)
    (rules,) = [r for r in doc["resources"] if r["type"] == "aws_vpc_security_group_ingress_rule"]
    assert rules["provider"] == 'provider["registry.terraform.io/hashicorp/aws"].copy_us_west_2'
    assert [(i["index_key"], i["attributes"]) for i in rules["instances"]] == [
        (k, {"id": f"aws_vpc_security_group_ingress_rule.r[{k}]", "security_group_id": "aws_security_group.am",
             "from_port": k, "description": f"rule {k} of ciam-prod-am (true)"}) for k in (0, 1)]
    assert notices == ()


def test_what_the_provider_assigns_comes_from_the_caller_under_what_is_configured():
    def assigned(mode, type_, name, index, configured):
        return {**synthetic(mode, type_, name, index, configured), "arn": f"arn:{type_}:{name}",
                "cidrs": ["10.1.0.0/16"], "name": "never-wins"}
    text, notices = tf_state((VPC, SG, RULE, POLICY, *VARIABLES), assigned, {"port": 9031})
    found, _ = _instances(text)
    policy = found[("managed", "aws_iam_policy", "p")]
    assert policy["policy"] == '{"Statement":[{"Effect":"Allow"}],"Version":"2012-10-17"}'
    assert (policy["subnet"], policy["port"], policy["arn"]) == ("10.1.0.0/16", "9031", "arn:aws_iam_policy:p")
    assert policy["trust"] == '{"Principal":{"Federated":"aws_vpc_security_group_ingress_rule.r[0]"}}'
    assert found[("managed", "aws_security_group", "am")]["name"] == "ciam-prod-am"
    assert "first" not in policy and notices == ("aws_iam_policy.p.first: tolist of a str",)


def test_what_cannot_be_evaluated_is_left_out_and_named():
    elsewhere = TfBlock("resource", ("aws_instance", "x"), (
        ("subnet_id", ref("aws_subnet.elsewhere.id")), ("password", ref("ephemeral.random_password.p.result")),
        ("port", ref("var.port")), ("arn", ref("data.aws_vpc.main.arn")), ("odd", ref("a + b")),
        ("missing", ref("aws_vpc_security_group_ingress_rule.r[5].id")), ("kept", 1)))
    text, notices = tf_state((VPC, SG, RULE, elsewhere, *VARIABLES))
    found, _ = _instances(text)
    assert found[("managed", "aws_instance", "x")] == {"id": "aws_instance.x", "kept": 1}
    assert notices == (
        "aws_instance.x.subnet_id: no aws_subnet.elsewhere in this root",
        "aws_instance.x.password: ephemeral.* is not evaluated here (never in state)",
        "aws_instance.x.port: no value for var.port", "aws_instance.x.arn: data.aws_vpc.main has no arn",
        "aws_instance.x.odd: not evaluated: a + b",
        "aws_instance.x.missing: aws_vpc_security_group_ingress_rule.r: no instance 5")


def test_root_states_take_the_inputs_an_operator_gives():
    files = {"x/prod/terraform/main.tf": 'variable "start" {\n  type = string\n}\n\nresource "t_thing" "a" {\n'
                                         '  body = {\n    when = var.start\n  }\n}\n'}
    found = lambda states: read_state(states["x/prod/terraform.tfstate"])[0][0].attributes
    assert "body" not in found(root_states(files, "x/prod"))             # never guessed
    assert found(root_states(files, "x/prod", variables={"start": "now"}))["body"] == {"when": "now"}


def test_an_input_another_root_outputs_takes_its_value_through_a_chain_of_roots():
    lz = (tf_block("resource", ["t_gateway", "main"], [("name", "gw")]),
          tf_block("output", ["t_gateway_main_id"], [("value", ref("t_gateway.main.id"))]))
    team = (tf_block("variable", ["t_gateway_main_id"], [("type", ref("string"))]),
            tf_block("resource", ["t_link", "b"], [("gateway", ref("var.t_gateway_main_id"))]),
            tf_block("output", ["t_link_b_id"], [("value", ref("t_link.b.id"))]))
    slice_ = (tf_block("variable", ["t_link_b_id"], [("type", ref("string"))]),
              tf_block("resource", ["t_route", "r"], [("link", ref("var.t_link_b_id"))]))
    files = {"x/prod/terraform/zone/main.tf": TfFile("# lz\n", lz),         # named against the apply order
             "x/prod/terraform/team/main.tf": TfFile("# team\n", team),
             "x/prod/terraform/slice/main.tf": TfFile("# slice\n", slice_)}
    states = root_states(files, "x/prod")
    (link,) = read_state(states["x/prod/terraform-team.tfstate"])[0]
    (route,) = read_state(states["x/prod/terraform-slice.tfstate"])[0]
    assert link.attributes["gateway"] == "t_gateway.main" and route.attributes["link"] == "t_link.b"


def test_a_root_given_as_the_files_it_is_written_from_has_the_state_of_their_text():
    items = (tf_block("variable", ["region"], [("default", "eu-west-1")]), comment("NOTE: named, not rendered"),
             tf_block("resource", ["t_vpc", "main"], [("name", "main"), ("tags", {"Where": "${var.region}"})]),
             tf_block("resource", ["t_thing", "a"], [("vpc", ref("t_vpc.main.id")), ("arn", "x/${var.region}/a"),
                                                     ("ports", [443]), ("nested", Block((("on", True),)))]))
    head = TfFile("# Generated by opsdir\n", items)
    as_data = {"x/prod/terraform/main.tf": head, "x/prod/terraform/landing-zone/main.tf": TfFile("# lz\n", items[:3])}
    assert root_states(as_data, "x/prod") == root_states(written(as_data), "x/prod")
    (thing,) = (r for r in read_state(root_states(as_data, "x/prod")["x/prod/terraform.tfstate"])[0]
                if r.type == "t_thing")
    assert thing.attributes["arn"] == "x/eu-west-1/a"                    # a template string, as read from its text
