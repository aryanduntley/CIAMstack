"""Terraform data read for translation: references parsed from expressions and string templates, roots found among an
adapter's files, and a root split into what another language writes and the Terraform root kept beside it."""
import pytest

from opsdir_format_terraform.hcl import Block, TfFile, comment, ref, tf_block, tf_import
from opsdir_format_terraform.translate import (Raw, TfRef, address, before_note, expression_refs, no_native_note,
                                               output_variable, parse_ref, ref_address, ref_text, root_items, roots,
                                               split_root, template_parts, value_refs)

VPC_ID = TfRef("data", "aws_vpc", "main", "id")
BUCKET_ARN = TfRef("resource", "aws_s3_bucket", "logs", "arn")


@pytest.mark.parametrize("text, expected", [
    ("aws_security_group.ds.id", TfRef("resource", "aws_security_group", "ds", "id")),
    ("data.aws_vpc.main.id", VPC_ID),
    ("var.region", TfRef("var", "", "region", "")),
    ("path.module", TfRef("path", "", "module", "")),
    ("tolist(data.aws_ssoadmin_instances.sso.arns)[0]", None),
    ("aws_instance.ds[0].private_ip", TfRef("resource", "aws_instance", "ds", "[0].private_ip")),
    ("aws_iam_role.r", TfRef("resource", "aws_iam_role", "r", "")),
    ("x.id", None), ("true", None), ("10", None)])
def test_a_single_reference_is_parsed(text, expected):
    assert parse_ref(text) == expected
    assert expected is None or ref_text(expected) == text


def test_an_expression_names_its_references_not_its_functions_keys_or_symbols():
    text = ('jsonencode({ Statement = [{ Resource = "${aws_s3_bucket.logs.arn}/*", Principal = var.principal }] }) '
            '+ length([for s in data.aws_subnets.all.ids : s.id]) + contains(self.names, "x")')
    assert expression_refs(text) == (BUCKET_ARN, TfRef("var", "", "principal", ""),
                                     TfRef("data", "aws_subnets", "all", "ids"), TfRef("self", "", "names", ""))


def test_a_string_is_parts_as_hcl_writes_it():
    assert template_parts(ref("data.aws_vpc.main.id")) == (VPC_ID,)
    assert template_parts("arn:${data.aws_partition.current.partition}:s3:::b/*") == (
        "arn:", TfRef("data", "aws_partition", "current", "partition"), ":s3:::b/*")
    assert template_parts("plain") == ("plain",)
    assert template_parts(ref('jsonencode({a = "${var.x}"})')) == (
        Raw('jsonencode({a = "${var.x}"})', (TfRef("var", "", "x", ""),)),)
    with pytest.raises(ValueError, match="unclosed"):
        template_parts("a ${var.x")


def test_values_name_their_references_through_blocks_lists_and_objects():
    body = (("vpc_id", ref("data.aws_vpc.main.id")), ("ingress", Block((("cidr", ["${var.cidr}", "10.0.0.0/8"]),))),
            ("tags", {"Name": "x-${var.env}"}), ("count", 2), ("again", ref("data.aws_vpc.main.id")))
    assert value_refs(body) == (VPC_ID, TfRef("var", "", "cidr", ""), TfRef("var", "", "env", ""))


def test_addresses_of_blocks_and_of_what_references_read():
    assert [address(b) for b in (tf_block("resource", ["aws_vpc", "a"], []), tf_block("data", ["aws_vpc", "b"], []),
                                 tf_block("variable", ["region"], []), tf_block("provider", ["aws"], []),
                                 comment("x"))] == ["aws_vpc.a", "data.aws_vpc.b", "var.region", None, None]
    assert [ref_address(r) for r in (BUCKET_ARN, VPC_ID, TfRef("var", "", "x", ""), TfRef("path", "", "module", ""))] \
        == ["aws_s3_bucket.logs", "data.aws_vpc.main", "var.x", None]


def test_roots_are_directories_of_terraform_data_in_path_order():
    main, providers = TfFile("", (comment("a"),)), TfFile("", (comment("b"),))
    found = roots({"tf/main.tf": main, "tf/providers.tf": providers, "tf/lz/main.tf": main, "tf/x.zip.txt": "text"})
    assert found == {"tf": (("tf/main.tf", main), ("tf/providers.tf", providers)), "tf/lz": (("tf/lz/main.tf", main),)}
    assert root_items(found["tf"]) == (comment("a"), comment("b"))


TERRAFORM = tf_block("terraform", [], [("required_version", ">= 1.6")])
PROVIDER = tf_block("provider", ["aws"], [("region", ref("var.region"))])
REGION = tf_block("variable", ["region"], [])
UNUSED = tf_block("variable", ["unused"], [])
VPC = tf_block("data", ["aws_vpc", "main"], [("id", ref("var.vpc"))])
VPC_VAR = tf_block("variable", ["vpc"], [])
BUCKET = tf_block("resource", ["aws_s3_bucket", "logs"], [("bucket", "logs")])
SG = tf_block("resource", ["aws_security_group", "ds"], [("vpc_id", ref("data.aws_vpc.main.id"))])
EXPORT = tf_block("resource", ["aws_macie2_classification_export_configuration", "e"], [
    ("s3_destination", Block((("bucket_name", ref("aws_s3_bucket.logs.id")),
                              ("key_prefix", "${aws_s3_bucket.logs.bucket}/macie"),
                              ("in_vpc", ref("data.aws_vpc.main.id"))))),
    ("depends_on", [ref("aws_s3_bucket.logs")])])
ENABLER = tf_block("resource", ["aws_inspector2_enabler", "i"], [("resource_types", ["EC2"]),
                                                                  ("depends_on", [ref("aws_s3_bucket.logs")])])
ITEMS = (TERRAFORM, PROVIDER, REGION, UNUSED, VPC_VAR, VPC, comment("buckets"), BUCKET, comment("security groups"), SG,
         comment("macie export"), EXPORT, ENABLER, tf_import("aws_inspector2_enabler.i", "123"),
         tf_import("aws_s3_bucket.logs", "logs"), comment("end"))
NO_NATIVE = {"aws_macie2_classification_export_configuration", "aws_inspector2_enabler"}


def native(b):
    return b.labels[0] not in NO_NATIVE


def test_a_root_whose_resources_all_have_a_native_form_is_written_whole():
    split = split_root(ITEMS, lambda b: True)
    assert split.native == ITEMS and split.side == () and split.outputs == () and split.unresolved == ()


def test_resources_with_no_native_form_stay_in_a_terraform_root_reading_the_templates_outputs():
    split = split_root(ITEMS, native)
    assert split.native == (TERRAFORM, PROVIDER, REGION, UNUSED, VPC_VAR, VPC, comment("buckets"), BUCKET,
                            comment("security groups"), SG, tf_import("aws_s3_bucket.logs", "logs"), comment("end"))
    bucket_id, bucket_name = (TfRef("resource", "aws_s3_bucket", "logs", a) for a in ("id", "bucket"))
    assert split.outputs == (bucket_id, bucket_name)
    assert [output_variable(r) for r in split.outputs] == ["aws_s3_bucket_logs_id", "aws_s3_bucket_logs_bucket"]
    export = tf_block("resource", ["aws_macie2_classification_export_configuration", "e"], [
        ("s3_destination", Block((("bucket_name", ref("var.aws_s3_bucket_logs_id")),
                                  ("key_prefix", "${var.aws_s3_bucket_logs_bucket}/macie"),
                                  ("in_vpc", ref("data.aws_vpc.main.id")))))])
    enabler = tf_block("resource", ["aws_inspector2_enabler", "i"], [("resource_types", ["EC2"])])
    assert split.side[:8] == (TERRAFORM, PROVIDER, REGION, VPC_VAR, VPC, comment("macie export"), export, enabler)
    assert split.side[8] == tf_import("aws_inspector2_enabler.i", "123")
    assert [address(b) for b in split.side[9:]] == ["var.aws_s3_bucket_logs_id", "var.aws_s3_bucket_logs_bucket"]
    assert split.unresolved == ()
    assert no_native_note(split, "AWS CloudFormation") == (
        "# AWS CloudFormation has no form for these resources; this Terraform root manages them, applied after "
        "the template, its variables taking the template's outputs:\n"
        "#   aws_macie2_classification_export_configuration.e\n#   aws_inspector2_enabler.i\n")


def test_a_native_resource_reading_one_that_stays_terraform_is_unresolved():
    reader = tf_block("resource", ["aws_s3_bucket_policy", "p"], [("bucket", ref("aws_inspector2_enabler.i.id"))])
    split = split_root((*ITEMS, reader), native)
    assert split.unresolved == (("aws_s3_bucket_policy.p", TfRef("resource", "aws_inspector2_enabler", "i", "id")),)


def test_a_resource_the_template_reads_may_be_applied_before_it_in_a_root_outputting_what_it_reads():
    bundle = tf_block("resource", ["aws_s3_object", "bundle"], [("bucket", "b"), ("key", "trust/x.pem")])
    store = tf_block("resource", ["aws_lb_trust_store", "x"], [("ca_certificates_bundle_s3_key",
                                                                 ref("aws_s3_object.bundle.key"))])
    items = (TERRAFORM, PROVIDER, REGION, comment("the bundle"), bundle, store, tf_import("aws_s3_object.bundle", "b"))
    split = split_root(items, lambda b: b.labels[0] != "aws_s3_object", lambda b: b.labels[0] == "aws_s3_object")
    key = TfRef("resource", "aws_s3_object", "bundle", "key")
    assert split.unresolved == () and split.side == () and split.inputs == (key,)
    assert split.before[:6] == (TERRAFORM, PROVIDER, REGION, comment("the bundle"), bundle,
                                tf_import("aws_s3_object.bundle", "b"))
    assert split.before[6:] == (tf_block("output", [output_variable(key)], [("value", "${aws_s3_object.bundle.key}")]),)
    assert split.native == (TERRAFORM, PROVIDER, REGION, store)
    assert before_note(split, "AWS CloudFormation", {"aws_s3_object.bundle": "no type"}) == (
        "# The AWS CloudFormation template reads these resources, which stay Terraform; this root manages them, "
        "applied BEFORE the template, its outputs the template's parameters:\n#   aws_s3_object.bundle: no type\n")
    without = split_root(items, lambda b: b.labels[0] != "aws_s3_object")
    assert without.before == () and without.unresolved == (("aws_lb_trust_store.x", key),)
