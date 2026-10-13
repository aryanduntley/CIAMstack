"""A rendered root partitioned among Terraform roots by the record entry each resource renders (5.7, decision 2732):
every root complete (its resources and imports, the providers, the data and variables it reads), a value read across
roots passed as an input variable the writing root outputs, the roots in the order they apply, a cycle refused."""
import pytest

from opsdir_format_terraform.hcl import TfBlock, comment, from_entry, hcl_item, tf_block, tf_import
from opsdir_format_terraform.translate import output_variable, parse_ref, partition

DBA, NET = "cn=db,ou=bindings", "cn=rt,ou=bindings"
PROVIDER = tf_block("provider", ["aws"], [("region", "${var.region}")])
TERRAFORM = tf_block("terraform", [], [("required_version", ">= 1.10")])
REGION = tf_block("variable", ["region"], [("type", "${string}")])
VPC = tf_block("data", ["aws_vpc", "main"], [("id", "vpc-1")])
SG = tf_block("resource", ["aws_security_group", "db"], [("vpc_id", "${data.aws_vpc.main.id}")])
DB = tf_block("resource", ["aws_db_instance", "grants"], [
    ("vpc_security_group_ids", ["${aws_security_group.db.id}"]), ("engine", "postgres")])
SERVER = tf_block("resource", ["aws_instance", "am_1"], [
    ("user_data", "db=${aws_db_instance.grants.address}"), ("depends_on", ["${aws_db_instance.grants}"])])
TABLE = tf_block("resource", ["aws_route_table", "rt"], [("vpc_id", "${data.aws_vpc.main.id}")])
ROOTS = {DBA: "terraform/landing-zone/dba", NET: "terraform/landing-zone/net"}


def _place(b):
    return ROOTS.get(b.origin)


def _items():
    return (TERRAFORM, PROVIDER, REGION, VPC, comment("the database's firewall"), *from_entry(DBA, (SG, DB)),
            tf_import("aws_db_instance.grants", "grants-db"), *from_entry(NET, (TABLE,)), SERVER, comment("end"))


def _names(items):
    return [hcl_item(x).splitlines()[0] for x in items]


def test_unstamped_items_are_one_root_unchanged():
    items = (TERRAFORM, PROVIDER, REGION, VPC, SG, DB, SERVER, comment("end"))
    p = partition(items, _place, "terraform")
    assert p.order == ("terraform",) and p.roots == {"terraform": items} and p.inputs == p.outputs == {}


def test_each_resource_goes_to_its_entry_s_root_with_its_import_comments_providers_and_the_data_it_reads():
    p = partition(_items(), _place, "terraform")
    dba = p.roots["terraform/landing-zone/dba"]
    assert _names(dba) == ['terraform {', 'provider "aws" {', 'variable "region" {', 'data "aws_vpc" "main" {',
                           "# the database's firewall", 'resource "aws_security_group" "db" {',
                           'resource "aws_db_instance" "grants" {', "import {",
                           'output "aws_db_instance_grants_address" {']
    net = p.roots["terraform/landing-zone/net"]
    assert _names(net) == ['terraform {', 'provider "aws" {', 'variable "region" {', 'data "aws_vpc" "main" {',
                           'resource "aws_route_table" "rt" {']


def test_a_value_another_root_writes_is_an_input_there_and_an_output_of_its_root():
    p = partition(_items(), _place, "terraform")
    ref = parse_ref("aws_db_instance.grants.address")
    assert p.inputs == {"terraform": (ref,)} and p.outputs == {"terraform/landing-zone/dba": (ref,)}
    stack = p.roots["terraform"]
    server = next(x for x in stack if isinstance(x, TfBlock) and x.kind == "resource")
    assert dict(server.body)["user_data"] == f"db=${{var.{output_variable(ref)}}}"
    assert "depends_on" not in dict(server.body)          # the order applies the database's root first
    assert _names(stack)[-2:] == ['# end', 'variable "aws_db_instance_grants_address" {']
    assert p.order.index("terraform/landing-zone/dba") < p.order.index("terraform")


def test_a_sensitive_value_is_marked_sensitive_on_both_sides():
    p = partition(_items(), _place, "terraform", sensitive=lambda r: r.attr == "address")
    out = p.roots["terraform/landing-zone/dba"][-1]
    var = p.roots["terraform"][-1]
    assert ("sensitive", True) in out.body and ("sensitive", True) in var.body


def test_a_root_with_only_providers_is_left_out():
    p = partition((TERRAFORM, PROVIDER, REGION, *from_entry(DBA, (DB._replace(body=(("engine", "postgres"),)),))),
                  _place, "terraform")
    assert p.order == ("terraform/landing-zone/dba",)


def test_roots_reading_each_other_are_refused():
    a = from_entry(DBA, (tf_block("resource", ["aws_s3_bucket", "a"], [("tag", "${aws_s3_bucket.b.arn}")]),))
    b = from_entry(NET, (tf_block("resource", ["aws_s3_bucket", "b"], [("tag", "${aws_s3_bucket.a.arn}")]),))
    with pytest.raises(ValueError, match="read each other's resources"):
        partition((PROVIDER, *a, *b), _place, "terraform")


def test_one_resource_placed_in_two_roots_is_refused():
    gateway = tf_block("resource", ["aws_vpn_gateway", "main"], [("vpc_id", "${data.aws_vpc.main.id}")])
    with pytest.raises(ValueError, match="placed in two roots: aws_vpn_gateway.main"):
        partition((PROVIDER, VPC, *from_entry(DBA, (gateway,)), *from_entry(NET, (gateway,))), _place, "terraform")


def test_an_input_named_like_a_variable_the_root_has_is_refused():
    clash = tf_block("variable", ["aws_db_instance_grants_address"], [("type", "${string}")])
    server = SERVER._replace(body=(*SERVER.body, ("tags", {"x": "${var.aws_db_instance_grants_address}"})))
    with pytest.raises(ValueError, match="named like a variable it has"):
        partition((PROVIDER, clash, *from_entry(DBA, (DB,)), server), _place, "terraform")


def test_stamping_marks_resources_and_imports_only_and_keeps_an_origin_already_set():
    stamped = from_entry(NET, (VPC, DB, tf_import("aws_db_instance.grants", "x"), comment("c"),
                               *from_entry(DBA, (SG,))))
    assert [getattr(x, "origin", None) for x in stamped] == [None, NET, NET, None, DBA]
    assert hcl_item(stamped[1]) == hcl_item(DB)           # the origin is never written


def test_an_entry_s_trailing_comments_stay_with_it_through_an_anchor_never_written():
    notes = from_entry(DBA, (comment("db: a note"),))
    assert [type(x).__name__ for x in notes] == ["tuple", "TfBlock"] and notes[1].origin == DBA
    p = partition((PROVIDER, *notes, SERVER._replace(body=(("ami", "ami-1"),))), _place, "terraform")
    assert p.roots["terraform/landing-zone/dba"][1:] == notes and comment("db: a note") not in p.roots["terraform"]
    assert hcl_item(notes[1]) == ""


def test_a_keeper_root_carries_the_files_it_reads_beside_it():
    from opsdir_format_terraform.hcl import TfFile
    from opsdir_format_terraform.placing import carried_files
    zipped = tf_block("data", ["archive_file", "c"], [("source_dir", "${path.module}/canaries/c"),
                                                      ("output_path", "${path.module}/.build/c.zip")])
    roots = {"terraform/main.tf": TfFile("", (zipped,)), "terraform/landing-zone/dba/main.tf": TfFile("", (zipped,))}
    files = {"terraform/canaries/c/python/canary.py": "x", "terraform/canaries/other/canary.py": "y"}
    assert carried_files(roots, files, "terraform") == {"terraform/landing-zone/dba/canaries/c/python/canary.py": "x"}
