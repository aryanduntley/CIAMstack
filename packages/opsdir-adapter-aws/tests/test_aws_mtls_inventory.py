"""Client certificates checked at an ALB, read back (milestone 122, task 585): the render of an edge trust policy reads
back through Terraform state with no change and nothing said; a listener that stops verifying, verifies with another
trust store, or a trust store whose CA certificates differ from the policy's bundle (by SHA-256) is an import notice;
a CloudFormation stack and the AWS CLI's outputs (describe-listeners' MutualAuthentication, describe-trust-stores) read
the same, the CLI comparing only the number of CA certificates and saying so; the collector lists the trust stores
only where the record has an edge trust policy. A CloudFormation render (task 591) keeps the bundle object in the
Terraform root applied before the template, passes cfn-lint in us-east-1 and us-gov-west-1, and reads back clean."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from opsdir.connectors.registry import ADAPTERS
from opsdir.connectors.roundtrip import read_back
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import written
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.cli import read_cli_inventory
from opsdir_adapter_aws.cloudformation import read_cloudformation, read_document
from opsdir_adapter_aws.collect import inventory_steps
from opsdir_adapter_aws.inventory import read_terraform_state
from opsdir_adapter_aws.mtls_inventory import bundle_fingerprints
from opsdir_adapter_aws.rendered_state import rendered_stacks, rendered_states
from opsdir_adapter_aws.terraform import render, render_files
from network_fixtures import ALPHA, entry, model
from pki_samples import CA_FINGERPRINT, CA_PEM, edge_trust_records

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
ACCOUNT = "111122223333"
LB = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/ciam-prod-svc-sso/0a1b"
STORE = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:truststore/ciam-prod-cac-users/0c1d"
OTHER_PEM = CA_PEM.replace("MIIBtDCC", "MIIBtDCD")
LINT = Path(__file__).resolve().parents[3] / "tools" / "cfn-lint" / "venv" / "bin" / "cfn-lint"
TERMINATE = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))
BUCKET = entry(ALPHA, "trust-bucket", "ciamObjectStore", ciamBindingRole="trust-store",
               ciamStorageRef="s3://ciam-trust/pki")


def _alpha(trust=True, region="us-east-1"):
    aws = LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                           ("replace", "ciamRegion", (region,)),
                                           ("replace", "ciamCloudProvider", ("aws",)),
                                           ("replace", "ciamAccountRef", (ACCOUNT,))))
    vpc = LdifRecord(f"cn=net,ou=bindings,{ALPHA}", "modify", {}, (("replace", "ciamProviderRef", ("vpc-0abc",)),))
    _, alpha, _ = model(alpha=(BUCKET,), tree=(*(edge_trust_records(CA_PEM) if trust else ()), *TERMINATE),
                        changes=(aws, vpc))
    return alpha


def _states(m):
    files = {f"alpha/prod/{p[len('terraform/'):]}": t for p, t in written(render_files(m, None)).items()}
    return rendered_states(files, m.d, "alpha/prod")


def _changed(states, type_, change):
    doc = json.loads(states["alpha/prod/terraform.tfstate"])
    for r in doc["resources"]:
        if r["type"] == type_:
            r["instances"][0]["attributes"] = change(r["instances"][0]["attributes"])
    return {**states, "alpha/prod/terraform.tfstate": json.dumps(doc)}


def _mtls(notices):
    return [n for n in notices if "trust store" in n or "mutual TLS" in n]


# ------------------------------------------------------------------ Terraform state
def test_the_render_of_an_edge_policy_reads_back_with_no_change_and_nothing_said():
    m = _alpha()
    files = {p: t for p, t in written(render_files(m, None)).items()}
    assert 'mode            = "verify"' in files["terraform/main.tf"]
    (trip,) = read_back(m.d, ADAPTER, files, ADAPTERS, None, "alpha/prod")
    assert trip.drift == () and _mtls(trip.notices) == []
    assert _mtls(read_terraform_state(_states(m), m.d, ()).notices) == []


def test_a_listener_that_stops_verifying_is_named():
    m = _alpha()
    off = _changed(_states(m), "aws_lb_listener", lambda a: {**a, "mutual_authentication": [{"mode": "off"}]})
    passed = _changed(_states(m), "aws_lb_listener", lambda a: {**a, "mutual_authentication": [
        {"mode": "passthrough"}]})
    (n,) = _mtls(read_terraform_state(off, m.d, ()).notices)
    assert n.startswith("alpha/prod: ciam-prod-svc-sso listener 443 (sso.example.test, trust policy cac-users) "
                        "checks no client certificate (mutual TLS off)")
    (n,) = _mtls(read_terraform_state(passed, m.d, ()).notices)
    assert "passes client certificates on unchecked (mutual TLS passthrough)" in n and "render and apply" in n


def test_another_trust_store_is_named():
    m = _alpha()
    other = _changed(_states(m), "aws_lb_trust_store", lambda a: {**a, "tags": {"TrustPolicy": "contractors"}})
    (n,) = _mtls(read_terraform_state(other, m.d, ()).notices)
    assert "verifies with trust store ciam-prod-cac-users (of trust policy contractors), not trust policy " \
           "cac-users's (ciam-prod-cac-users)" in n


def test_a_ca_set_that_differs_from_the_policy_bundle_is_named_by_fingerprint():
    m = _alpha()
    swapped = _changed(_states(m), "aws_s3_object", lambda a: {**a, "content": OTHER_PEM})
    (n,) = _mtls(read_terraform_state(swapped, m.d, ()).notices)
    (extra,) = bundle_fingerprints(OTHER_PEM)
    assert n.startswith("alpha/prod: trust store ciam-prod-cac-users (trust policy cac-users) holds 1 CA "
                        f"certificate(s) the policy doesn't trust: SHA-256 {extra}; lacks 1 it trusts: "
                        f"CN=DoD Root CA 6 (SHA-256 {CA_FINGERPRINT})")


def test_nothing_is_checked_without_an_edge_policy():
    m = _alpha(trust=False)
    assert "mutual_authentication" not in written(render_files(m, None))["terraform/main.tf"]
    assert _mtls(read_terraform_state(_states(m), m.d, ()).notices) == []


# ------------------------------------------------------------------ CloudFormation
def _stack(mode="verify", store_name="ciam-prod-cac-users"):
    template = {"Resources": {
        "Alb": {"Type": "AWS::ElasticLoadBalancingV2::LoadBalancer", "Properties": {
            "Name": "ciam-prod-svc-sso", "Type": "application",
            "Tags": [{"Key": "Service", "Value": "sso.example.test"}]}},
        "Listener": {"Type": "AWS::ElasticLoadBalancingV2::Listener", "Properties": {
            "LoadBalancerArn": {"Ref": "Alb"}, "Port": 443, "Protocol": "HTTPS",
            "MutualAuthentication": {"Mode": mode, "TrustStoreArn": {"Ref": "TrustStore"}},
            "DefaultActions": [{"Type": "fixed-response"}]}},
        "TrustStore": {"Type": "AWS::ElasticLoadBalancingV2::TrustStore", "Properties": {
            "Name": store_name, "CaCertificatesBundleS3Bucket": "ciam-trust",
            "CaCertificatesBundleS3Key": "pki/trust/cac-users.pem"}}}}
    resources = [{"LogicalResourceId": lid, "ResourceType": r["Type"], "ResourceStatus": "CREATE_COMPLETE",
                  "PhysicalResourceId": pid} for (lid, r), pid in zip(template["Resources"].items(),
                                                                      (LB, f"{LB}/listener-1", STORE))]
    state = {"version": 4, "resources": [{"mode": "managed", "type": "aws_s3_object", "name": "bundle",
                                          "instances": [{"attributes": {"bucket": "ciam-trust",
                                                                        "key": "pki/trust/cac-users.pem",
                                                                        "content": CA_PEM}}]}]}
    return {"alpha/prod/edge/template.json": json.dumps(template),
            "alpha/prod/edge/stack.json": json.dumps({"Stacks": [{
                "StackName": "edge", "StackId": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/edge/1"}]}),
            "alpha/prod/edge/resources.json": json.dumps({"StackResourceSummaries": resources}),
            "alpha/prod/terraform.tfstate": json.dumps(state)}


def test_a_stack_reads_its_trust_store_and_listener_mutual_tls():
    m = _alpha()
    clean = read_cloudformation(_stack(), m.d, ())
    assert _mtls(clean.notices) == [] and not [n for n in clean.notices if "TrustStore" in n]
    (n,) = _mtls(read_cloudformation(_stack(mode="passthrough"), m.d, ()).notices)
    assert "(mutual TLS passthrough)" in n
    (n,) = _mtls(read_cloudformation(_stack(store_name="ciam-prod-other"), m.d, ()).notices)
    assert "verifies with trust store ciam-prod-other, not trust policy cac-users's" in n


# ------------------------------------------------------------------ a CloudFormation render (task 591)
def _cloudformation(m):
    return {p: t for p, t in written(render(m, None, ("cloudformation",))).items()}


def test_a_cloudformation_render_keeps_the_bundle_in_a_root_applied_before_the_template():
    files = _cloudformation(_alpha())
    template = read_document(files["cloudformation/template.yaml"])
    store = template["Resources"]["LbTrustStoreCacUsers"]
    assert store["Type"] == "AWS::ElasticLoadBalancingV2::TrustStore"
    assert store["Properties"] == {"Name": "ciam-prod-cac-users", "CaCertificatesBundleS3Bucket": "ciam-trust",
                                   "CaCertificatesBundleS3Key": {"Ref": "AwsS3ObjectCacUsersTrustBundleKey"},
                                   "Tags": [{"Key": "TrustPolicy", "Value": "cac-users"},
                                            {"Key": "ManagedBy", "Value": "opsdir"}]}
    key = template["Parameters"]["AwsS3ObjectCacUsersTrustBundleKey"]
    assert key["Default"] == "pki/trust/cac-users.pem" and "applied before this template" in key["Description"]
    (listener,) = [r["Properties"] for r in template["Resources"].values()
                   if r["Type"] == "AWS::ElasticLoadBalancingV2::Listener" and r["Properties"]["Port"] == 443]
    assert listener["MutualAuthentication"] == {"Mode": "verify", "TrustStoreArn": {"Ref": "LbTrustStoreCacUsers"}}
    before = files["cloudformation/terraform-before/main.tf"]
    assert 'resource "aws_s3_object" "cac_users_trust_bundle"' in before and "applied BEFORE the template" in before
    assert 'output "aws_s3_object_cac_users_trust_bundle_key"' in before
    assert "aws_s3_object" not in files.get("cloudformation/terraform/main.tf", "")
    assert json.loads(files["cloudformation/placements.json"])["aws_s3_object.cac_users_trust_bundle"] == {
        "in": "terraform-before/main.tf",
        "why": "no CloudFormation type; the template reads it, so it is applied before the template"}


def test_a_cloudformation_render_reads_back_with_no_change_and_nothing_said():
    for region in ("us-east-1", "us-gov-west-1"):
        m = _alpha(region=region)
        files = _cloudformation(m)
        (trip,) = (t for t in read_back(m.d, ADAPTER, files, ADAPTERS, None, "alpha/prod")
                   if t.importer == "aws/cloudformation")
        assert trip.drift == () and _mtls(trip.notices) == [], region
        stacks = rendered_stacks({f"alpha/prod/{p[len('cloudformation/'):]}": t for p, t in files.items()
                                  if p.startswith("cloudformation/")}, m.d, "alpha/prod")
        assert "alpha/prod/terraform-before.tfstate" in stacks
        assert _mtls(read_cloudformation(stacks, m.d, ()).notices) == []
        swapped = {**stacks, "alpha/prod/terraform-before.tfstate": stacks[
            "alpha/prod/terraform-before.tfstate"].replace("MIIBtDCC", "MIIBtDCD")}
        (n,) = _mtls(read_cloudformation(swapped, m.d, ()).notices)
        assert "holds 1 CA certificate(s) the policy doesn't trust" in n, region


@pytest.mark.cloudformation
@pytest.mark.skipif(not LINT.exists(), reason="no tools/cfn-lint (opsdir/scripts/fetch-tools.sh)")
def test_the_trust_store_and_mutual_tls_pass_cfn_lint_in_each_partition(tmp_path):
    """The fixture's servers and certificate are unbound (cfn-lint names those), so only findings about what an edge
    trust policy renders are checked: none on the trust store, its bundle key's parameter or a listener's
    MutualAuthentication."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    ours = {"LbTrustStoreCacUsers", "AwsS3ObjectCacUsersTrustBundleKey", "MutualAuthentication"}
    for region in ("us-east-1", "us-gov-west-1"):
        path = tmp_path / f"{region}.yaml"
        path.write_text(_cloudformation(_alpha(region=region))["cloudformation/template.yaml"])
        done = subprocess.run([str(LINT), "--format", "json", "--", str(path)], capture_output=True, text=True,
                              env=env)
        found = json.loads(done.stdout or "[]")
        assert [f for f in found if ours & set(map(str, f["Location"]["Path"]))] == [], region


# ------------------------------------------------------------------ the AWS CLI
def _cli(count=1, mode="verify"):
    outs = {"load-balancers.json": {"LoadBalancers": [{"LoadBalancerArn": LB, "LoadBalancerName": "ciam-prod-svc-sso",
                                                       "Scheme": "internet-facing", "Type": "application",
                                                       "DNSName": "ciam-prod-svc-sso-1.us-east-1.elb.amazonaws.com"}]},
            "lb-tags-0a1b.json": {"TagDescriptions": [{"ResourceArn": LB, "Tags": [
                {"Key": "Service", "Value": "sso.example.test"}]}]},
            "listeners-0a1b.json": {"Listeners": [{
                "ListenerArn": f"{LB}/l-1", "LoadBalancerArn": LB, "Port": 443, "Protocol": "HTTPS",
                "MutualAuthentication": {"Mode": mode, "TrustStoreArn": STORE, "IgnoreClientCertificateExpiry": False,
                                         "TrustStoreAssociationStatus": "active"}, "DefaultActions": []}]},
            "trust-stores.json": {"TrustStores": [{"Name": "ciam-prod-cac-users", "TrustStoreArn": STORE,
                                                   "Status": "ACTIVE", "NumberOfCaCertificates": count,
                                                   "TotalRevokedEntries": 0}]}}
    return {f"alpha/prod/{p}": json.dumps(doc) for p, doc in outs.items()}


def test_the_cli_compares_the_mode_the_trust_store_and_the_number_of_cas_and_says_what_it_cant():
    m = _alpha()
    found = read_cli_inventory(_cli(), m.d, ())
    assert not [n for n in found.notices if "trust-stores.json" in n]            # recognized
    (n,) = _mtls(found.notices)
    assert n.startswith("alpha/prod: trust store ciam-prod-cac-users (trust policy cac-users): its CA certificates' "
                        "fingerprints aren't in this source") and "get-trust-store-ca-certificates-bundle" in n
    counted = _mtls(read_cli_inventory(_cli(count=3), m.d, ()).notices)
    assert any("holds 3 CA certificate(s), the policy's bundle holds 1" in n for n in counted)
    assert any("(mutual TLS off)" in n for n in _mtls(read_cli_inventory(_cli(mode="off"), m.d, ()).notices))


def test_the_collector_lists_trust_stores_only_where_the_record_has_an_edge_policy():
    def operations(m):
        return {c.argv[1:3] for _, c in inventory_steps(m.d, m, {}, {})}
    assert ("elbv2", "describe-trust-stores") in operations(_alpha())
    assert ("elbv2", "describe-trust-stores") not in operations(_alpha(trust=False))
