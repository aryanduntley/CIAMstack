"""Client certificates checked at an ALB, read back (milestone 122, task 585): the render of an edge trust policy reads
back through Terraform state with no change and nothing said; a listener that stops verifying, verifies with another
trust store, or a trust store whose CA certificates differ from the policy's bundle (by SHA-256) is an import notice;
a CloudFormation stack and the AWS CLI's outputs (describe-listeners' MutualAuthentication, describe-trust-stores) read
the same, the CLI comparing only the number of CA certificates and saying so; the collector lists the trust stores
only where the record has an edge trust policy."""
import json

from opsdir.connectors.registry import ADAPTERS
from opsdir.connectors.roundtrip import read_back
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import written
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.cli import read_cli_inventory
from opsdir_adapter_aws.cloudformation import read_cloudformation
from opsdir_adapter_aws.collect import inventory_steps
from opsdir_adapter_aws.inventory import read_terraform_state
from opsdir_adapter_aws.mtls_inventory import bundle_fingerprints
from opsdir_adapter_aws.rendered_state import rendered_states
from opsdir_adapter_aws.terraform import render_files
from network_fixtures import ALPHA, entry, model
from pki_samples import CA_FINGERPRINT, CA_PEM, edge_trust_records

CLOUD = "cloud=alpha,ou=environments,dc=ciam-ops"
ACCOUNT = "111122223333"
LB = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:loadbalancer/app/ciam-prod-svc-sso/0a1b"
STORE = f"arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT}:truststore/ciam-prod-cac-users/0c1d"
OTHER_PEM = CA_PEM.replace("MIIBtDCC", "MIIBtDCD")
TERMINATE = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))
BUCKET = entry(ALPHA, "trust-bucket", "ciamObjectStore", ciamBindingRole="trust-store",
               ciamStorageRef="s3://ciam-trust/pki")


def _alpha(trust=True):
    aws = LdifRecord(CLOUD, "modify", {}, (("add", "objectClass", ("ciamCloudAccount",)),
                                           ("replace", "ciamRegion", ("us-east-1",)),
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
