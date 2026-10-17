"""Client certificates checked at an ALB (milestone 122, task 577): an edge trust policy's bundle in S3 and an ALB trust
store reading it, the listeners in front of its accepting roles verifying with it, what ALB mTLS can't do as notes, and
a blocker when the bundle or its store location is missing."""
import re

from opsdir.core.directory import get
from opsdir_format_terraform.hcl import as_text
from opsdir.domains.pki.trust import edge_policies
from opsdir_adapter_aws.mtls import cert_forwarding, mtls_notes, mutual_authentication, render_trust_stores
from network_fixtures import ALPHA, entry, model
from pki_samples import edge_trust_records

PEM = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"
POLICY = "cn=cac-users,ou=trust-policies,dc=ciam-ops"
TERMINATE = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))


def _alpha(tree=(), **kw):
    store = entry(ALPHA, "trust-bucket", "ciamObjectStore", ciamBindingRole="trust-store",
                  ciamStorageRef="s3://ciam-trust/pki")
    _, alpha, _ = model(alpha=(store,), tree=(*edge_trust_records(PEM, **kw), *tree))
    return alpha


def _sso(m):
    return next(b for b in m.bindings if b.dn.startswith("cn=svc-sso,"))


def test_an_edge_policy_is_an_alb_trust_store_and_its_listeners_verify():
    m = _alpha()
    (policy,) = edge_policies(m)
    text = re.sub(r" +", " ", "\n\n".join(as_text(render_trust_stores(m))))
    for line in ('resource "aws_s3_object" "cac_users_trust_bundle"', 'bucket = "ciam-trust"',
                 'key = "pki/trust/cac-users.pem"', 'resource "aws_lb_trust_store" "cac_users"',
                 "ca_certificates_bundle_s3_key = aws_s3_object.cac_users_trust_bundle.key",
                 r'content = "-----BEGIN CERTIFICATE-----\nMIIBroot\n-----END CERTIFICATE-----\n"'):
        assert line in text, line
    svc = next(b for b in m.bindings if b.dn.startswith("cn=svc-sso,"))
    ((key, block),) = mutual_authentication(m, svc)
    assert key == "mutual_authentication" and "verify" in str(block)
    assert "aws_lb_trust_store.cac_users.arn" in str(block)
    severities = sorted(n.severity for n in mtls_notes(m))
    assert severities == ["action", "note"] and get(m.d, POLICY) == policy


def test_without_a_store_location_or_a_bundle_it_is_a_blocker_and_listeners_stay_plain():
    m = _alpha(store=None, anchors=False)
    svc = next(b for b in m.bindings if b.dn.startswith("cn=svc-sso,"))
    assert mutual_authentication(m, svc) == ()
    (blocker,) = mtls_notes(m)
    assert blocker.severity == "blocker" and "a bundle" in blocker.text and "ciamTrustStoreRole" in blocker.text


def test_an_alb_verifying_a_service_forwards_the_leaf_url_encoded_from_its_subnets():
    m = _alpha(tree=TERMINATE)
    f = cert_forwarding(m, _sso(m))
    assert (f.header, f.encoding, f.holds, f.sources) == ("X-Amzn-Mtls-Clientcert-Leaf", "url-pem", "leaf",
                                                          ("10.1.2.0/24",))


def test_nothing_is_forwarded_through_a_network_load_balancer_or_without_a_rendered_trust_store():
    assert cert_forwarding(_alpha(), _sso(_alpha())) is None           # TLS passes through: an NLB
    m = _alpha(tree=TERMINATE, store=None)
    assert cert_forwarding(m, _sso(m)) is None
