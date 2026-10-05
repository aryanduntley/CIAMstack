"""The network depth the stack keeps as AWS Terraform: VPC endpoints (Interface with a security group and private DNS,
Gateway on the route tables), endpoint services on an L4 service's NLB, an egress firewall's domain allowlist as a
Network Firewall rule group; comments for what AWS has no endpoint for and what others keep."""
from opsdir_adapter_aws.network import render_network
from network_fixtures import ALPHA, entry, model

TERMINATE = ("dn: ou=edge-policies,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             entry("ou=edge-policies,dc=ciam-ops", "sso-edge", "ciamTrafficPolicy", ciamServiceRole="sso-service",
                   ciamTlsMode="terminate"))
SECRET = entry(ALPHA, "secret-a", "ciamSecretRef", ciamBindingRole="admin-password", ciamRefUri="aws-sm://arn:a")
BACKUP = entry(ALPHA, "backup", "ciamBackupTarget", ciamBindingRole="backup-target", ciamStorageRef="s3://bk")


def _render(*records, tree=()):
    return "\n\n".join(render_network(model(alpha=records, tree=tree)[1]))


def test_nothing_recorded_renders_nothing():
    assert render_network(model()[1]) == ()


def test_an_interface_endpoint_in_its_subnets_with_a_security_group_and_private_dns():
    out = _render(SECRET, entry(ALPHA, "pe-secrets", "ciamPrivateEndpoint", ciamBindingRole="pe-secrets",
                                ciamPrivateService="secrets", ciamPrivateEndpointKind="interface",
                                ciamReachesRole="admin-password", ciamSubnetRole="subnet-ds", ciamPrivateDns="TRUE"))
    assert "# Private endpoint 'pe-secrets' to secrets (reaches admin-password)" in out
    assert 'service_name        = "com.amazonaws.region-1.secretsmanager"' in out
    assert 'vpc_endpoint_type   = "Interface"' in out and "private_dns_enabled = true" in out
    assert "subnet_ids          = [data.aws_subnet.subnet_ds.id]" in out
    assert "security_group_ids  = [aws_security_group.pe_secrets_endpoint.id]" in out
    assert 'cidr_ipv4         = "10.1.0.0/16"' in out and "from_port         = 443" in out


def test_a_gateway_endpoint_goes_on_the_tables_of_its_subnets_and_the_main_table():
    tables = (entry(ALPHA, "rt-ds", "ciamRouteTable", ciamBindingRole="rt-ds", ciamRoute="0.0.0.0/0 nat egress",
                    ciamSubnetRole="subnet-ds", ciamProviderRef="rtb-ds"),
              entry(ALPHA, "rt-main", "ciamRouteTable", ciamBindingRole="rt-main", ciamRoute="0.0.0.0/0 nat egress",
                    ciamMainTable="TRUE", ciamProviderRef="rtb-main"),
              entry(ALPHA, "rt-other", "ciamRouteTable", ciamBindingRole="rt-other", ciamRoute="0.0.0.0/0 nat egress",
                    ciamSubnetRole="subnet-other", ciamProviderRef="rtb-other"))
    gateway = entry(ALPHA, "pe-s3", "ciamPrivateEndpoint", ciamBindingRole="pe-s3", ciamPrivateService="object-storage",
                    ciamPrivateEndpointKind="gateway", ciamReachesRole="backup-target",
                    ciamSubnetRole=("subnet-ds", "subnet-web"))
    out = _render(BACKUP, gateway, *tables)
    assert 'service_name      = "com.amazonaws.region-1.s3"' in out and 'vpc_endpoint_type = "Gateway"' in out
    assert 'route_table_ids   = ["rtb-ds", "rtb-main"]' in out                # subnet-web has no table: the main one
    assert "aws_security_group" not in out


def test_what_aws_has_no_endpoint_for_is_said():
    out = _render(entry(ALPHA, "pe-kms", "ciamPrivateEndpoint", ciamBindingRole="pe-kms", ciamPrivateService="keys",
                        ciamPrivateEndpointKind="gateway"),
                  entry(ALPHA, "pe-db", "ciamPrivateEndpoint", ciamBindingRole="pe-db", ciamPrivateService="database"),
                  entry(ALPHA, "pe-apis", "ciamPrivateEndpoint", ciamBindingRole="pe-apis", ciamPrivateService="apis",
                        ciamPrivateEndpointKind="all-apis"))
    assert "# Private endpoint 'pe-kms': kms has no gateway endpoint (only S3 and DynamoDB)" in out
    assert "# Private endpoint 'pe-db': no VPC endpoint for database" in out
    assert "# Private endpoint 'pe-apis': no VPC endpoint for apis" in out
    assert "aws_vpc_endpoint" not in out


def test_an_endpoint_service_exposes_an_l4_services_nlb_and_not_an_alb():
    service = entry(ALPHA, "ldaps-link", "ciamEndpointService", ciamBindingRole="ldaps-link",
                    ciamServiceRole="sso-service", ciamAllowedPrincipal="arn:aws:iam::444455556666:root",
                    ciamAcceptanceRequired="TRUE")
    out = _render(service)
    assert 'resource "aws_vpc_endpoint_service" "ldaps_link"' in out and "acceptance_required        = true" in out
    assert "network_load_balancer_arns = [aws_lb.svc_sso.arn]" in out
    assert 'allowed_principals         = ["arn:aws:iam::444455556666:root"]' in out
    out = _render(service, tree=TERMINATE)
    assert "terminates TLS at an application load balancer; an endpoint service needs a network load balancer" in out
    assert "aws_vpc_endpoint_service" not in out
    assert "# UNBOUND: endpoint service 'x' exposes nowhere" in _render(
        entry(ALPHA, "x", "ciamEndpointService", ciamBindingRole="x", ciamServiceRole="nowhere"))


def test_the_stacks_egress_firewall_gets_a_domain_allowlist_rule_group():
    out = _render(entry(ALPHA, "egress-fw", "ciamProxy", ciamBindingRole="egress-firewall", ciamProxyKind="firewall",
                        ciamProviderRef="arn:aws:network-firewall:region-1:111122223333:firewall-policy/ciam",
                        ciamAllowedDestination=("idp.partner.example", "*.okta.example", "ocsp.ca.example:80")))
    assert "reference this rule group from its firewall policy (arn:aws:network-firewall:" in out
    assert 'resource "aws_networkfirewall_rule_group" "egress_fw_domains"' in out and 'type        = "STATEFUL"' in out
    assert 'generated_rules_type = "ALLOWLIST"' in out and 'target_types         = ["TLS_SNI", "HTTP_HOST"]' in out
    assert 'targets              = ["ocsp.ca.example", "idp.partner.example", ".okta.example"]' in out
    assert 'definition = ["10.1.0.0/16"]' in out and "capacity    = 100" in out


def test_what_others_keep_is_a_comment_naming_them():
    party = ("dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
             "dn: cn=net-team,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: net-team\n"
             "ciamOwnerKind: team\n")
    out = _render(entry(ALPHA, "hub-fw", "ciamProxy", ciamBindingRole="hub-firewall", ciamProxyKind="firewall",
                        ciamAllowedDestination="idp.partner.example", ciamManagedBy="cn=net-team,ou=owners,dc=ciam-ops"),
                  tree=party)
    assert out == ("# Egress firewall 'hub-fw' is kept by net-team; its allowlist is rendered in their root, not "
                   "here.")


def test_a_domain_list_says_what_isnt_web_traffic():
    out = _render(entry(ALPHA, "egress-fw", "ciamProxy", ciamBindingRole="egress-firewall", ciamProxyKind="firewall",
                        ciamAllowedDestination=("smtp.example:587", "idp.partner.example")))
    assert ("# A domain list matches TLS SNI and HTTP Host only: smtp.example:587 isn't web traffic, so the policy's "
            "other stateful rules decide it") in out
