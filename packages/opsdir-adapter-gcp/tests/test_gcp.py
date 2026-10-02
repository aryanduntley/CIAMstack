"""The Google Cloud adapter as the core sees it (registered, chosen from data, owning its vocabulary, references and
the credential forms the store refuses), and the Terraform it renders for a Google Cloud environment: the landing
zone's network as data, firewall rules by network tag with pinned priorities, instances with CMEK boot disks,
passthrough load balancers with Cloud DNS records, and Secret Manager secrets named, never read."""
import re
from types import SimpleNamespace

from opsdir.connectors.registry import ADAPTERS, secret_patterns
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.secrets import SECRET_PATTERNS, secret_manager_command
from support import REGISTRY, build_directory

ENV = "env=prod,cloud=gcp,ou=environments,dc=ciam-ops"
HOST = "projects/host-net"
KEY = "projects/ciam-prod/locations/us-central1/keyRings/ciam/cryptoKeys/disk"


def _entry(dn, oc, **attrs):
    return f"dn: {dn}\nobjectClass: top\nobjectClass: {oc}\n" + "".join(
        f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,)))


def _binding(cn, oc, role, **attrs):
    return _entry(f"cn={cn},ou=bindings,{ENV}", oc, cn=cn, ciamBindingRole=role, **attrs)


def _server(cn, role, ip, zone):
    return _entry(f"cn={cn},{ENV}", "ciamServer", cn=cn, ciamServerRole=role, ciamHostname=f"{cn}.gcp.example.test",
                  ciamPrivateIp=ip, ciamZone=zone, ciamInstanceSize="n2-standard-4",
                  ciamImageRef="projects/ciam-prod/global/images/ciam-ds-2026",
                  ciamSubnet=f"cn=subnet-ds,ou=bindings,{ENV}", ciamProductVersion="PingDS 8.0.1")


RECORDS = "\n".join((
    "dn: dc=ciam-ops\nobjectClass: top\nobjectClass: domain\ndc: ciam-ops\n",
    "dn: ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: environments\n",
    "dn: cloud=gcp,ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCloud\ncloud: gcp\n"
    "ciamCloudProvider: gcp\nciamRegion: us-central1\n",
    f"dn: {ENV}\nobjectClass: top\nobjectClass: ciamEnvironment\nenv: prod\n",
    f"dn: ou=bindings,{ENV}\nobjectClass: top\nobjectClass: organizationalUnit\nou: bindings\n",
    _binding("vpc", "ciamNetwork", "network", ciamCidr="10.30.0.0/16",
             ciamProviderRef=f"{HOST}/global/networks/ciam-vpc"),
    _binding("subnet-ds", "ciamSubnetBinding", "subnet-ds", ciamCidr="10.30.1.0/24",
             ciamProviderRef=f"{HOST}/regions/us-central1/subnetworks/ciam-ds"),
    _binding("fw-ldaps", "ciamFirewallRule", "fw-ldaps", ciamSourceCidr=("10.40.0.0/16", "10.41.0.0/16"),
             ciamPort="1636", ciamTargetRole="ds", ciamRulePriority="900"),
    _binding("fw-admin", "ciamFirewallRule", "fw-admin", ciamSourceCidr="10.50.0.0/24", ciamPort=("4444", "8443"),
             ciamTargetRole="ds"),
    _binding("svc-ldaps", "ciamServiceName", "ds-ldaps-service", ciamFqdn="ldaps.gcp.example.test",
             ciamDnsZone="gcp.example.test", ciamDnsZoneRef="ciam-private", ciamTargetRole="ds", ciamPort="1636",
             ciamFrontendIp="10.30.1.100"),
    _binding("svc-public", "ciamServiceName", "ds-public-service", ciamFqdn="ds.example.test",
             ciamDnsZone="example.test", ciamDnsZoneRef="ciam-public", ciamTargetRole="ds",
             ciamPort=("1636", "1389", "4444", "8443", "8080", "8989"), ciamFrontendIp="34.120.10.10",
             ciamProviderRef="ciam-prod-ds-public"),
    _binding("key-disk", "ciamKeyRef", "disk-encryption", ciamRefUri=f"gcp-kms://{KEY}"),
    _binding("secret-root", "ciamSecretRef", "ds-root-password",
             ciamRefUri="gcp-sm://projects/ciam-prod/secrets/ds-root-password"),
    _binding("secret-tls", "ciamSecretRef", "ds-tls-keystore",
             ciamRefUri="gcp-sm://projects/ciam-prod/locations/us-central1/secrets/ds-tls"),
    _server("ds-1", "ds", "10.30.1.11", "us-central1-a"),
    _server("ds-2", "ds", "10.30.1.12", "us-central1-b")))


def _render():
    d = build_directory(REGISTRY, tuple(parse(RECORDS)))
    return ADAPTER.render_env(env_model(d, "gcp/prod"), None)


def test_registered_and_chosen_by_provider():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "provider"
    assert ADAPTER.applies(SimpleNamespace(provider="gcp")) and not ADAPTER.applies(SimpleNamespace(provider="aws"))
    assert ADAPTER.vocabulary["ciamCloudProvider"] == ("gcp",)
    assert set(ADAPTER.ref_schemes) == {"gcp-sm", "gcp-kms", "gcp-cert", "gs"}
    assert set(ADAPTER.secret_schemes) == {"gcp-sm"}


def test_secret_references_resolve_with_gcloud():
    assert secret_manager_command("projects/ciam-prod/secrets/ds-root") == (
        "gcloud secrets versions access latest --secret='ds-root' --project='ciam-prod'")
    assert secret_manager_command("projects/ciam-prod/locations/europe-west1/secrets/tls") == (
        "gcloud secrets versions access latest --secret='tls' --project='ciam-prod' --location='europe-west1'")


def test_the_store_refuses_google_cloud_credentials():
    assert {p.name for p in SECRET_PATTERNS} <= {p[0] for p in secret_patterns()}
    found = {p.name for p in SECRET_PATTERNS for text in (
        '{"type": "service_account", "private_key_id": "0123456789abcdef0123456789abcdef01234567"}',
        "key=AIzaSyA1234567890abcdefghijklmnopqrstuv", "client_secret: GOCSPX-abcdefghijklmnopqrstuvwxyz12")
        if re.search(p.pattern, text)}
    assert found == {"gcp-service-account-key", "gcp-api-key", "gcp-oauth-client-secret"}


def test_providers_take_the_project_and_region():
    providers = _render()["terraform/providers.tf"]
    assert 'source  = "hashicorp/google"' in providers and 'version = "~> 8.0"' in providers
    assert 'default = "us-central1"' in providers and "project = var.project_id" in providers


def test_the_landing_zones_network_is_read_from_its_host_project():
    main = _render()["terraform/main.tf"]
    assert 'data "google_compute_network" "main" {\n  name    = "ciam-vpc"\n  project = "host-net"\n}' in main
    assert 'name    = "ciam-ds"\n  region  = "us-central1"\n  project = "host-net"' in main


def test_firewall_rules_target_a_tag_with_pinned_priorities():
    main = _render()["terraform/main.tf"]
    assert 'priority    = 900' in main and 'target_tags   = ["ciam-prod-ds"]' in main
    assert ("# NOTE: fw-admin has no pinned ciamRulePriority; assigned 1000. Pin it in the directory." in main)
    assert 'source_ranges = ["10.40.0.0/16", "10.41.0.0/16"]' in main and 'ports    = ["4444", "8443"]' in main


def test_instances_use_the_environments_key_shielded_vm_and_os_login():
    main = _render()["terraform/main.tf"]
    assert f'kms_key_self_link = "{KEY}"' in main
    assert 'enable_secure_boot          = true' in main and 'enable-oslogin = "TRUE"' in main
    assert 'ciam-product   = "PingDS 8.0.1"' in main
    assert 'product    = "pingds-8-0-1"' in main and 'tags         = ["ciam-prod-ds"]' in main


def test_a_service_is_an_internal_passthrough_load_balancer_with_its_dns_name():
    main = _render()["terraform/main.tf"]
    assert 'resource "google_compute_instance_group" "svc_ldaps_us_central1_a"' in main
    assert 'resource "google_compute_instance_group" "svc_ldaps_us_central1_b"' in main
    assert 'load_balancing_scheme = "INTERNAL"' in main and 'ip_address            = "10.30.1.100"' in main
    assert 'managed_zone = "ciam-private"' in main and 'name         = "ldaps.gcp.example.test."' in main


def test_backends_are_instance_groups_by_self_link_admitting_health_checks():
    main = _render()["terraform/main.tf"]
    assert 'group          = google_compute_instance_group.svc_ldaps_us_central1_a.self_link' in main
    assert ".id\n" not in main.split('resource "google_compute_region_backend_service" "svc_ldaps"')[1].split("}")[1]
    internal = main.split('resource "google_compute_firewall" "svc_ldaps_health_checks"')[1].split("\n}")[0]
    assert 'source_ranges = ["35.191.0.0/16"]' in internal and 'ports    = ["1636"]' in internal
    assert 'target_tags   = ["ciam-prod-ds"]' in internal


def test_an_external_service_names_its_port_and_forwards_all_ports_past_five():
    main = _render()["terraform/main.tf"]
    backend = main.split('resource "google_compute_region_backend_service" "svc_public"')[1].split("\n}")[0]
    assert 'load_balancing_scheme = "EXTERNAL"' in backend and 'port_name             = "ciam"' in backend
    assert "capacity_scaler = 1.0" in backend
    assert 'named_port {\n    name = "ciam"\n    port = 1636\n  }' in main
    rule = main.split('resource "google_compute_forwarding_rule" "svc_public"')[1].split("\n}")[0]
    assert "all_ports       = true" in rule and "\n  ports " not in rule
    probes = main.split('resource "google_compute_firewall" "svc_public_health_checks"')[1].split("\n}")[0]
    assert '"35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"' in probes
    internal = main.split('resource "google_compute_region_backend_service" "svc_ldaps"')[1].split("\n}")[0]
    assert "port_name" not in internal and "capacity_scaler" not in internal


def test_secrets_are_named_never_read():
    main = _render()["terraform/main.tf"]
    assert 'data "google_secret_manager_secret" "ds_root_password"' in main
    assert 'data "google_secret_manager_regional_secret" "ds_tls_keystore"' in main
    assert "secret_version" not in main
