"""Each cloud's Terraform for a service name that records no frontend address: with no exposure either, a comment in
place of its load balancer and DNS record (never a crash, never a guess); with an exposure, the load balancer the cloud
assigns an address to; with no DNS zone, a comment in place of the record."""
import pytest

from gateway_sample import CLOUDS, _changes, _records
from opsdir.connectors.registry import services
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
import mini_estate
from network_fixtures import ALPHA
from support import REGISTRY, build_directory

SSO = f"dn: cn=svc-sso,ou=bindings,{ALPHA}\nchangetype: modify\n"


def _main(cloud, change):
    render, refs = CLOUDS[cloud]
    keep = (*_changes(refs)[1:], *parse(SSO + change))           # the gateway sample, keeping the mini estate's svc-sso
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *_records(refs))))), keep)
    return render(env_model(d, "alpha/prod"), services())["terraform/main.tf"]


@pytest.mark.parametrize("cloud", sorted(CLOUDS))
def test_no_address_and_no_exposure_is_a_comment(cloud):
    main = _main(cloud, "delete: ciamExposure\n-\n")
    assert "# UNBOUND:sso-service-exposure: service name `svc-sso` (sso.example.test)" in main
    assert "sso.example.test" not in main.replace("# UNBOUND:sso-service-exposure: service name `svc-sso` "
                                                  "(sso.example.test)", "")


@pytest.mark.parametrize("cloud", sorted(CLOUDS))
@pytest.mark.parametrize("exposure", ("internet", "internal"))
def test_an_exposure_without_an_address_renders_the_load_balancer(cloud, exposure):
    main = _main(cloud, f"replace: ciamExposure\nciamExposure: {exposure}\n-\n")
    assert "UNBOUND:sso-service-exposure" not in main and "svc_sso" in main
    assert "# UNBOUND:sso-service-dns-zone: no DNS zone recorded for `sso.example.test`" in main


@pytest.mark.parametrize("cloud", sorted(CLOUDS))
def test_a_zone_recorded_on_the_name_gets_its_record(cloud):
    main = _main(cloud, "add: ciamDnsZoneRef\nciamDnsZoneRef: Z999\n-\n"
                        "add: ciamDnsZone\nciamDnsZone: example.test\n-\n")
    assert "sso-service-dns-zone" not in main
