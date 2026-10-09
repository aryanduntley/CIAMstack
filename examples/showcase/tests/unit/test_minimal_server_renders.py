"""Each cloud's Terraform for a server that records only what its class requires (role, hostname, subnet): its image
and size are UNBOUND values naming it (applying fails there, never the render), its private address the cloud's."""
import pytest

from gateway_sample import CLOUDS, _changes, _records
from opsdir.connectors.registry import services
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
import mini_estate
from network_fixtures import ALPHA, entry
from support import REGISTRY, build_directory


def _main(cloud):
    render, refs = CLOUDS[cloud]
    web = (entry(ALPHA, "subnet-web", "ciamSubnetBinding", ciamBindingRole="subnet-web", ciamCidr="10.1.2.0/24",
                 ciamProviderRef=refs["SUBNET"].format("web")),
           entry(ALPHA, "web-1", "ciamServer", ciamServerRole="web", ciamHostname="web-1.example.test",
                 ciamSubnet=f"cn=subnet-web,ou=bindings,{ALPHA}"))
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *_records(refs), *web)))), _changes(refs))
    return render(env_model(d, "alpha/prod"), services())["terraform/main.tf"]


@pytest.mark.parametrize("cloud", sorted(CLOUDS))
def test_a_server_without_image_size_or_address_renders_unbound_values(cloud):
    main = _main(cloud)
    assert '"UNBOUND:web-1-image"' in main and '"UNBOUND:web-1-size"' in main
    assert "10.1.2." not in main                                    # no address recorded: the cloud assigns one
