"""The translation layer (opsdir_format_terraform.translate) over every cloud render of the showcase, before and after
the approved changes: every reference the renderers' Terraform data makes is parsed and resolves to a block of its
own root, as Terraform resolves it, and a root splits whole to either side."""
import pytest

from opsdir.connectors.registry import ADAPTERS, environment_specs, services
from opsdir.connectors.render import render_parts
from opsdir_adapter_aws.terraform import render_files as aws
from opsdir_adapter_azure.terraform import render_files as azure
from opsdir_adapter_gcp.terraform import render_files as gcp
from opsdir_format_terraform.hcl import TfBlock
from opsdir_format_terraform.translate import address, ref_address, root_items, roots, split_root, value_refs

AS_DATA = {"aws": aws, "azure": azure, "gcp": gcp}


def cloud_roots(d):
    """((spec, adapter name, root directory, items), ...) of every cloud root the showcase renders."""
    found = services(ADAPTERS)
    out = []
    for spec in environment_specs(d):
        m, adapters, _, _, _ = render_parts(d, spec)
        out.extend((spec, a.name, root, root_items(files)) for a in adapters if a.name in AS_DATA
                   for root, files in roots(AS_DATA[a.name](m, found)).items())
    return tuple(out)


@pytest.fixture(scope="module", params=["before", "after"])
def rendered(request, estate):
    return cloud_roots(estate[request.param])


def test_every_cloud_renders_roots(rendered):
    assert {cloud for _, cloud, _, _ in rendered} == set(AS_DATA)


def test_every_reference_resolves_within_its_root(rendered):
    unresolved = []
    for spec, cloud, root, items in rendered:
        blocks = tuple(x for x in items if isinstance(x, TfBlock))
        known = {address(b) for b in blocks}
        unresolved.extend((spec, root, address(b) or b.kind, ref_address(r)) for b in blocks
                          for r in value_refs(b.body) if ref_address(r) and ref_address(r) not in known)
    assert unresolved == []
    assert sum(len(value_refs(b.body)) for *_, items in rendered for b in items if isinstance(b, TfBlock)) > 1000


def test_a_root_splits_whole_to_either_side(rendered):
    for spec, cloud, root, items in rendered:
        assert split_root(items, lambda b: True).native == items, (spec, root)
        everything_stays = split_root(items, lambda b: False)
        resources = [address(b) for b in items if isinstance(b, TfBlock) and b.kind == "resource"]
        assert [address(b) for b in everything_stays.side if isinstance(b, TfBlock) and b.kind == "resource"] == \
            resources and everything_stays.outputs == () and everything_stays.unresolved == (), (spec, root)
