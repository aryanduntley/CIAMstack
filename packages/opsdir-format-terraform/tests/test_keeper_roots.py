"""An environment's Terraform render placed in its keepers' roots as the cloud adapters share it (placing.keeper_*):
the stack's root under the caller's headers, a keeper's under a header naming the cloud and who keeps it, each root's
providers.tf as the cloud writes it, and what a keeper keeps of the network plumbing gathered from its bindings."""
from types import SimpleNamespace

from network_fixtures import model
from opsdir_format_terraform.hcl import from_entry, tf_block
from opsdir_format_terraform.placing import (MAIN, PROVIDERS, STACK, Rendered, keeper_head, keeper_placed,
                                             keeper_rendered, keeper_roots)

PROVIDER = tf_block("provider", ["aws"], [("region", "r")])
APP = tf_block("resource", ["aws_instance", "app"], [("ami", "a")])
NET = tf_block("resource", ["aws_vpc", "main"], [("cidr_block", "10.0.0.0/16")])
EXTRA = tf_block("variable", ["extra"], [])


def _parts(dn):
    return (PROVIDERS, (PROVIDER,)), (MAIN, (APP,)), (MAIN, from_entry(dn, (NET,)), dn)


def test_the_stack_and_the_landing_zone_each_in_their_root_with_their_headers():
    _, m, _ = model()
    landing = m.bindings[0].dn
    roots = keeper_roots(m, _parts(landing), frozenset({landing}), lambda name: f"stack {name}", "Some Cloud",
                         providers=lambda placed: lambda root, items: (*items, EXTRA))
    assert sorted(roots) == [f"{STACK}/landing-zone/{MAIN}", f"{STACK}/landing-zone/{PROVIDERS}", f"{STACK}/{MAIN}",
                             f"{STACK}/{PROVIDERS}"]
    assert roots[f"{STACK}/{MAIN}"].head == f"stack {MAIN}" and roots[f"{STACK}/{MAIN}"].items == (APP,)
    assert "Some Cloud landing zone for the CIAM platform, kept by" in roots[f"{STACK}/landing-zone/{MAIN}"].head
    assert [x.labels for x in roots[f"{STACK}/landing-zone/{MAIN}"].items] == [NET.labels]
    assert all(roots[p].items[-1] == EXTRA for p in roots if p.endswith(PROVIDERS))      # the cloud's providers.tf


def test_a_keepers_root_takes_the_adjusted_providers():
    _, m, _ = model()
    landing = m.bindings[0].dn
    pinned = tf_block("provider", ["aws"], [("region", "elsewhere")])
    placed = keeper_placed(m, _parts(landing), frozenset({landing}),
                           adjust=lambda root, items: items if root == STACK else
                           tuple(pinned if x == PROVIDER else x for x in items))
    assert placed.files[STACK][PROVIDERS] == (PROVIDER,)
    assert placed.files[f"{STACK}/landing-zone"][PROVIDERS] == (pinned,)


def test_a_keeper_roots_files_headers_name_the_cloud_and_the_keeper():
    _, m, _ = model()
    assert "Providers and inputs (landing zone)" in keeper_head(m, "terraform/x", PROVIDERS, "net-team", "Some Cloud")
    assert "Some Cloud network kept by net-team for the CIAM platform" in \
        keeper_head(m, "terraform/x", "network.tf", "net-team", "Some Cloud")
    assert "Some Cloud infrastructure kept by net-team for the CIAM platform" in \
        keeper_head(m, "terraform/x", MAIN, "net-team", "Some Cloud")


def test_what_a_keeper_keeps_gathered_from_its_bindings():
    _, m, _ = model()
    first, second = m.bindings[:2]
    shared = tf_block("data", ["aws_vpc", "main"], [("id", "vpc-1")])
    data = tf_block("data", ["aws_region", "current"], [])

    def render(m, b, here):
        assert here == {first.dn, second.dn}
        return Rendered((tf_block("resource", ["aws_route_table", b.dn.split(",")[0][3:]], []),),
                        (EXTRA,), (shared,))
    found = keeper_rendered(m, SimpleNamespace(bindings=(first, second)),
                            (("ciamNoSuchClass", None), ("top", render)), (data,))
    assert [b.origin for b in found.blocks] == [first.dn, second.dn]                  # each stamped with its entry
    assert found.variables == (EXTRA,) and found.shared == (data, shared)              # inputs and shared once
