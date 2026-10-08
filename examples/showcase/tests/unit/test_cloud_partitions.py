"""The target environment rendered in each Azure partition: the showcase estate's public cloud (its record) and the
government cloud (the cloud entry switched in memory). Only the provider block names the partition; the resources
are the same (Azure Government adds comments where Microsoft lists a Defender plan as unavailable there)."""
from types import MappingProxyType

import pytest

from opsdir.connectors.render import render_env
from opsdir.core.directory import make_entry, one

DST = "target/prod"


def _in_partition(partition):
    def switch(e):
        if "ciamCloud" in e.classes and one(e, "ciamCloudProvider") == "azure":
            return make_entry(e.dn, e.classes, {**e.attrs, "ciamCloudEnvironment": (partition,)})
        return e
    return switch


@pytest.fixture(scope="module")
def renders(estate):
    d = estate["before"]
    gov = d._replace(entries=MappingProxyType({n: _in_partition("usgovernment")(e) for n, e in d.entries.items()}))
    return {"public": render_env(d, DST)[1], "usgovernment": render_env(gov, DST)[1]}


def test_only_the_government_provider_block_names_its_partition(renders):
    assert 'environment     = "usgovernment"' in renders["usgovernment"]["terraform/providers.tf"]
    assert "environment     =" not in renders["public"]["terraform/providers.tf"]


def _uncommented(text):
    """main.tf without the comments that say a Microsoft availability page lists a plan as unavailable there."""
    return "\n".join(line for line in text.split("\n") if "confirm with the account team" not in line)


def test_the_resources_are_the_same_in_both_partitions(renders):
    """The same resources in both: Azure Government only adds comments where one of Microsoft's availability pages
    lists a Defender plan as unavailable there (rendered all the same)."""
    public, gov = renders["public"]["terraform/main.tf"], renders["usgovernment"]["terraform/main.tf"]
    assert _uncommented(gov) == public
    assert "confirm with the account team" in gov and "confirm with the account team" not in public
