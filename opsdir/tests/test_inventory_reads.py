"""Reading an environment as one: a folder's files read together, so what one file holds links to what another does;
an object read more than once (managed in one root and looked up in another) placed once, each attribute as reported
by whichever read reports it."""
import json

from opsdir.core.inventory import merge_reads, read_together, resource

MANAGED = resource("logs", "law-ops", {"ciamRetentionDays": "30"}, links={"ciamEncryptedByRole": "key-1"},
                   name="law-ops", tags={"Role": "ops-logs"})
LOOKED_UP = resource("logs", "law-ops", {"ciamDestinationKind": "workspace"}, name=None, role="ops-logs")


def test_an_object_read_twice_is_one_resource_with_what_each_read_reports():
    (merged,) = merge_reads((LOOKED_UP, MANAGED))
    assert dict(merged.attrs) == {"ciamRetentionDays": ("30",), "ciamDestinationKind": ("workspace",)}
    assert (merged.links, merged.name, merged.role, dict(merged.tags)) == (
        {"ciamEncryptedByRole": "key-1"}, "law-ops", "ops-logs", {"Role": "ops-logs"})


def test_the_first_read_wins_where_both_report_and_other_objects_stay_apart():
    other = resource("logs", "law-audit", {"ciamRetentionDays": "90"})
    later = resource("logs", "law-ops", {"ciamRetentionDays": "60"})
    assert [dict(r.attrs)["ciamRetentionDays"] for r in merge_reads((MANAGED, other, later))] == [("30",), ("90",)]


def test_files_read_together_link_across_files():
    """A flow log in one file reads its log group's retention from another."""
    def file_pairs(text):
        return tuple(json.loads(text)), (f"read {len(json.loads(text))}",)

    def pairs_resources(pairs):
        groups = {a["name"]: a for t, a in pairs if t == "group"}
        return tuple(resource("flow-log", a["name"], {"ciamRetentionDays": groups.get(a["to"], {}).get("days")})
                     for t, a in pairs if t == "flow"), ("mapped",)
    parse = read_together(file_pairs, pairs_resources)
    resources, notices = parse({"a.tfstate": json.dumps([["flow", {"name": "fl", "to": "g"}]]),
                                "b.tfstate": json.dumps([["group", {"name": "g", "days": 30}]])})
    assert [dict(r.attrs) for r in resources] == [{"ciamRetentionDays": ("30",)}]
    assert notices == ("mapped", "read 1", "read 1")
