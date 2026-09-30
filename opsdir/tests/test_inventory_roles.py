"""The role map (<cloud>/<env>/roles.json) gives roles to resources a cloud can't tag: by provider ref or name, only
where the source names none; entries that disagree with the source or match nothing are named; a malformed map is
refused as a whole. And a source that reports the record's values in another order changes nothing."""
from opsdir.core.directory import get, make_directory, values
from opsdir.core.inventory import environment_groups, read_role_map, resource, with_roles

SUBNET = resource("subnet", "vnet-1/snet-new", {"ciamCidr": "10.60.4.0/24"}, name="snet-new")
RULE = resource("firewall", "fw-new", {"ciamPort": "4444"}, name="fw-new")
VM = resource("server", "/subscriptions/0/vm-ds-2", {}, name="ds-2", role="ds")


def test_resources_without_a_role_take_the_maps_by_ref_or_name():
    placed, notices = with_roles((SUBNET, RULE, VM), {"vnet-1/snet-new": "subnet-ds", "fw-new": "fw-admin"})
    assert [r.role for r in placed] == ["subnet-ds", "fw-admin", "ds"]
    assert notices == ()


def test_the_sources_role_is_kept_and_disagreements_and_strays_named():
    placed, notices = with_roles((VM,), {"ds-2": "pf-engine", "snet-typo": "subnet-ds"})
    assert placed == (VM,)
    assert notices == ("roles.json: server ds-2 has role ds from the source; the map's pf-engine not used",
                       "roles.json: snet-typo matches nothing the source reports")


def test_a_map_that_is_not_an_object_of_names_to_roles_is_refused():
    assert read_role_map('{"a": "b"}') == ({"a": "b"}, None)
    assert read_role_map("[1]")[1] == "not a JSON object of provider references or names to roles"
    assert read_role_map('{"a": ""}')[1] == "not a JSON object of provider references or names to roles"
    assert read_role_map("nope")[1] == "not JSON"


def test_the_same_values_in_another_order_change_nothing():
    env = "env=prod,cloud=main,ou=environments,dc=ciam-ops"
    rule = f"cn=fw-rep,ou=bindings,{env}"
    d = make_directory((), {}, (
        ("cloud=main,ou=environments,dc=ciam-ops", ("top", "ciamCloud"), {"cloud": ["main"]}),
        (env, ("top", "ciamEnvironment"), {"env": ["prod"]}),
        (f"ou=bindings,{env}", ("top", "organizationalUnit"), {"ou": ["bindings"]}),
        (rule, ("top", "ciamFirewallRule"), {"cn": ["fw-rep"], "ciamBindingRole": ["fw-rep"],
                                             "ciamSourceCidr": ["10.60.1.0/24", "10.20.0.0/16"], "ciamPort": ["8989"],
                                             "ciamTargetRole": ["ds"]})))
    reported = resource("firewall", "fw-rep", {"ciamSourceCidr": ["10.20.0.0/16", "10.60.1.0/24"], "ciamPort": "8989"},
                        name="fw-rep")
    ((_, (entry,)),), _ = environment_groups(d, "main/prod", (reported,))
    assert entry == get(d, rule) and values(entry, "ciamSourceCidr") == ("10.60.1.0/24", "10.20.0.0/16")
