"""Where a deployment kit deploys PingFederate, PingFederate's own check compares the record's cluster discovery with
the DNS name the kit's chart answers (contract.DiscoveryAnswer, on the model: core.environment.discovery_answers): an
action with the fix binding DNS_PING through that name when they differ, fine when they agree."""
from opsdir.connectors.registry import core_fragments
from opsdir.core.contract import DiscoveryAnswer, PlanContext
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.core.standard import registry_ldif
from opsdir_adapter_pingfederate.adapter import ADAPTER
from opsdir_adapter_pingfederate.checks import check_kit_discovery
from opsdir_adapter_pingfederate.naming import DISCOVERY_ROLE, PRODUCT
from opsdir_adapter_pingfederate.schema import FRAGMENT
import mini_estate
from support import build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
REGISTRY = registry_ldif((*core_fragments(), FRAGMENT))
QUERY = "pingfederate-pingfederate-cluster.identity.svc.cluster.local"
ANSWER = DiscoveryAnswer(PRODUCT, "identity", QUERY, "a-kit", "A_SETTING")


def _binding(oc, attrs):
    return (f"dn: cn=pf-discovery,ou=bindings,{ALPHA}\nobjectClass: top\nobjectClass: {oc}\ncn: pf-discovery\n"
            f"ciamBindingRole: {DISCOVERY_ROLE}\n{attrs}")


DNS = _binding("pingfedClusterDiscovery", f"pingfedDiscoveryProtocol: DNS_PING\nciamFqdn: {QUERY}\n")


def _checked(*extra, answers=(ANSWER,)):
    d = build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *extra)))))
    m = env_model(d, "alpha/prod")._replace(cluster_discovery=answers)
    return check_kit_discovery(PlanContext(d, m, m, None, None, {}, {}, ()))


def test_it_is_the_first_of_pingfederates_checks():
    assert ADAPTER.checks[0] is check_kit_discovery          # the plan and fix list keep the kit's findings in place


def test_the_record_binds_what_the_charts_cluster_service_answers():
    found = _checked(DNS)
    assert not found.actions and not found.fixes
    assert found.ok == ("PingFederate's cluster discovery in alpha/prod (namespace `identity`) is what the a-kit chart "
                        f"answers: DNS_PING through `{QUERY}`.",)
    assert _checked(DNS, answers=()) == _checked(answers=())          # no kit deploys PingFederate: nothing to say
    assert not _checked(answers=()).actions and not _checked(answers=()).ok


def test_no_binding_is_an_action_with_the_fix_binding_dns_ping():
    found = _checked()
    ((area, text, _, by),) = found.actions
    assert (area, by) == ("PingFederate on Kubernetes", None)
    assert text == ("PingFederate runs on Kubernetes in alpha/prod (namespace `identity`): the chart's pods find each "
                    f"other by DNS_PING through its cluster service `{QUERY}`, but the record binds no "
                    f"`{DISCOVERY_ROLE}` there. Record that binding.")
    (fix,) = found.fixes
    assert fix.key == "a-kit-discovery:alpha/prod:identity" and fix.area == "PingFederate on Kubernetes"
    assert fix.manual == ("Install alpha/prod's rendered a-kit values (they set A_SETTING from the binding).",)
    (record,) = [r for r in fix.records if r.dn.startswith("cn=pf-discovery,")]
    assert record.attrs["pingfedDiscoveryProtocol"] == ("DNS_PING",) and record.attrs["ciamFqdn"] == (QUERY,)


def test_another_protocol_or_name_is_an_action():
    s3 = _binding("ciamObjectStore", "ciamStorageRef: s3://pf-cluster\n")
    ((_, text, _, _),) = _checked(s3).actions
    assert text.endswith(f"but its `{DISCOVERY_ROLE}` binding uses NATIVE_S3_PING. Record that binding.")
    elsewhere = DNS.replace(QUERY, "pf.example.test")
    found = _checked(elsewhere)
    ((_, text, _, _),) = found.actions
    assert "has them query `pf.example.test`, which the chart's service doesn't answer" in text
    (fix,) = found.fixes
    assert fix.records[0].mods[0] == ("replace", "pingfedDiscoveryProtocol", ("DNS_PING",))
    assert ("replace", "ciamFqdn", (QUERY,)) in fix.records[0].mods
