"""Log sources: the kind of a line (match rules in order, then the source's kind), what a route picks from a source
(all, some, none), the sources a route reads, the declaration checks, the products' and kits' declarations, and per
environment where each route's logs come from: servers without an install root named in the log-collection report
and, in the target, as the planner's action."""
import datetime as dt

from opsdir.connectors.observability import log_collection_check
from opsdir.core.contract import Adapter, LogSource, PlanContext
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.compute.naming import WORKLOADS, workload_dn
from opsdir.domains.observability.logs import log_routes
from opsdir.domains.observability.naming import LOG_ROUTES
from opsdir.domains.observability.sources import (ALL, Clause, NONE, SOME, collection_rows, collections,
                                                  declaration_problems, kind_of, kinds_of, kept_clauses, picks,
                                                  route_sources, shipments, under, unpermitted,
                                                  unrooted)
import mini_estate
from support import REGISTRY, build_directory

AM = LogSource("am", "kubernetes", None, "mixed", "debug",
               (("eventName", "AM-ACCESS-", "access"), ("eventName", "", "audit")))
ERRORS = LogSource("ds", "servers", "logs/errors", "text", "error", line_start=r"^\[")
ACCESS = LogSource("ds", "servers", "logs/ldap-access.audit.json", "json-lines", "access")


def test_a_line_takes_the_first_matching_rule_else_the_sources_kind():
    assert kind_of(AM, {"eventName": "AM-ACCESS-OUTCOME"}) == "access"
    assert kind_of(AM, {"eventName": "AM-CONFIG-CHANGE"}) == "audit"       # "" matches any value
    assert kind_of(AM, {"message": "debug"}) == "debug"                    # no field: the source's kind
    assert kind_of(AM, {"eventName": 7}) == "debug"                        # only string values match
    assert kind_of(AM, None) == "debug"                                    # a text line
    assert kinds_of(AM) == ("access", "audit", "debug")
    assert kinds_of(ERRORS) == ("error",)


def test_a_route_picks_all_some_or_none_of_a_source():
    assert picks(AM, ("access", "audit", "debug", "error")) == ALL
    assert picks(AM, ("audit",)) == SOME
    assert picks(AM, ("replication",)) == NONE
    assert picks(ERRORS, ("error",)) == ALL


def test_the_clauses_keep_exactly_the_lines_of_the_wanted_kinds():
    access, any_event = ("eventName", "AM-ACCESS-"), ("eventName", "")
    assert kept_clauses(AM, ("access",)) == (Clause(access, ()),)
    assert kept_clauses(AM, ("audit",)) == (Clause(any_event, (access,)),)       # an access event isn't audit
    assert kept_clauses(AM, ("debug",)) == (Clause(None, (access, any_event)),)
    assert kept_clauses(AM, ("access", "debug")) == (Clause(access, ()), Clause(None, (any_event,)))
    assert kept_clauses(AM, ("error",)) == ()
    lines = ({"eventName": "AM-ACCESS-OUTCOME"}, {"eventName": "AM-CONFIG"}, {"message": "x"}, None)

    def holds(clause, record):
        def hit(rule):
            return record is not None and isinstance(record.get(rule[0]), str) and record[rule[0]].startswith(rule[1])
        return (clause.match is None or hit(clause.match)) and not any(hit(r) for r in clause.excluded)
    for kinds in (("access",), ("audit",), ("debug",), ("access", "debug"), ("audit", "debug"), ("access", "audit")):
        assert [any(holds(c, r) for c in kept_clauses(AM, kinds)) for r in lines] == [
            kind_of(AM, r) in kinds for r in lines]


def test_a_route_reads_the_sources_of_its_roles_and_kinds():
    sources = (AM, ERRORS, ACCESS)
    assert route_sources(sources, ("ds", "am"), ("access",)) == ((AM, SOME), (ACCESS, ALL))
    assert route_sources(sources, ("ds", "am"), ("access",), on="servers") == ((ACCESS, ALL),)
    assert route_sources(sources, ("pf-engine",), ("access",)) == ()


def test_declarations_are_checked():
    assert declaration_problems(AM) == () and declaration_problems(ERRORS) == ()
    assert declaration_problems(LogSource("ds", "vm", "x", "csv", "noise", (("f", "", "loud"),))) == (
        "kind `loud` is not a log kind", "kind `noise` is not a log kind",
        "place `vm` is not one of servers, kubernetes", "format `csv` is not one of json-lines, text, mixed")
    assert declaration_problems(LogSource("ds", "servers", None, "text", "error", (("f", "", "audit"),))) == (
        "a file on servers needs a path relative to the install root", "match rules need JSON lines")
    assert declaration_problems(LogSource("am", "kubernetes", "x", "text", "error")) == (
        "container output has no path",)
    assert declaration_problems(LogSource("ds", "servers", "x", "text", "error", container="tail")) == (
        "a file on servers has no container",)


def _adapters():
    from opsdir_adapter_forgeops.adapter import ADAPTER as FORGEOPS
    from opsdir_adapter_opendj.adapter import ADAPTER as OPENDJ
    from opsdir_adapter_ping_devops.adapter import ADAPTER as PING_DEVOPS
    from opsdir_adapter_pingam.adapter import ADAPTER as PINGAM
    from opsdir_adapter_pingds.adapter import ADAPTER as PINGDS
    from opsdir_adapter_pingfederate.adapter import ADAPTER as PINGFEDERATE
    from opsdir_adapter_pinggateway.adapter import ADAPTER as PINGGATEWAY
    from opsdir_adapter_pingidm.adapter import ADAPTER as PINGIDM
    return {a.name: a for a in (FORGEOPS, OPENDJ, PING_DEVOPS, PINGAM, PINGDS, PINGFEDERATE, PINGGATEWAY, PINGIDM)}


def test_every_declared_source_is_well_formed():
    adapters = _adapters()
    assert {name: [(s.path, declaration_problems(s)) for s in a.logs if declaration_problems(s)]
            for name, a in adapters.items() if any(declaration_problems(s) for s in a.logs)} == {}
    assert all(a.logs for a in adapters.values())


def test_products_declare_files_and_kits_container_output():
    adapters = _adapters()
    assert {s.on for name in ("pingam", "pingds", "pingfederate", "pinggateway", "pingidm")
            for s in adapters[name].logs} == {"servers"}
    assert {s.on for name in ("forgeops", "ping-devops") for s in adapters[name].logs} == {"kubernetes"}
    assert {s.server_role for s in adapters["forgeops"].logs} == {"am", "idm", "ig"}    # DS: no documented default
    assert all(s.requires for s in adapters["forgeops"].logs if s.match)        # audit on stdout must be switched on
    assert {s.server_role for s in adapters["ping-devops"].logs} == {"pf-engine", "pf-admin"}
    assert all(not s.match for s in adapters["ping-devops"].logs)               # tailed files can't be told apart
    pf = {(s.server_role, s.path.rsplit("/", 1)[1]) for s in adapters["pingfederate"].logs}
    assert ("pf-admin", "admin.log") in pf and ("pf-engine", "audit.log") in pf and ("pf-admin", "audit.log") not in pf


ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
WEB = LogSource("web", "servers", "logs/audit.log", "text", "audit")
APP = LogSource("app", "kubernetes", None, "mixed", "debug", (("eventName", "", "audit"),),
                requires="the app's JSON stdout audit handler")


def _server(env, cn, role, root=None):
    return (f"dn: cn={cn},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: {role}\n"
            f"ciamHostname: {cn}.example.test\nciamSubnet: cn=net,ou=bindings,{env}\n"
            + (f"ciamInstallRoot: {root}\n" if root else ""))


def _destination(env):
    return (f"dn: cn=audit,ou=bindings,{env}\nobjectClass: top\nobjectClass: ciamLogDestination\ncn: audit\n"
            "ciamBindingRole: audit-logs\nciamDestinationKind: workspace\nciamProviderRef: ws-1\n")


RECORDS = (
    _server(ALPHA, "web-1", "web", "/opt/web"), _server(ALPHA, "web-2", "web"), _server(BETA, "web-b1", "web"),
    _server(ALPHA, "web-3", "web", "/srv/web/"), _server(ALPHA, "web-4", "web", "/opt/web"),
    _destination(ALPHA), _destination(BETA),
    f"dn: {WORKLOADS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: workloads\n",
    f"dn: {workload_dn('app')}\nobjectClass: top\nobjectClass: ciamWorkload\ncn: app\nciamWorkloadKind: deployment\n"
    "ciamTargetRole: app\nciamClusterRole: k8s\nciamWorkloadRole: app-workload\n",
    f"dn: cn=app,ou=bindings,{BETA}\nobjectClass: top\nobjectClass: ciamWorkloadBinding\ncn: app\n"
    "ciamBindingRole: app-workload\nciamContainerImage: app=registry.example.test/app:1\n",
    f"dn: cn=k8s,ou=bindings,{BETA}\nobjectClass: top\nobjectClass: ciamCluster\ncn: k8s\nciamBindingRole: k8s\n"
    "ciamProviderRef: cluster-1\n",
    f"dn: {LOG_ROUTES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: log-routes\n",
    f"dn: cn=audit,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\ncn: audit\n"
    "ciamLogKind: audit\nciamLogKind: admin\nciamPublishedBy: web\nciamPublishedBy: app\n"
    "ciamLogDestinationRole: audit-logs\n",
    f"dn: cn=errors,{LOG_ROUTES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamLogRoute\ncn: errors\n"
    "ciamLogKind: error\nciamPublishedBy: web\nciamLogDestinationRole: ops-logs\n")


def _record():
    return build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join(RECORDS))))


def test_servers_without_an_install_root_are_named():
    d = _record()
    assert unrooted(env_model(d, "alpha/prod"), "web") == ("web-2",)       # web-1, 3, 4 record one
    assert unrooted(env_model(d, "beta/prod"), "web") == ("web-b1",)


def test_each_route_collects_from_where_its_roles_run():
    d = _record()
    alpha, beta = env_model(d, "alpha/prod"), env_model(d, "beta/prod")
    assert [(c.role, c.on, c.source, c.lines, c.unrooted) for c in collections(alpha, log_routes(d), (WEB, APP))] == [
        ("web", "servers", WEB, ALL, ("web-2",)),          # app runs nowhere in alpha
        ("web", "servers", None, NONE, ())]                # the errors route: no web log holds errors
    assert collection_rows(beta, log_routes(d), (WEB, APP)) == [
        ("audit", "web", "servers", "logs/audit.log", "all", "no install root: web-b1"),
        ("audit", "app", "kubernetes", "container output", "by content", "needs the app's JSON stdout audit handler"),
        ("errors", "web", "servers", "", "", "its logs here hold only audit")]
    assert collection_rows(beta, log_routes(d), (APP,))[0] == (
        "audit", "web", "servers", "", "", "no product declares its logs here")
    assert collection_rows(beta, log_routes(d), (APP._replace(container="audit-tail"),))[1][3] == (
        "container audit-tail output")


def _plan(d, *sources):
    adapter = Adapter(name="product", kind="product", applies=None, required_roles=(), render_neutral=None,
                      render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                      vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(), importers=(),
                      profile_terms=None, access=None, logs=sources)
    return log_collection_check((adapter,))(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"),
                                                        None, dt.date(2026, 10, 1), {}, {}, ()))


def test_what_the_target_cant_collect_is_an_action():
    f = _plan(_record(), WEB, APP)
    assert [t for _, t, _, _ in f.actions] == [
        "Servers of role `web` in beta/prod record no install root (web-b1): the files log route `audit` collects "
        "from them can't be located, so nothing ships them. Record where the product is installed on each server "
        "(ciamInstallRoot)."]                              # the errors route: ops-logs isn't bound in beta
    assert [t for _, t, _, _ in _plan(_record(), APP, WEB._replace(kind="error")).actions] == [
        "Log route `audit` collects audit, admin logs, but in beta/prod nothing declares such a log for `web` on "
        "servers (its logs here hold only error): nothing ships them from there."]
    assert _plan(_record(), WEB._replace(path=None, on="kubernetes", server_role="app"),
                 WEB._replace(path="logs/x", kind="audit")).actions[0][1].startswith("Servers of role `web`")


def test_a_route_ships_per_install_root_to_the_binding_its_destination_role_names():
    d = _record()
    alpha, beta = env_model(d, "alpha/prod"), env_model(d, "beta/prod")
    assert under("/srv/web/", "/logs/x") == "/srv/web/logs/x"
    assert [(x.route.dn.split(",")[0], x.role, x.on, x.lines, x.destination.dn.split(",")[0], x.root, x.path, x.hosts)
            for x in shipments(alpha, log_routes(d), (WEB, APP))] == [
        ("cn=audit", "web", "servers", ALL, "cn=audit", "/opt/web", "/opt/web/logs/audit.log", ("web-1", "web-4")),
        ("cn=audit", "web", "servers", ALL, "cn=audit", "/srv/web/", "/srv/web/logs/audit.log", ("web-3",))]
    (container,) = shipments(beta, log_routes(d), (WEB, APP))          # web-b1 records no root: nothing on servers
    assert (container.role, container.on, container.lines, container.root, container.path, container.hosts) == (
        "app", "kubernetes", SOME, None, None, ())
    errors = WEB._replace(kind="error")
    (shipped,) = [x for x in shipments(alpha, log_routes(d), (errors,)) if x.hosts == ("web-3",)]
    assert shipped.destination is None                                 # alpha binds no ops-logs


def test_a_role_shipping_where_no_principal_lets_it_write_is_named():
    from opsdir.domains.access.naming import PERMISSION_SETS, PRINCIPALS
    d = _record()
    alpha = env_model(d, "alpha/prod")
    found = shipments(alpha, log_routes(d), (WEB, WEB._replace(kind="error")))
    assert unpermitted(alpha, found) == (("web", "audit-logs"), ("web", "ops-logs"))
    granted = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + "\n".join((*RECORDS,
        f"dn: {PERMISSION_SETS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: permission-sets\n",
        f"dn: cn=web-runtime,{PERMISSION_SETS}\nobjectClass: top\nobjectClass: ciamObject\n"
        "objectClass: ciamPermissionSet\ncn: web-runtime\nciamPermits: write-logs audit-logs\n",
        f"dn: {PRINCIPALS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: principals\n",
        f"dn: cn=web,{PRINCIPALS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamPrincipal\n"
        f"cn: web\nciamPrincipalKind: workload\nciamIdentityRole: identity-web\nciamTargetRole: web\n"
        f"ciamHoldsSet: cn=web-runtime,{PERMISSION_SETS}\n")))))
    alpha = env_model(granted, "alpha/prod")
    assert unpermitted(alpha, shipments(alpha, log_routes(granted), (WEB, WEB._replace(kind="error")))) == (
        ("web", "ops-logs"),)
