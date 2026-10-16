"""Cloud-managed directory services (ciamManagedDirectory, flow 76): a target holds the platform's user directory on
a managed Active Directory, a neighbour is a directory the platform binds to. The planner checks what the record needs
of a target (its own schema, password policies, secure LDAP, regions, trusts) against what the adapters declare of the
service, within its limits and editions; the record's base DNs, ACIs and users are actions."""
import datetime as dt

from opsdir.connectors.managed_directory import AREA, managed_directory_check
from opsdir.connectors import managed_service
from opsdir.core.contract import ManagedDirectory, PlanContext
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.directory.domain import DOMAIN
from opsdir.domains.directory.managed import (MANAGED_HEADERS, domain_dn, managed_rows, moved_bases, target_needs,
                                              trust_capability, words)
import mini_estate
from support import REGISTRY, applied, build_directory

BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
TEAM = "cn=ops,ou=owners,dc=ciam-ops"
CORP = "cn=corp-it,ou=owners,dc=ciam-ops"
DECLARED = "ou=declared,ou=config,dc=ciam-ops"
DIRECTORY = f"cn=user-dir,ou=bindings,{BETA}"

SPEC = ManagedDirectory(
    name="fake-ad", title="Fake AD", partition=lambda m: "gov" if m.cloud is not None and
    "gov-1" in (m.cloud.attrs.get("ciamRegion") or ()) else "com",
    available={"com": "the fake guide"}, absent={},
    supported={"ldap": "doc", "ldaps": "doc", "password-policies": "doc", "multi-region": "doc",
               "trust:forest:two-way": "doc"},
    unsupported={"schema-extension": "Microsoft runs its schema (fake FAQ)",
                 "trust:external:two-way": "forest trusts only (fake FAQ)"},
    partition_unsupported={}, conditions={"ldaps": "a certificate from the fake CA"},
    notes={"*": (("DNS", "Point the network's DNS at its controllers.", "Set it before joining machines."),)},
    users="Passwords come from the fake tenant.",
    limits={"password-policies": (2, "two predefined PSOs (fake guide)"), "regions": (2, "fake quota")},
    editions={"multi-region": (("enterprise",), "fake pricing")},
    default_base=lambda b: f"OU=FAKE,{domain_dn(b.attrs['ciamFqdn'][0])}" if b.attrs.get("ciamFqdn") else None)
CHECK = managed_directory_check((mini_estate.FAKE._replace(managed_directory=(SPEC,)),))
AS_OF = dt.date(2026, 10, 16)


def _entry(dn, *classes, **attrs):
    return (f"dn: {dn}\n" + "".join(f"objectClass: {c}\n" for c in ("top", *classes))
            + "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,))))


def _ou(dn):
    return _entry(dn, "organizationalUnit", ou=dn.split(",")[0].split("=")[1])


RECORD = (
    _ou("ou=owners,dc=ciam-ops"),
    _entry(TEAM, "ciamParty", cn="ops", ciamOwnerKind="team"),
    _entry(CORP, "ciamParty", cn="corp-it", ciamOwnerKind="team"),
    _ou("ou=unknowns,dc=ciam-ops"), _ou("ou=config,dc=ciam-ops"), _ou(DECLARED),
    _ou("ou=user-schema,dc=ciam-ops"), _ou("ou=consumers,dc=ciam-ops"), _ou("ou=acis,dc=ciam-ops"),
    _ou("ou=integrations,dc=ciam-ops"),
    _entry(f"cn=userData,{DECLARED}", "ciamBackend", cn="userData", ciamBackendType="je",
           ciamBaseDn="ou=people,dc=example,dc=test"),
    _entry(f"cn=default,{DECLARED}", "ciamPasswordPolicy", cn="default", ciamStorageScheme="PBKDF2"),
    _entry(f"cn=partners,{DECLARED}", "ciamPasswordPolicy", cn="partners", ciamStorageScheme="PBKDF2",
           ciamPopulation="partners"),
    _entry("cn=badge,ou=user-schema,dc=ciam-ops", "ciamUserAttribute", cn="badge", ciamLdapName="exBadge",
           ciamPiiClass="low", ciamLdapOid="1.3.6.1.4.1.32473.7.1"),
    _entry("cn=mail,ou=user-schema,dc=ciam-ops", "ciamUserAttribute", cn="mail", ciamLdapName="mail",
           ciamPiiClass="moderate"),
    _entry("cn=portal,ou=consumers,dc=ciam-ops", "ciamConsumer", cn="portal",
           ciamBindDn="uid=portal,ou=apps,dc=example,dc=test", ciamSubtreeRead="ou=people,dc=example,dc=test",
           ciamTlsOnly="TRUE"),
    _entry("cn=portal-read,ou=acis,dc=ciam-ops", "ciamAci", cn="portal-read",
           ciamAciTargetDn="ou=people,dc=example,dc=test", ciamAciRight="read",
           ciamAciGrantee="cn=portal,ou=consumers,dc=ciam-ops"),
    _entry("cn=hr-sync,ou=integrations,dc=ciam-ops", "ciamIntegration", cn="hr-sync", ciamProtocolType="ldap"),
    _entry(DIRECTORY, "ciamManagedDirectory", cn="user-dir", ciamBindingRole="user-dir", ciamManagedService="fake-ad",
           ciamRealizes="ds", ciamFqdn="corp.example.test", ciamDirectoryEdition="standard",
           ciamReplicaRegion="west-2", ciamOwner=TEAM),
    _entry(f"cn=onprem,{DIRECTORY}", "ciamDirectoryTrust", cn="onprem", ciamFqdn="hq.example.test",
           ciamTrustType="external", ciamTrustDirection="two-way", ciamManagedBy=CORP),
    _entry(f"cn=corp-ad,ou=bindings,{BETA}", "ciamManagedDirectory", cn="corp-ad", ciamBindingRole="corp-ad",
           ciamManagedService="fake-ad", ciamPartnerOf="cn=hr-sync,ou=integrations,dc=ciam-ops", ciamManagedBy=CORP),
)


def _directory(*extra, changes=()):
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORD, *extra)))), changes)


def _context(d):
    return PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())


def _texts(rows):
    return [r[1] for r in rows]


def _binding(d, name):
    return next(b for b in env_model(d, "beta/prod").bindings if b.dn.startswith(f"cn={name},"))


# ------------------------------------------------------------------ the model
def test_the_directory_domain_reports_managed_directories_and_imports_them():
    assert "managed-directory" in DOMAIN.reports
    assert ("managed-directory", "ciamManagedDirectory") in [(k.kind, k.object_class) for k in DOMAIN.import_kinds]


def test_the_report_has_a_row_per_binding_target_or_neighbour():
    rows = managed_rows(_directory())
    assert len(MANAGED_HEADERS) == len(rows[0])
    assert rows == [("beta/prod", "corp-ad", "fake-ad", "neighbour", "hr-sync", "", "", "", "", "corp-it", ""),
                    ("beta/prod", "user-dir", "fake-ad", "target", "ds", "corp.example.test", "standard", "west-2",
                     "hq.example.test (external, two-way)", "platform", "")]


def test_what_the_record_needs_of_a_target_is_read_from_it():
    d = _directory()
    needs = target_needs(d, _binding(d, "user-dir"))
    assert [n.capability for n in needs] == ["schema-extension", "password-policies", "multi-region",
                                             "trust:external:two-way"]
    assert "(`exBadge`)" in needs[0].cause and "`mail`" not in needs[0].cause     # standard attributes need nothing
    assert "2 password policies" in needs[1].cause and "`partners` for a population" in needs[1].cause
    assert words("trust:forest:one-way-outgoing") == "keep a one-way outgoing forest trust"
    assert trust_capability(next(e for e in d.entries.values() if e.dn.startswith("cn=onprem,"))) == \
        "trust:external:two-way"
    assert domain_dn("corp.example.test") == "DC=corp,DC=example,DC=test"


def test_base_dns_move_under_the_writable_ou_with_the_consumers_naming_them():
    d = _directory()
    (old, consumers), = moved_bases(d, "OU=FAKE,DC=corp,DC=example,DC=test")
    assert old == "ou=people,dc=example,dc=test" and [c.dn for c in consumers] == ["cn=portal,ou=consumers,dc=ciam-ops"]
    assert moved_bases(d, "dc=example,dc=test") == ()


# ------------------------------------------------------------------ the planner
def test_documented_gaps_block_and_limits_and_editions_are_checked():
    blockers = _texts(CHECK(_context(_directory())).blockers)
    assert any("the record defines attribute types and object classes of its own (`exBadge`), so `user-dir` (Fake AD) "
               "in beta/prod must take attribute types and object classes of the record's own (a schema extension "
               "under their OIDs), which Fake AD can't (Microsoft runs its schema (fake FAQ))." in t for t in blockers)
    assert any("keep a two-way external trust, which Fake AD can't (forest trusts only (fake FAQ))" in t
               for t in blockers)
    assert any("which Fake AD does only on the enterprise edition (fake pricing), and it records standard" in t
               for t in blockers)
    # two policies fit two PSOs; the two regions fit the quota
    assert not any("takes at most" in t for t in blockers)
    three = _directory(_entry(f"cn=staff,{DECLARED}", "ciamPasswordPolicy", cn="staff", ciamStorageScheme="PBKDF2"))
    assert "`user-dir` in beta/prod needs 3 password policies, and Fake AD takes at most 2 (two predefined PSOs " \
        "(fake guide)): reduce them in the record, or hold the user directory elsewhere." in \
        _texts(CHECK(_context(three)).blockers)


def test_a_capability_no_documentation_establishes_proposes_its_question():
    internet = _directory(changes=parse(f"dn: {DIRECTORY}\nchangetype: modify\nadd: ciamLdapsMode\n"
                                        "ciamLdapsMode: internet\n"))
    m, b = env_model(internet, "beta/prod"), _binding(internet, "user-dir")
    name = managed_service.question_name(m, b, "ldaps-internet")
    found = CHECK(_context(internet))
    assert any("serve LDAPS to clients on the internet, and no vendor documentation establishes that it can" in t and
               f"question `{name}`" in t for t in _texts(found.blockers))
    fix = next(f for f in found.fixes if f.key == f"unknown:{name}")
    assert "(the directory's record, or where the user directory is held)" in fix.manual[0]
    answer = parse(f"dn: cn={name},ou=unknowns,dc=ciam-ops\nchangetype: modify\nadd: ciamAnswer\n"
                   "ciamAnswer: The vendor confirms internet LDAPS (case 7)\n")
    confirmed = CHECK(_context(applied(applied(internet, fix.records), answer)))
    assert any(f"confirmed in question `{name}`" in t for t in confirmed.ok)
    # secure LDAP itself is supported on a condition: an action
    assert any("which Fake AD does on a condition: a certificate from the fake CA" in t
               for t in _texts(found.actions))


def test_what_doesnt_carry_is_actions():
    actions = _texts(CHECK(_context(_directory())).actions)
    assert any("entries under `ou=people,dc=example,dc=test` land under `OU=FAKE,DC=corp,DC=example,DC=test`" in t
               and "change them: `portal`." in t for t in actions)
    assert any("The record's ACIs (`portal-read`) don't carry onto `user-dir`" in t for t in actions)
    assert any("`portal` connect only with TLS, and `user-dir` in beta/prod records no secure LDAP" in t
               for t in actions)
    assert any("Point the network's DNS at its controllers. Set it before joining machines." in t for t in actions)
    assert any(t.startswith("User accounts and passwords don't move with the directory's configuration onto "
                            "`user-dir` (Fake AD) in beta/prod: Passwords come from the fake tenant.") for t in actions)
    unnamed = managed_directory_check((mini_estate.FAKE._replace(managed_directory=(
        SPEC._replace(default_base=lambda b: None),)),))
    assert any("records no OU the platform writes in: record it (ciamWritableBase)" in t
               for t in _texts(unnamed(_context(_directory())).actions))


def test_a_target_must_realize_the_directory_role():
    wrong = _directory(changes=parse(f"dn: {DIRECTORY}\nchangetype: modify\nreplace: ciamRealizes\n"
                                     "ciamRealizes: am\n"))
    assert any("`user-dir` in beta/prod realizes `am`: a managed directory holds the user directory (ciamRealizes ds)"
               in t for t in _texts(CHECK(_context(wrong)).blockers))


def test_a_neighbour_serves_its_partner_integrations_and_its_ok_line_names_its_keeper():
    found = CHECK(_context(_directory()))
    assert "`corp-ad` (Fake AD, kept by corp-it) in beta/prod is a neighbour directory: partner of `hr-sync`; " \
        "trusts: none." in found.ok
    assert "`user-dir` holds the user directory on Fake AD in beta/prod: corp.example.test, standard, west-2; " \
        "trusts: `hq.example.test`." in found.ok


def test_a_service_the_partition_lacks_and_an_undeclared_one_block():
    gov = _directory(changes=parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\n"
                                   "replace: ciamRegion\nciamRegion: gov-1\n"))
    absent = managed_directory_check((mini_estate.FAKE._replace(managed_directory=(
        SPEC._replace(absent={"gov": "commercial only (fake guide)"}),)),))
    assert "`user-dir` in beta/prod (gov) is Fake AD, which doesn't exist there (commercial only (fake guide)). Hold " \
        "the user directory elsewhere (keep it on its current product, or choose a service the partition has), or " \
        "record the environment's cloud correctly." in _texts(absent(_context(gov)).blockers)
    assert any("no vendor documentation establishes that it exists there" in t
               for t in _texts(CHECK(_context(gov)).blockers))
    bare = managed_directory_check((mini_estate.FAKE,))
    assert any("is `fake-ad`, which no adapter rendering beta/prod declares" in t
               for t in _texts(bare(_context(_directory())).blockers))
    assert AREA == "Managed directory"
