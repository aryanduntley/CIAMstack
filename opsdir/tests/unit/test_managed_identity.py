"""Cloud-managed identity services (ciamManagedIdentity, flow 63): a target runs one of the platform's identity
services on a managed service, a neighbour is the partner side of integrations; issuer or relying party follows from
the integrations' protocol types. The planner checks a target against what the adapters declare of the service:
documented-unsupported gaps block with no way out but changing the record, gaps no documentation establishes block
until a question of the unknowns register (its name given, its fix proposed) is answered."""
import datetime as dt

from opsdir.connectors.managed_identity import AREA, managed_identity_check, question_name
from opsdir.connectors.importing import import_changes
from opsdir.core.contract import Imported, ManagedService, PlanContext
from opsdir.core.inventory import environment_groups, resource
from opsdir.core.directory import get, one
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.federation.checks import check_identity_services
from opsdir.domains.federation.domain import DOMAIN
from opsdir.domains.federation.managed import (MANAGED_HEADERS, integration_needs, managed_rows, roles, slug,
                                               status, UNESTABLISHED, UNSUPPORTED, SUPPORTED)
import mini_estate
from support import REGISTRY, applied, build_directory

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
TEAM = "cn=ops,ou=owners,dc=ciam-ops"
APPS = "cn=apps,ou=owners,dc=ciam-ops"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

SPEC = ManagedService(
    name="fake-pool", title="Fake pool", partition=lambda m: "gov" if one(m.cloud, "ciamRegion") == "gov-1" else "com",
    available={"com": "the fake guide"}, absent={"gov": "the fake guide: commercial only"},
    supported={"issue:oidc": "doc", "trust:saml": "doc", "trust:oidc": "doc", "grant:authorization_code": "doc",
               "grant:client_credentials": "doc", "token-auth:none": "doc", "signing-alg:RS256": "doc",
               "custom-domain": "doc"},
    unsupported={"issue:saml": "no SAML IdP (fake doc)", f"grant:{EXCHANGE}": "no token exchange (fake doc)",
                 "custom-issuer": "its own issuer (fake doc)", "mfa-per-client": "pool-wide MFA (fake doc)"},
    partition_unsupported={}, conditions={"grant:client_credentials": "the M2M add-on"},
    notes={"*": (("flows", "Its journeys are its own.", "Recreate them."),)}, users="Users reset.")
CHECK = managed_identity_check((mini_estate.FAKE._replace(managed_identity=(SPEC,)),))


def _entry(dn, *classes, **attrs):
    return (f"dn: {dn}\n" + "".join(f"objectClass: {c}\n" for c in ("top", *classes))
            + "".join(f"{k}: {v}\n" for k, vs in attrs.items() for v in (vs if isinstance(vs, tuple) else (vs,))))


def _integration(cn, protocol, **attrs):
    return _entry(f"cn={cn},ou=integrations,dc=ciam-ops", "ciamIntegration", cn=cn, ciamProtocolType=protocol,
                  ciamOwner=APPS, **attrs)


RECORD = (
    _entry("ou=owners,dc=ciam-ops", "organizationalUnit", ou="owners"),
    _entry(TEAM, "ciamParty", cn="ops", ciamOwnerKind="team"),
    _entry(APPS, "ciamParty", cn="apps", ciamOwnerKind="team"),
    _entry("ou=unknowns,dc=ciam-ops", "organizationalUnit", ou="unknowns"),
    _entry("ou=integrations,dc=ciam-ops", "organizationalUnit", ou="integrations"),
    _integration("portal", "oidc-client", ciamClientId="portal", ciamGrantType=("authorization_code", EXCHANGE),
                 ciamTokenAuthMethod="none", ciamDpopBound="TRUE", ciamRedirectUri="https://portal.example.test/cb",
                 ciamMfaRequired="TRUE"),
    _integration("batch", "oidc-client", ciamClientId="batch", ciamGrantType="client_credentials",
                 ciamTokenAuthMethod="none"),
    _integration("crm", "saml2-sp", ciamEntityId="https://crm.example.test", ciamAcsUrl="https://crm.example.test/a"),
    _integration("partner", "saml2-idp", ciamEntityId="https://idp.partner.test",
                 ciamSsoUrl="https://idp.partner.test/sso"),
    _integration("app-pool", "oidc-client", ciamClientId="app",
                 ciamServedBy="cn=other,ou=identity-services,dc=ciam-ops"),
    _entry("cn=other,ou=identity-services,dc=ciam-ops", "ciamIdentityService", cn="other",
           ciamBaseUrl="https://other.example.test"),
    _entry(f"cn=sso-pool,ou=bindings,{BETA}", "ciamManagedIdentity", cn="sso-pool", ciamBindingRole="sso-pool",
           ciamManagedService="fake-pool", ciamRealizes="sso", ciamFqdn="sso.example.test", ciamOwner=TEAM),
    _entry(f"cn=app-team-pool,ou=bindings,{BETA}", "ciamManagedIdentity", cn="app-team-pool",
           ciamBindingRole="app-team-pool", ciamManagedService="fake-pool",
           ciamPartnerOf=("cn=app-pool,ou=integrations,dc=ciam-ops", "cn=partner,ou=integrations,dc=ciam-ops"),
           ciamManagedBy=APPS),
)
AS_OF = dt.date(2026, 10, 15)


def _directory(*extra, changes=()):
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *RECORD, *extra)))), changes)


def _context(d):
    return PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF, {}, {}, ())


def _texts(rows):
    return [r[1] for r in rows]


# ------------------------------------------------------------------ the model
def test_the_federation_domain_reports_managed_identities_and_imports_them():
    assert "managed-identity" in DOMAIN.reports
    assert [(k.kind, k.object_class) for k in DOMAIN.import_kinds] == [("managed-identity", "ciamManagedIdentity")]


def test_a_cloud_read_of_a_binding_keeps_the_sign_in_flows_and_extensions_beneath_it():
    # another importer's entries (a tenant's Graph configuration) beneath a binding a cloud read reports
    pool = f"cn=sso-pool,ou=bindings,{BETA}"
    beneath = (_entry(f"cn=loyalty,{pool}", "ciamAuthExtension", cn="loyalty",
                      ciamExtensionEvent="token-issuance-start", ciamExtensionClaim="tier"),
               _entry(f"cn=sign-up,{pool}", "ciamSignInFlow", cn="sign-up", ciamSignInMethod=("email-otp", "sign-up"),
                      ciamFlowApplications="cn=portal,ou=integrations,dc=ciam-ops",
                      ciamFlowExtension=f"cn=loyalty,{pool}", ciamCollectedAttribute="email"))
    d = _directory(*beneath)
    read = resource("managed-identity", "pool-1", {"ciamManagedService": "fake-pool", "ciamRealizes": "sso"},
                    role="sso-pool")
    groups, _ = environment_groups(d, "beta/prod", (read,))
    (scope, (binding, *kept)), = groups
    assert scope == pool and one(binding, "ciamProviderRef") == "pool-1"
    assert sorted(e.dn for e in kept) == sorted((f"cn=loyalty,{pool}", f"cn=sign-up,{pool}"))
    assert not [r for r in import_changes(d, Imported((), groups, ())) if r.changetype == "delete"]


def test_issuer_and_relying_party_follow_from_the_protocol_types():
    d = _directory()
    m = env_model(d, "beta/prod")
    target, neighbour = (next(b for b in m.bindings if b.dn.startswith(f"cn={n},")) for n in ("sso-pool",
                                                                                              "app-team-pool"))
    # a target issues to the oidc-client and saml2-sp integrations it serves and relies on the saml2-idp ones
    assert roles(d, target) == (("batch", "crm", "portal"), ("partner",))      # DN order
    # a neighbour partner of an oidc-client relies on the platform; partner of a saml2-idp issues to it
    assert roles(d, neighbour) == (("partner",), ("app-pool",))
    assert integration_needs(get(d, "cn=partner,ou=integrations,dc=ciam-ops"), as_partner=True) == ("issue:saml",)


def test_the_report_has_a_row_per_binding_target_or_neighbour():
    rows = managed_rows(_directory())
    assert len(MANAGED_HEADERS) == len(rows[0])
    assert rows == [("beta/prod", "app-team-pool", "fake-pool", "neighbour", "app-pool, partner", "partner", "app-pool",
                     "apps", ""),
                    ("beta/prod", "sso-pool", "fake-pool", "target", "sso", "batch, crm, portal", "partner",
                     "platform", "")]


def test_a_capability_is_documented_supported_unsupported_or_not_established():
    assert status(SPEC, "com", "issue:oidc") == (SUPPORTED, "doc")
    assert status(SPEC, "com", "issue:saml") == (UNSUPPORTED, "no SAML IdP (fake doc)")
    assert status(SPEC, "com", "dpop-bound") == (UNESTABLISHED, None)
    assert status(SPEC._replace(partition_unsupported={"gov": {"custom-domain": "not there"}}), "gov",
                  "custom-domain") == (UNSUPPORTED, "not there")
    assert slug(f"grant:{EXCHANGE}") == "grant-token-exchange"


# ------------------------------------------------------------------ the planner
def test_documented_gaps_block_with_no_confirmation_path():
    found = CHECK(_context(_directory()))
    blockers = _texts(found.blockers)
    assert any("`crm` (saml2-sp) needs `sso-pool` (Fake pool, running `sso` in beta/prod) to act as a SAML identity "
               "provider to service providers, which Fake pool can't (no SAML IdP (fake doc))." in t for t in blockers)
    assert any("accept the token-exchange grant, which Fake pool can't (no token exchange (fake doc))" in t
               for t in blockers)
    unknown_keys = {f.key for f in found.fixes}
    assert not any("saml" in k or "token-exchange" in k for k in unknown_keys)


def test_a_gap_no_documentation_establishes_blocks_and_proposes_its_question():
    d = _directory()
    m = env_model(d, "beta/prod")
    binding = next(b for b in m.bindings if b.dn.startswith("cn=sso-pool,"))
    name = question_name(m, binding, "dpop-bound")
    assert name == "confirm-beta-prod-sso-pool-dpop-bound"
    found = CHECK(_context(d))
    assert any(f"bind access tokens to DPoP proofs (RFC 9449), and no vendor documentation establishes that it can"
               in t and f"question `{name}`" in t for t in _texts(found.blockers))
    fix = next(f for f in found.fixes if f.key == f"unknown:{name}")
    record = fix.records[0]
    assert record.dn == f"cn={name},ou=unknowns,dc=ciam-ops"
    assert record.attrs["ciamBlocking"] == ("TRUE",) and record.attrs["ciamOwner"] == (APPS,)
    assert set(record.attrs["ciamConcerns"]) == {binding.dn, "cn=portal,ou=integrations,dc=ciam-ops"}


def test_an_answered_question_clears_the_gap_and_an_open_blocking_one_is_the_registers():
    d = _directory()
    m = env_model(d, "beta/prod")
    binding = next(b for b in m.bindings if b.dn.startswith("cn=sso-pool,"))
    name = question_name(m, binding, "dpop-bound")
    fix = next(f for f in CHECK(_context(d)).fixes if f.key == f"unknown:{name}")
    asked = applied(d, fix.records)
    assert not any(name in t for t in _texts(CHECK(_context(asked)).blockers))      # the register's blocker now
    answer = parse(f"dn: cn={name},ou=unknowns,dc=ciam-ops\nchangetype: modify\nadd: ciamAnswer\n"
                   "ciamAnswer: The vendor confirms DPoP-bound tokens (case 42)\n")
    found = CHECK(_context(applied(asked, answer)))
    assert not any("DPoP" in t for t in _texts(found.blockers))
    assert any(f"confirmed in question `{name}`: The vendor confirms DPoP-bound tokens (case 42)" in t
               for t in found.ok)


def test_supported_on_a_condition_users_and_notes_are_actions():
    actions = _texts(CHECK(_context(_directory())).actions)
    assert any("`batch` (oidc-client)" in t and "on a condition: the M2M add-on" in t for t in actions)
    assert any(t.startswith("User accounts and passwords don't move with `sso`'s configuration") for t in actions)
    assert any("Its journeys are its own. Recreate them." in t for t in actions)
    # portal requires MFA and the others don't: the pool can't require it per application
    assert any("`portal` require MFA" in t for t in actions)


def test_published_hosts_are_kept_by_a_custom_domain_never_by_an_issuer_the_service_owns():
    found = CHECK(_context(_directory()))
    assert "`sso-pool` keeps `sso`'s published host `sso.example.test` in beta/prod." in found.ok
    assert any("`sso` publishes `sso.example.test` (its issuer), so `sso-pool` in beta/prod must issue tokens under a "
               "custom issuer, which Fake pool can't (its own issuer (fake doc))" in t for t in _texts(found.blockers))
    moved = _directory(changes=parse(f"dn: cn=sso-pool,ou=bindings,{BETA}\nchangetype: modify\nreplace: ciamFqdn\n"
                                     "ciamFqdn: login.example.test\n"))
    assert any("records no such domain: record the domain it serves sign-in at (ciamFqdn sso.example.test)" in t
               for t in _texts(CHECK(_context(moved)).blockers))


def test_a_service_the_partition_lacks_blocks():
    gov = _directory(changes=parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\n"
                                   "replace: ciamRegion\nciamRegion: gov-1\n"))
    blockers = _texts(CHECK(_context(gov)).blockers)
    assert "`sso-pool` in beta/prod (gov) is Fake pool, which doesn't exist there (the fake guide: commercial only). " \
        "Run the identity service elsewhere (keep it on its current product, or choose a service the partition has), " \
        "or record the environment's cloud correctly." in blockers
    elsewhere = _directory(changes=parse("dn: cloud=beta,ou=environments,dc=ciam-ops\nchangetype: modify\n"
                                         "replace: ciamRegion\nciamRegion: gov-1\n"))
    unknown = managed_identity_check((mini_estate.FAKE._replace(managed_identity=(SPEC._replace(absent={}),)),))
    assert any("no vendor documentation establishes that it exists there" in t
               for t in _texts(unknown(_context(elsewhere)).blockers))


def test_a_neighbour_plays_the_part_its_integrations_give_it():
    found = CHECK(_context(_directory()))
    assert "`app-team-pool` (Fake pool, kept by apps) in beta/prod is a neighbour: issuer to the platform for " \
        "`partner`; relying party of the platform for `app-pool`." in found.ok
    # partner of a saml2-idp integration: the neighbour would have to issue SAML, which the pool can't
    assert any("`app-team-pool` (Fake pool) in beta/prod is the partner side of `partner` (saml2-idp), so it must act "
               "as a SAML identity provider to service providers, which Fake pool can't" in t
               for t in _texts(found.blockers))


def test_a_service_no_adapter_declares_blocks():
    bare = managed_identity_check((mini_estate.FAKE,))
    assert any("is `fake-pool`, which no adapter rendering beta/prod declares" in t
               for t in _texts(bare(_context(_directory())).blockers))


def test_the_service_name_check_leaves_a_realized_identity_service_to_the_managed_check():
    d = _directory()
    plain = check_identity_services(_context(mini_estate.directory()))
    assert any("`sso`" in t for t in plain.ok)
    assert not any("`sso`" in t for t in (*check_identity_services(_context(d)).ok,
                                          *_texts(check_identity_services(_context(d)).blockers)))
    assert AREA == "Managed identity"
