# opsdir-adapter-siteminder

The Broadcom SiteMinder (formerly CA Single Sign-On) adapter, for SiteMinder as the **source** of a migration: its policy store's export read into the record on the standard bases, what has no standard equivalent carried as data the plan acts on, and the planner's checks for a plan from an environment that runs it. It renders nothing: SiteMinder is what a migration leaves.

**Applies to** environments whose servers run SiteMinder: `ciamProductVersion` `SiteMinder <version>` (Policy Server), `SiteMinder Web Agent <version>`, `SiteMinder Access Gateway <version>`, each in `>=12.8,<13` (12.8 service packs and 12.9). Server roles it defines (`ciamServerRole` / `ciamTargetRole`): `sm-policy-server`, `sm-agent` (a web server running a Web Agent), `sm-access-gateway` (Access Gateway / SPS).

**Depends on** `opsdir` only (the standard library's XML parser, through `opsdir.core.sources.xml_document`).

## What it reads

Importer `siteminder/xps`: every `*.xml` file given, as `XPSExport` writes it (the whole store with `-xb`, or parts; `opsdir import --change <id> siteminder/xps <folder>`). The export is the operator's: XPSExport runs on a Policy Server as its administrator (no read-only role is documented for it), so there is no collector. A document declaring a DOCTYPE or an entity is refused; an export whose root names a release outside `>=12.8,<13` is refused whole, its version named (12.51 and 12.52 are 12.5 service packs: older).

| In the export | In the record |
|---|---|
| Policy domain (`CA.SM::Domain`) | `smPolicyDomain` at `cn=<name>,ou=domains,ou=siteminder` (its subtree is the import's) |
| Realm (`CA.SM::Realm`, nested ones too) | `smRealm` under the domain's `ou=realms`: resource filter, its agent (`smAgent`), its authentication scheme (`smAuthScheme`), idle and maximum session timeouts; a nested realm is named after its parent (`crew-admin`) |
| Rule (`CA.SM::Rule`) | `smRule` below its realm: resource, regex or not, actions, allow or deny, enabled |
| Policy (`CA.SM::Policy`, its `PolicyLink` and `UserPolicy` children) | `smPolicy` under the domain's `ou=policies`: the rules it grants, the responses it returns, its user selections (`smSubject` `<directory> <kind> <value>`) |
| Response attribute that is an HTTP header (`WebAgent-HTTP-Header-Variable`) | the edge domain's **header contract** (`ciamHeaderContract`, `cn=<domain>-<header>`): set by `sm-agent`, value from a user attribute or the user's DN (`identity`); a fixed value is withheld (an application trusting a fixed header is trusting a shared secret). Who trusts it and whether the agent strips the client's own copy aren't in the export: the record says so (the edge checks then act) |
| Authentication scheme (`CA.SM::AuthScheme`) | `smAuthScheme` at `ou=auth-schemes,ou=siteminder`: type, protection level, library |
| User directory (`CA.SM::UserDirectory`) | `smUserDirectory` at `ou=user-directories,ou=siteminder`: namespace, the role its servers are in the record (a service name or external host, `hosts_role`) and their port, the **directory consumer** it binds as (`smConsumer`, by bind DN; a notice when no consumer records it) |
| Agent (`CA.SM::Agent`) | `smAgent` at `ou=agents,ou=siteminder`, with the server role it runs on (`ciamTargetRole`: `sm-access-gateway` for an SPS / Access Gateway type, else `sm-agent`; a role the record sets is kept) |
| SAML partnership, SiteMinder the IdP (`CA.FED::SPPartnership`) | a **`saml2-sp` integration**: the partner's entity ID, ACS URL and binding, NameID formats, the claims of its assertion attributes linked to their user-schema records (others named in a notice), the certificate it signs with when the record holds it (by fingerprint) |
| SAML partnership, SiteMinder the SP (`CA.FED::IDPPartnership`) | a **`saml2-idp` integration**: entity ID, SSO URL, binding, NameID formats |
| OIDC client (`CA.FED::OIDCClient`) | an **`oidc-client` integration**: client ID, redirect URIs, grant types and token endpoint methods in the standard vocabulary, scopes (its secret withheld) |
| SiteMinder's local federation entity | the identity service new integrations are served by (`ciamServedBy`): the record's service with that entity ID, else `cn=siteminder,ou=identity-services` from the entity and its base URL (role `sm-policy-server`) |
| What has no standard equivalent | a **source object** (core `ciamSourceObject` at `ou=siteminder,ou=source-objects`, below) |

Integrations the record already holds (matched by entity ID or client ID) keep what the record says of them; that SiteMinder federates with them too is a notice. The generated runtime objects of a partnership (`CA.SM::SAMLv2SP`) aren't read twice. Every entry the import makes carries auxiliary class `smObject`: its XID, its XPS class, the settings not mapped to an attribute of their own (`smConfig`, JSON) and what was withheld (`smWithheld`). A link to an object the export doesn't hold is named (export it whole, or with its dependencies); a realm, rule or policy outside a domain the export holds isn't read. A re-import changes nothing; owners and the handling a change records are kept.

### Source objects (carried, not dropped)

| Object | Handling (`ciamHandling`) | Held by | A move waits? |
|---|---|---|---|
| Agent configuration object (`CA.SM::AgentConfig`) | rebuild: its settings become the target gateway's or agent's | `sm-agent` | no |
| Host configuration object (`CA.SM::HostConfig`) | retire: agents' list of policy servers | `sm-agent` | no |
| Trusted host (`CA.SM::TrustedHost`) | re-register: each web server registers with what protects it | `sm-agent` | no |
| Agent instance (`CA.SM::AgentInstance`) | retire | `sm-agent` | no |
| Password policy (`CA.SM::PasswordPolicy`) | review: its rules and the password history it keeps in the directory (encrypted with the session key) | `sm-policy-server` | no |
| Administrators and their rights | review: re-created in the target's admin model | `sm-policy-server` | no |
| OpenID provider configuration (`CA.FED::OIDCAdminConfig`) | rebuild in the target's OpenID provider | `sm-policy-server` | no |
| Custom authentication scheme (type *Custom*) | rebuild: the operator's own sign-on code | `sm-policy-server` | **yes** (concerns the realms using it) |
| Cookie response (`WebAgent-HTTP-Cookie-Variable`) / any other response | rebuild / review in the target gateway's identity mapping | `sm-agent` | no |
| An Access Gateway agent's routing | rebuild: its proxy rules aren't in the policy store | `sm-access-gateway` | **yes** |
| The keys (one object, whenever the export has agents, hosts or partnerships) | re-provision: agent and session keys (`smkeyexport`) and federation keys (the certificate data store) are never in an XPSExport | `sm-policy-server` | no |
| Any class this adapter doesn't map | review | `sm-policy-server` | no |

`opsdir report source-objects` lists them; the core planner check (`check_source_objects`) makes each an action for its owner, or a blocker when the move waits for it, for a target that doesn't run the role holding it.

## Secrets

Never stored, neither the value nor its ciphertext. `XPSExport -npass` writes sensitive settings in **clear text**; `-pass` encrypts them with a passphrase: either way the import withholds them. A setting is withheld when its name is a sensitive one (password, secret, passphrase, private key: SiteMinder publishes no per-class list), when its value looks encrypted (a `{cipher}` prefix) or when the store's secret patterns match it; a header response's fixed value too. The entry records only that it existed, what it is and that the target re-provisions it (`smWithheld`, e.g. `Password: the bind password of the connection; re-provision in the target`), and every import says how many it withheld and that the export file must be treated as a secret. Agent keys, the session key and federation keys aren't in an XPSExport at all (`smkeyexport`, `smkeytool`): the `keys` source object says so.

## Planner checks

Run when the adapter applies to a plan's **source** (`source_checks`):

- `check_realms`: a **blocker** for every realm whose agent's role the source runs and the target doesn't: its rules, the policies granting them, its sign-on scheme and the headers the application trusts stop. Protect those resources with a gateway or access product the target runs, then retire the realm.
- `check_user_directories`: an **action** for every user directory binding as an account no directory consumer records.

The core checks the rest: integrations still served by SiteMinder's identity service (federation: blocks until re-homed), its header contracts (edge: a setter the target doesn't run blocks; a client-sendable identity header is an action), its source objects (governance) and its bind account (directory consumers).

## Schema

Under this package's OID arc `1.3.6.1.4.1.32473.3.6` (prefix `sm`, `schema.py`): 24 attributes, classes `smObject` (auxiliary), `smPolicyDomain`, `smRealm`, `smRule`, `smPolicy`, `smAuthScheme`, `smUserDirectory`, `smAgent`. They map one to one onto the planned neutral protected-web-application layer (realm: an application's path, enforcement point, sign-on and session; rule: a path rule with methods and an effect; policy: who it admits, and the headers it sets), which PingAccess and PingGateway will share.

## Known limits

- **The XPS names are unverified for 12.8 and 12.9.** The layout and the class and property names come from Broadcom's archived 12.51 XPS reference and knowledge-base articles quoting 12.8 exports; Broadcom's current XPSExport page wasn't readable. Every name the adapter reads is data in `xps.py` (`KINDS`, `FIELDS`, the response types, `VERSION_ATTRIBUTES`), so a real export that names them otherwise is fixed there. The tests and the showcase's export are built from the documented shapes, not taken from a real policy store. **Acceptance items** (a real 12.8 SP and 12.9.1 `-xb` export, with `-pass` and with `-npass`): the root element's version attribute; the property names of realms, rules, policies and their links, user policies, responses and response attributes (in particular whether the agent type of a response attribute is a link to an `AgentTypeAttr` object rather than a name), user directories, authentication schemes, agents and agent types, partnerships (local and remote entities, ACS and SSO endpoints, bindings, NameID, assertion attributes, certificates), OIDC clients; the IdP-side partnership class name; how `-pass` writes an encrypted value (the `{cipher}` prefix is assumed) and which properties it marks sensitive; federation objects `-xp` may leave out (a 12.52 SP1 limitation: select `PartnershipBase*` XIDs).
- **Policy objects stay in this package's schema** until the neutral protected-web-application layer exists (a later milestone): no target product renders them yet, so `check_realms` blocks until something the target runs protects those resources.
- **Not read**: the admin policy REST API (`/ca/api/sso/services/policy/v1/`: needs a legacy administrator; its coverage is unverified), Web Agent files (`WebAgent.conf`, `SmHost.conf`), Access Gateway proxy rules (`proxyrules.xml`: carried as a blocking source object), the key store, the session and audit stores, the certificate data store's contents (certificates are linked only when the record holds them).
- **Responses' other types, variables, active rules and expressions** beyond `userattr` and `userdn` are kept as source objects to review or in `smConfig`, not interpreted.
- **One identity service per export**: partnerships of several local entities are served by the first (a notice names the others).
- **Versions**: an export naming no release is read (the servers' recorded versions apply); a server's `ciamProductVersion` is compared as PEP 440, so record 12.52 as `12.5.2`.

## Tests

`tests/test_siteminder.py` with the synthetic export `tests/xps/policy-store.xml`: registration and applicability, every mapping above, nested realms and XREF references, held integrations kept, every sensitive value absent from what is stored, DOCTYPE and other releases refused, unresolved links named, a re-import changing nothing and keeping the record's handling, the source checks and the core source-object check. The core's `opsdir/tests/unit/test_source_objects.py` covers source objects, the federation check and the planner hook.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-siteminder/tests
```

In this repository: `opsdir/scripts/dev-install.sh`.
