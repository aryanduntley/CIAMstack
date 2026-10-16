# opsdir-adapter-siteminder

The Broadcom SiteMinder (formerly CA Single Sign-On) adapter, for SiteMinder as the **source** of a migration: its policy store's export read into the record on the standard bases, what has no standard equivalent carried as data the plan acts on, and the planner's checks for a plan from an environment that runs it. It renders nothing: SiteMinder is what a migration leaves.

**Applies to** environments whose servers run SiteMinder: `ciamProductVersion` `SiteMinder <version>` (Policy Server), `SiteMinder Web Agent <version>`, `SiteMinder Access Gateway <version>`, each in `>=12.8,<13` (12.8 service packs and 12.9). Server roles it defines (`ciamServerRole` / `ciamTargetRole`): `sm-policy-server`, `sm-agent` (a web server running a Web Agent), `sm-access-gateway` (Access Gateway / SPS).

**Depends on** `opsdir` only (the standard library's XML parser, through `opsdir.core.sources.xml_document`).

## What it reads

Two importers: `siteminder/xps`, the policy store's export (below), and `siteminder/agent-files`, the agents' and
Access Gateways' own files ([Agent and gateway files](#agent-and-gateway-files)). Read the export first: what the files
name is linked only when the record holds it.

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
| An Access Gateway agent's routing | rebuild: its proxy rules aren't in the policy store; dropped once the record holds the gateway's routes (its agent files) | `sm-access-gateway` | **yes** |
| An Access Gateway route sending another path (`rewrite-<application>`, agent files) | rebuild: the neutral layer has no backend path | `sm-access-gateway` | **yes** (concerns the application) |
| The keys (one object, whenever the export has agents, hosts or partnerships) | re-provision: agent and session keys (`smkeyexport`) and federation keys (the certificate data store) are never in an XPSExport | `sm-policy-server` | no |
| Any class this adapter doesn't map | review | `sm-policy-server` | no |

The ACO's source object also keeps its settings (`smConfig`): the agents' settings are read from it. Once a server's
agent files are read, the ACO, HCO and trusted host source objects concern the servers whose files name them
(`ciamConcerns`).

`opsdir report source-objects` lists them; the core planner check (`check_source_objects`) makes each an action for its owner, or a blocker when the move waits for it, for a target that doesn't run the role holding it.

### The neutral layer (`neutral.py`)

Every import also projects the policy store onto the neutral protected-application layer (core domain `webaccess`),
so a plan can move what SiteMinder protects to a product the target runs:
- A realm becomes `ciamProtectedApp` `<domain>-<realm>`:
  - its resource filter is the base path;
  - enforced by its agent's role, with no backend (a web agent runs in the application's own web server);
  - sign-on from its authentication scheme's type (`xps.SCHEME_SIGN_ONS`: HTML form, basic, X.509 certificate, a
    SAML/JWT/OpenID journey as `federated`, custom);
  - its idle and maximum timeouts;
  - the header contracts of the responses its granting policies return.
- Each enabled rule becomes a `ciamPathResource`:
  - its resource below the realm's (`*` a wildcard, `?` making it a regex, a regex as written with a leading copy of
    the realm's filter dropped);
  - the HTTP methods among its actions (event actions are named in a notice);
  - unprotected when the realm's `ProtectAll` is false;
  - the access rules of the enabled policies granting it.
- Each enabled policy becomes `ciamAccessRule` `<domain>-<policy>`:
  - it allows its user selections (group, user, filter; every user of a directory: `authenticated`);
  - `<domain>-<policy>-deny` holds the deny rules it grants;
  - a selection of another kind makes the rule `custom`.

The service names clients reach a realm at, the application behind a gateway that takes it over, and the integration
that gateway signs users in as aren't in an export: the record adds them, and the import keeps them.

The agent files add (`agents.py`, `routing.py`; one projection over the whole record, which both importers run):
- the extensions and URLs an agent passes through unprotected (`IgnoreExt`, `IgnoreUrl`: its ACO's, or its
  `LocalConfig.conf`'s where the ACO allows it) as `unprotected` path resources of every application its realms
  become, projected from the agent: an extension anywhere below the base path (`/*.gif`), a URL exactly (a URL takes
  no wildcard, KB 44956: matching it exactly is the conservative reading); what its instances don't all pass through
  is left out, and a notice names them;
- a gateway application's backend role, port and TLS from the first route every request of it takes (its virtual
  host's names and its base path decide; a condition on a query, header or cookie, or one only part of it meets, is
  named), and the roles of the names it is published at, each only where the record resolves the host (a service
  name, an external host, a server);
- a forward route no realm covers as application `<agent>-<route>`: enforced by the gateway, no sign-on, one `/*`
  resource `unprotected`, with its backend (the gateway passes it through, so the target must too);
- a route sending another path than the request's (`http://app:8080/old$1` for `/legacy`) as a blocking `rewrite`
  source object concerning the application.

## Agent and gateway files

Importer `siteminder/agent-files`: one folder per server, named by its hostname or record name (a server of role
`sm-agent` or `sm-access-gateway`; `opsdir import --change <id> siteminder/agent-files <folder>`):

| In the folder | In the record |
|---|---|
| `WebAgent.conf` (one per instance: an Apache instance, an IIS site, an Access Gateway virtual host's) | `smWebAgent` at `cn=<cloud>-<env>-<server>-<virtual host \| ServerPath \| webagent>,ou=web-agents,ou=siteminder`, naming its server (`smServer`): enabled, its ACO (`smAgentConfig`, the ACO's source object), its other settings (`smConfig`) |
| `SmHost.conf` (the one its `HostConfigFile` names, by the tail of the path, else beside it) | its trusted host (`smTrustedHost`, from `hostname`) and HCO (`smHostConfig`) source objects, the servers of role `sm-policy-server` of its environment its `policyserver` lines name (`smPolicyServer`, by hostname or address); `sharedsecret` withheld |
| `LocalConfig.conf` | settings overriding its ACO where the ACO allows (`AllowLocalConfig`: no by default, yes, or the names it lists); the agent identities it acts as (`smActsAs`: `DefaultAgentName`, each `AgentName` mapping's name; local or the ACO's) |
| `server.conf` (an Access Gateway's) | each `<VirtualHost>` an instance (`smVirtualHost`: its `hostnames`), its `WebAgent.conf` the one its `<WebAgent> sminitfile` names (else `<VirtualHostDefaults>`'s, else `proxy-engine/conf/defaultagent/WebAgent.conf`); `ClientPassPhrase` withheld |
| `proxyrules.xml` (the one `ServiceDispatcher` `rules_file` names) | `smRoute` at `cn=<cloud>-<env>-<server>-route-<n>,ou=routes,ou=siteminder`, naming the gateway (`smServer`): the rule tree flattened into routes in the order the gateway tries them (`ciamOrder`), each with the conditions on its way (`smCondition` `<type> <criteria> <value>`, all must hold), forward or redirect (`smRouteAction`) and its target as written (`smRouteTarget`; a forward's filter class in `smConfig`) |

Broadcom's proxy rules files declare an external DOCTYPE (`<!DOCTYPE nete:proxyrules SYSTEM ".../proxyrules.dtd">`,
KB 216168): exactly one such declaration (a SYSTEM or PUBLIC id, no internal subset) is removed before the file is
read; any other DOCTYPE, an internal subset or an entity is refused like any XML the core reads. Secrets are withheld
whole, never stored: `sharedsecret` (`{RC2}`/`{AES}`, KB 10974 and 224434), `ClientPassPhrase`, an IIS agent's
`DefaultPassword` (clear text in `LocalConfig.conf`) and anything the export's rules call sensitive; the instance
records that each existed, what it is and that the target re-provisions it (`smWithheld`). A re-import replaces what
the record says of each server's instances and routes and changes nothing when the files haven't. They are kept in
SiteMinder's own branch, not below the server, so no other importer's scope (a cloud's state, CLI output or native
templates, which replace a server's subtree) removes them; an instance or route whose server the record no longer
holds is named by every SiteMinder import, and no source object concerns it.

## Secrets

Never stored, neither the value nor its ciphertext. `XPSExport -npass` writes sensitive settings in **clear text**; `-pass` encrypts them with a passphrase: either way the import withholds them. A setting is withheld when its name is a sensitive one (password, secret, passphrase, private key: SiteMinder publishes no per-class list), when its value looks encrypted (a `{cipher}` prefix) or when the store's secret patterns match it; a header response's fixed value too. The entry records only that it existed, what it is and that the target re-provisions it (`smWithheld`, e.g. `Password: the bind password of the connection; re-provision in the target`), and every import says how many it withheld and that the export file must be treated as a secret. Agent keys, the session key and federation keys aren't in an XPSExport at all (`smkeyexport`, `smkeytool`): the `keys` source object says so.

## Planner checks

Run when the adapter applies to a plan's **source** (`source_checks`). What stops being protected when the target doesn't run the agents (a realm's rules, policies, sign-on and headers) is the web access domain's check over the projected realms, and a product the target runs offers to take the realm over (`protect:<adapter>/<domain>-<realm>`):

- `check_user_directories`: an **action** for every user directory binding as an account no directory consumer records.

The core checks the rest: integrations still served by SiteMinder's identity service (federation: blocks until re-homed), its header contracts (edge: a setter the target doesn't run blocks; a client-sendable identity header is an action), its source objects (governance) and its bind account (directory consumers).

## Schema

Under this package's OID arc `1.3.6.1.4.1.32473.3.6` (prefix `sm`, `schema.py`): 34 attributes, classes `smObject` (auxiliary), `smPolicyDomain`, `smRealm`, `smRule`, `smPolicy`, `smAuthScheme`, `smUserDirectory`, `smAgent`, `smWebAgent`, `smRoute`. Realms, rules and policies are projected onto the core's neutral protected-application layer, which PingAccess and PingGateway share (above).

## Known limits

- **The XPS names are unverified for 12.8 and 12.9.** The layout and the class and property names come from Broadcom's archived 12.51 XPS reference and knowledge-base articles quoting 12.8 exports; Broadcom's current XPSExport page wasn't readable. Every name the adapter reads is data in `xps.py` (`KINDS`, `FIELDS`, the response types, `VERSION_ATTRIBUTES`), so a real export that names them otherwise is fixed there. The tests and the showcase's export are built from the documented shapes, not taken from a real policy store. **Acceptance items** (a real 12.8 SP and 12.9.1 `-xb` export, with `-pass` and with `-npass`): the root element's version attribute; the property names of realms, rules, policies and their links, user policies, responses and response attributes (in particular whether the agent type of a response attribute is a link to an `AgentTypeAttr` object rather than a name), user directories, authentication schemes, agents and agent types, partnerships (local and remote entities, ACS and SSO endpoints, bindings, NameID, assertion attributes, certificates), OIDC clients; the IdP-side partnership class name; how `-pass` writes an encrypted value (the `{cipher}` prefix is assumed) and which properties it marks sensitive; federation objects `-xp` may leave out (a 12.52 SP1 limitation: select `PartnershipBase*` XIDs).
- **The neutral projection is unverified like the rest.**
  - Broadcom's REST examples (KB 380127) name a realm's `ProtectAll` and spell a rule's regex flag `RegularExpression`
    and its actions `["Get", "Post"]`, where `xps.py` reads `IsRegex` and `GET,POST`: acceptance items for the
    real exports.
  - So are a policy's exclusion and AND flags and user selections of other kinds (`organizationalUnit`, roles): not
    read, so a policy using them is `custom`.
  - Also whether a regex rule is matched against the whole path (assumed) and the 12.8/12.9 deny-over-allow precedence
    (documented for 12.51).
- **The agent files' names are unverified for 12.8 and 12.9.** They come from Broadcom's archived Web Agent 12.52,
  Secure Proxy Server 12.52 and r12 SP3 guides and knowledge-base articles (the current TechDocs pages weren't
  readable); every name read is data in `conf.py` (`NAMES`, the server.conf sections) and `proxyrules.py`. The
  tests' files are built from the documented shapes. **Acceptance items** (a real Apache and IIS Web Agent 12.8.x
  install, an Access Gateway 12.8 SP and 12.9.1): the parameter names of `WebAgent.conf`, `SmHost.conf` and
  `LocalConfig.conf` (one per Apache instance or IIS site?); how the ACO's parameters appear in an XPSExport
  (`Parameters` `<name>=<value>` assumed) and whether `AllowLocalConfig` still works as r12 SP3 documents (SP2
  differs); whether `IgnoreUrl` matches a path exactly (assumed: the conservative reading) or as a prefix, and how
  `IgnoreExt` treats a query string; the proxy rules DTD of 12.8/12.9 (the `case` element's `value`, `xprcond`'s
  `type`, an `xpr` result's `service`, whether `default` may be left out and what happens then); `server.conf`'s
  section and setting names (`VirtualHost` `hostnames`, `<WebAgent> sminitfile`, `ServiceDispatcher` `rules_file`) and
  whether a virtual host can name its agent identity directly; `sharedsecrettime`'s meaning (KB 10974 and 369902
  disagree: it is kept, not withheld).
- **Routes the record can't place** (a condition on a query, header or cookie, a regular expression, `contains` or
  `endswith`, a redirect) are named in the import's notices, not recorded as anything the plan acts on: rebuild them
  in the target gateway.
- **Not read**: the admin policy REST API (`/ca/api/sso/services/policy/v1/`: needs a legacy administrator; its coverage is unverified), an Access Gateway's own session schemes, filters and other `server.conf` settings (only its virtual hosts and rules file), `IgnoreHost` and the agents' other settings (kept in `smConfig`), the key store, the session and audit stores, the certificate data store's contents (certificates are linked only when the record holds them).
- **Responses' other types, variables, active rules and expressions** beyond `userattr` and `userdn` are kept as source objects to review or in `smConfig`, not interpreted.
- **One identity service per export**: partnerships of several local entities are served by the first (a notice names the others).
- **Versions**: an export naming no release is read (the servers' recorded versions apply); a server's `ciamProductVersion` is compared as PEP 440, so record 12.52 as `12.5.2`.

## Tests

`tests/test_agent_files.py` with the synthetic export `tests/agent-files/policy-store.xml` and two server folders
(an Apache Web Agent; an Access Gateway with a virtual host and proxy rules): the files' parsing, the routes in order,
the DOCTYPE forms accepted and refused, instances below their servers and their links, secrets withheld whole, the
ignored extensions and URLs, a gateway application's backend and names, uncovered routes, rewrites, source objects'
concerns and the routing dropped, a re-import of either changing nothing, and the core checks.

`tests/test_siteminder.py` with the synthetic export `tests/xps/policy-store.xml`: registration and applicability, every mapping above, nested realms and XREF references, held integrations kept, every sensitive value absent from what is stored, DOCTYPE and other releases refused, unresolved links named, a re-import changing nothing and keeping the record's handling, the source checks and the core source-object check. The core's `opsdir/tests/unit/test_source_objects.py` covers source objects, the federation check and the planner hook.

```bash
opsdir/.venv/bin/python -m pytest packages/opsdir-adapter-siteminder/tests
```

In this repository: `opsdir/scripts/dev-install.sh`.
