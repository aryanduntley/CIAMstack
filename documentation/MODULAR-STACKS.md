# Assembling your own stack: a vendor-neutral core and adapters

*How CIAMstack fits the products an organization actually runs instead of assuming one vendor's stack. The adapter contract itself is in [`opsdir/SPEC.md`](../opsdir/SPEC.md) §8, and how to write an adapter package is in [`opsdir/README.md`](../opsdir/README.md#writing-an-adapter-package).*

---

## 1. Why the core names no vendor

No two identity platforms are built the same way. One organization runs PingDS and PingFederate on AWS. Another runs a different directory server, a cloud-managed sign-in service and its own on-premises data centers. A third is retiring SiteMinder and moving to PingAccess at the same time. Each has a different mix of secret stores, certificate authorities, ITSM tools, SIEMs and network gear around it.

A tool that assumed one stack would fit nobody exactly. So CIAMstack is split in two:

- **The core** holds the record and everything that is the same whatever the products are: the governed database and its rules, the schema, history, reports, the dependency graph, the planner, workspaces and cutover. It names no cloud, product, vendor or secret store, and it runs without any adapter installed (it then renders nothing).
- **Adapters** are separate installable packages, one per product, cloud or tool. Each translates between the record and its product, in both directions: an importer reads the product's own exports or APIs into the record, and a renderer writes the product's working files from it.

An organization installs the core and the adapters for what it actually runs, and nothing else. Changing a product means adding or swapping an adapter. The core, the record's other entries and the other adapters stay as they are.

## 2. The layers

| Layer | What it is | Examples |
|---|---|---|
| **Core** | The record, its rules (R1–R10), history, reports, graph, planner, workspaces | `opsdir` |
| **Domains** | The vendor-neutral parts of an identity stack, each with its own schema, checks and reports | directory, federation, PKI, governance, configuration, compute, messaging, web access |
| **Standard bases** | The standards products implement, shared by every product that implements them | `opsdir-adapter-ldap` (LDAPv3), `opsdir-base-saml` (SAML 2.0), `opsdir-base-oidc` (OpenID Connect), `opsdir-base-ds` (the OpenDJ / ForgeRock DS / PingDS lineage) |
| **Adapters** | One product, cloud or tool each | `opsdir-adapter-pingfederate`, `opsdir-adapter-azure`, `opsdir-adapter-hashicorp-vault`, `opsdir-adapter-servicenow` |
| **Formats** | File syntaxes renderers write | `opsdir-format-terraform`, `opsdir-format-arm`, `opsdir-format-cloudformation`, `opsdir-format-sigma` |

Domains hold things in neutral terms. A federation connection is a SAML or OIDC integration with its claims, whichever product serves it. An application behind an access gateway is a protected application with path resources and access rules, whichever gateway enforces it. A certificate is a certificate, whichever CA issued it. Product adapters map those neutral entries to and from their product's own objects. A product adds its own entries only for what has no neutral form.

Products build on the standard bases instead of repeating them. A directory adapter renders the standard LDAP schema files through `opsdir-adapter-ldap`. A federation adapter renders SAML metadata and OIDC discovery documents through the SAML and OIDC bases at its own endpoint paths. So the work in a new product's adapter is mostly the product's own syntax, not the standards.

## 3. How an adapter joins the core

An adapter is a Python package that depends on `opsdir` and registers itself through a Python entry point (`opsdir.adapters`). Installing it is all it takes. The core finds it, and `opsdir upgrade` adds what it brings to the record's schema and vocabulary.

An adapter declares, as data:

- **when it applies**, decided from the record (or never by itself, for a generic adapter of a standard, which renders only where an environment's stack names it);
- **the roles it needs an environment to bind**: a service name, a secret, a key store, a subnet;
- **its renderers and importers**, and which of its own renders each importer reads back, so its tests can prove a round trip changes nothing;
- **its planner checks**, which run in every plan where it applies;
- **the secret-reference schemes it owns** (`vault://`, `k8s-secret://`, `cyberark://`) and the forms its vendor's secret material takes, which the database then refuses to store;
- **the file formats it writes** and **the product versions it supports**, with what changes between versions that affects the record;
- **what its product can express**, where a neutral layer allows things a product can't (see [section 6](#6-when-a-product-cant-express-something));
- optionally, **schema of its own**, numbered under an OID arc the package owns, so packages written independently never collide.

## 4. Declaring a stack per environment

Each environment in the record declares its **stack**: for each role (provider, directory, federation, access management, gateway, secret store, DNS, load balancer, firewall, SIEM, ITSM, PKI), which adapter fills it, which adapter versions it accepts and where to get it. In the onboarding answers file it looks like this:

```toml
[[environment]]
cloud = "source"
env = "prod"
provider = "aws"
region = "us-east-1"
[environment.stack]
provider = "aws"
directory = { adapter = "pingds", versions = ">=0.1,<1" }
federation = "pingfederate"
```

`opsdir check` compares every environment's declared stack with the installed adapters. For each component it reports whether the adapter is missing (and where to get it), installed at a version outside the range, installed but not matching the environment's data, or applying to the data without being declared. When an environment declares a stack, exactly those adapters render it.

Stacks are declared **per environment**, so environments in one record can run different products. A production environment on PingFederate, a lab on another federation server and a migration target on a cloud-managed sign-in service can sit side by side in one record, each rendered by its own adapters.

## 5. When your product has no adapter

Anything not listed in the [README](../README.md#adapters) can be added as a package, by the organization's own team, by the author or by anyone else, without touching the core or the other adapters. That covers another directory or federation product, a cloud-managed identity service, another cloud, secret store, ITSM, SIEM or network tool.

A practical order for a new adapter:

1. **Read first.** An importer that reads the product's own export or a read-only API into the record. This alone gives the inventory, the dependency graph and the planner's findings for that product, with no risk to production.
2. **Render.** A renderer that writes the product's working files from the record, and a read-back test proving that importing its own render changes nothing.
3. **Check.** Planner checks for what the product requires, and its capabilities declared as data, so a move onto it reports what it can't do.

The adapter contract is documented and the core's shared helpers (parsing exports, writing YAML and JSON, cloud inventories, secret-store inventories, findings) are public and tested, so an adapter is mostly the mapping between the product and the record.

## 6. When a product can't express something

Neutral layers can hold more than any one product can express. Each product adapter says what it can express, and anything it can't reaches the person rendering it as data, not as a silent omission:

- **Render notes.** `opsdir render` and `opsdir check` list each environment's render notes as blockers and actions. For example, an access rule the target gateway can't render is a blocker, because rendering it without the rule would admit more than the record says.
- **Source objects.** When a product is retired, what it holds that has no neutral equivalent (agent configuration, custom sign-on code, host registrations) is recorded as a source object with an owner and how it is handled: rebuild, re-provision, re-register, replace, retire or review. Nothing is silently lost.
- **Keepers and requests.** Infrastructure another team keeps renders into that team's own Terraform root, or, if the team doesn't take generated infrastructure, becomes a drafted request to it.

[`PEOPLE-IN-CONTROL.md`](PEOPLE-IN-CONTROL.md) describes how these reach the people who decide.

## 7. What exists today

The adapters listed in the [README](../README.md#adapters) are built: the ForgeRock/Ping stack (PingDS, OpenDJ, PingFederate, PingAM, PingIDM, PingGateway, PingAccess), SiteMinder as a product to retire, AWS (including GovCloud), Azure (commercial and Government), Google Cloud and on-premises, with secret stores, PKI, ITSM, SIEM, CI and network tooling around them.

They are tested offline: each adapter's own tests, round trips of every render through its own importer, and a showcase estate whose planted problems the planner must find. Rendered Terraform passes `terraform validate`, Kubernetes output passes kustomize, helm and kubeconform, and PingFederate requests are checked against Ping's Admin API specification. They haven't yet been validated against real product instances or cloud accounts ([what's verified](../examples/showcase/README.md#whats-verified-and-what-isnt)).
