# Adapter testing and trust

*How an adapter is shown to produce valid configuration for the product versions it claims, what each level of assurance means, and where every adapter stands today. How to write an adapter is in [`opsdir/README.md`](../opsdir/README.md#writing-an-adapter-package); the trust risks of installing one are in [`THREAT-MODEL.md`](THREAT-MODEL.md).*

---

## 1. Three levels, kept apart

| Level | Means | Where adapters stand |
|---|---|---|
| **Offline-tested** | The adapter's own tests, round trips, golden outputs, and validation of its output by the vendor's or the format's own tools and published specifications, all without a real product instance or cloud account | Every adapter |
| **Validated against the vendor product** | Its renders applied to, and its importers and collectors run against, a real instance of each supported version (in a lab, sandbox or evaluation environment) | HashiCorp Vault and EJBCA Community Edition collectors only, against local instances (below). The rest is next (validation against real products in a sandbox). |
| **Production-certified** | Used in a customer's production estate, for named versions, with the evidence kept | None yet. CIAMstack is pre-production. |

Saying which level a claim rests on is part of the contract: a supported version range (PingFederate 11–13, for example) means the adapter is built and offline-tested for it, not that it has been run against every release in it.

## 2. The testing contract

Every adapter is held to these, and the repository's test configuration collects each package's tests:

| Test | What it proves | How |
|---|---|---|
| **Unit tests** | Its renderers, importers, checks and collectors do what they say on the record they're given | Each package's `tests/`, no database needed |
| **Round trip** | Reading its own render back changes nothing in the record | `opsdir.connectors.roundtrip.read_back` over each `ReadBack` the adapter declares; for intent, also a fixed point (render, import, render gives the same files) |
| **Golden outputs** | Its output for a full estate doesn't change unnoticed | The showcase estate's renders, reports and plans compared byte for byte with the accepted copies; a change needs a reviewed re-baseline |
| **Planted findings** | Its planner checks find what they should | The showcase's planted problems listed in `expected-findings.json`; the tests fail if any is missed |
| **Schema validation** | Its schema additions are valid and composed without collisions | Schema fragments under the package's own OID arc; the store composes them and re-checks stored entries on every upgrade |
| **Vendor specification validation** | Its output matches what the vendor publishes for the version | See section 3 |
| **Format tool validation** | Its files pass the format's own tools | `terraform validate`, `cfn-lint`, `bicep build` and `bicep lint`, `kustomize`, `helm`, `kubeconform -strict`, `ansible-lint` |
| **Version compatibility** | Each supported product version is declared, with what changes between versions | `products=` ranges and `version_changes=`; `opsdir check` names a product version outside the range; the planner names the changes a move's upgrade crosses |
| **Upgrade test** | The record's data survives CIAMstack upgrades | Schema migrations run against real data from the showcase (`test_showcase_upgrades.py`); an upgrade re-validates every stored entry before it commits |
| **Failure modes** | Bad input and failed reads don't corrupt the record | Importers report a file that isn't their format instead of failing; a collection with a failed call is recorded and never imported, and "nothing there" answers are told apart from failures; XML with DOCTYPE or entities is refused |
| **Secret handling** | No secret value is stored or rendered | The vendor's secret forms registered as patterns the database refuses; importers' withheld values tested |

## 3. Vendor specifications and tools used today

| Adapter or output | Checked against |
|---|---|
| PingFederate Admin API requests | The Admin API OpenAPI specification of each version the environment runs, kept in the repository (12.1, 12.2, 12.3, 13.0, 13.1) |
| PingFederate as Terraform | `terraform validate` against Ping's Terraform provider at the release pinned for the version (1.8.1 for 11.3 to 12.1, 1.10.0 for 12.2 to 13.1) |
| AWS and Azure Terraform | `terraform validate` against the `hashicorp/aws` and `hashicorp/azurerm` provider schemas |
| AWS CloudFormation | `cfn-lint` with AWS's resource schemas, including GovCloud regions |
| Azure ARM and Bicep | `bicep build` and `bicep lint` |
| Kubernetes output (ForgeOps, ping-devops, the stack's own manifests) | `kustomize build`, `helm template`, `kubeconform -strict` |
| Ansible playbooks | `ansible-lint` with the pinned `ansible-core` |
| HashiCorp Vault collection | A local Vault dev server (the pinned CLI), collected for real |
| EJBCA collection | A local EJBCA Community Edition container, collected over mutual TLS |
| SAML metadata, OIDC documents, LDAP schema | Shaped to the standards; not yet loaded into a real SAML, OIDC or LDAP product |

Tools are pinned and fetched by `opsdir/scripts/fetch-tools.sh` into the repository's ignored `tools/` folder. Tests that need a tool are skipped without it, and say so.

## 4. Not verified yet

- Rendered product configuration applied to real PingDS, OpenDJ, PingFederate, PingAM, PingIDM, PingGateway and PingAccess instances.
- `terraform plan` and `apply` against real cloud accounts, including GovCloud and Azure Government.
- Kubernetes output deployed to a real cluster.
- Collectors against live products and clouds (their tests replay recorded output), other than the Vault and EJBCA ones above.
- Google Cloud Terraform with `terraform validate`.

The plan for these is a lab per product with evaluation licences where vendors offer them, then a sandbox account per cloud: render, apply, read back, and compare.

## 5. Trusting an adapter you install

Tests show an adapter works. They don't show it is safe to install: an adapter is code that runs with CIAMstack's rights ([threat model](THREAT-MODEL.md)). Before installing one:

- take it from a source the company trusts, at a reviewed version, from an internal mirror with pinned hashes;
- check its declared product versions cover what the environment runs (`opsdir check`);
- run its tests and the showcase in a non-production record first;
- review what it reads during collection (`opsdir collect --list` shows every call) and the read-only rights its README asks for.
