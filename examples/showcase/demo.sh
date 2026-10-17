#!/usr/bin/env bash
# Walk-through of operating an identity platform from the opsdir record, on a fictional estate.
#   ./demo.sh                 run everything (output under out/)
#   TERRAFORM=/path/terraform ./demo.sh   run terraform fmt/validate on the rendered code with that terraform
#                                          (default: tools/bin/terraform when opsdir/scripts/fetch-tools.sh fetched it)
set -uo pipefail
cd "$(dirname "$0")"                           # the showcase; outputs go to out/ here
CORE=$(cd ../../opsdir && pwd)
PY=$CORE/.venv/bin/python
unset PYTHONPATH                               # a folder a shell exports there would shadow the venv's packages
AS_OF=2026-09-23                               # the synthetic data is dated relative to this day
od() { "$CORE/opsdir.sh" --as-of "$AS_OF" "$@"; }
. "$CORE/scripts/dev-env.sh"   # OPSDIR_DSN: the local dev database unless already set (init below drops its opsdir schema)
step() { printf '\n\033[1m══ %s\033[0m\n' "$*"; }

step "1. The record: the whole platform as governed entries in one database"
"$PY" scripts/gen-synthetic.py
od init && od load data/*.ldif
echo "-- the partner realm's PingAM configuration, read from its Amster export (approved change CHG-2004)"
od import --change CHG-2004 --at 20260920030000Z pingam exports/amster
echo "-- the partner identity sync's PingIDM project (same change)"
od import --change CHG-2004 --at 20260920030000Z pingidm exports/idm
echo "-- the partner portal's PingGateway routes (same change)"
od import --change CHG-2004 --at 20260920030000Z pinggateway exports/ig
echo "-- what the production directory servers actually run: each one's config.ldif (and ds-2's archived one)"
od import --change CHG-2006 --at 20260920030000Z pingds/config exports/ds-config
echo "-- who uses the directory: consumers found in its access logs (values-free; end users only counted)"
od import --change CHG-2007 --at 20260920030000Z pingds/access-log exports/ds-access-logs
echo "-- PingFederate's configuration, from its Admin API bulk export (a client the record didn't have is found)"
od import --change CHG-2008 --at 20260920030000Z pingfederate/bulk exports/pingfederate
od import --change CHG-2008 --at 20260920030000Z pingfederate/node-files exports/pingfederate-nodes
echo "-- where the record's values are copied into files (the census): each file and line; secrets flagged, not stored"
od census --change CHG-2009 exports/census
echo "-- the platform's hidden automation: servers' cron and timers, CI pipelines"
od import --change CHG-2010 --at 20260920030000Z linux/jobs exports/hosts
od import --change CHG-2010 --at 20260920030000Z github-actions/workflows exports/pipelines
echo "-- what the servers run beyond the products: each role's host baseline, from the same servers' files"
od import --change CHG-2012 --at 20260920030000Z linux/baseline exports/hosts
echo "-- the shape of the production user data, values-free: ldapsearch output read once, counts written (no database)"
od data-profile --env source/prod --at 20260920030000Z --term last-login=lastLoginTime --term kba=challengeAnswer \
  --term pending=registrationStatus=pending --term disabled=registrationStatus=disabled \
  -o out/data-profile/source-prod.json exports/ds-data/source-prod.ldif
od import --change CHG-2014 --at 20260920030000Z ldap/data-profile out/data-profile
echo "-- each environment's declared stack against the installed adapters"; od check
echo "-- what each kind of value is: intent, contract, binding, secret reference, observed, meta"; od report portability

step "2. Ask it questions"
echo "-- certificates by expiry";            od report expiring
echo "-- what depends on the Skyline Air signing cert?"
od report blast-radius "cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops"
echo "-- who can read privacy-classified attributes?"; od report pii
echo "-- the consumers to review: what they do, who owns them, what to check"; od report consumers
echo "-- the shape of the user data: size, password schemes, idle accounts, group health"; od report data-profile
echo "-- what the platform is watched for, where its logs go, and what each cloud runs of it"
od report alerts; od report log-routes; od report monitors
echo "-- who changes each cloud: the control-plane audit trails, what they record, where, and how well protected"
od report audit-trails
od report security-services
od report incident-reporting; od report reportable-incidents
od report assessments; od report poam; od report exceptions
od report authorizations; od report responsibilities
echo "-- what each environment needs of its provider's limits, and the budgets its spending is held to"
od report quotas; od report budgets
echo "-- the user directory's attributes: what each is for, its privacy class, standard or defined here"
od report user-schema
echo "-- the managed databases each environment runs: engine, version, availability, encryption, backups"
od report databases
echo "-- the object stores: versioning, locks, keys, lifecycle, public access and copies of each environment's buckets"
od report object-stores
echo "-- the disks: each server role's volumes, their size, class, key and the snapshot policy that copies them"
od report volumes
echo "-- the tag policy: the tags every rendered resource carries and the value each takes in every environment"
od report tags
echo "-- disaster recovery: each objective against the environments running its roles, the standbys, the drills"
od report recovery; od report standbys; od report failover-drills
echo "-- the network: routes, private endpoints, endpoint services, and the sites egress lets the servers reach"
od report routes; od report private-endpoints; od report endpoint-services; od report egress-sites
echo "-- the edge: DNS, traffic and protection policies, what each load balancer runs, header contracts"
od report dns; od report edge-policies; od report edge-services; od report header-contracts
echo "-- who may act on the platform: identities, principals, guardrails, the paths to each permission"
od report identities; od report principals; od report guardrails; od report access-paths
echo "-- what changing ds-1 touches in files: its hostname and address, copied where"
od report census "cn=ds-1,env=prod,cloud=source,ou=environments,dc=ciam-ops"
echo "-- LDAP filter search: consumers not yet tested against the second environment"
od search -b ou=consumers,dc=ciam-ops '(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))' ciamMigrationStatus ciamOwner

step "3. Keys and secrets, as references"
echo "-- where production keeps every key and secret"; od report keys source/prod
echo "-- credential sprawl: every key and secret, where it is held and used"; od report credentials
echo "-- what rotating the PingFederate signing key touches"
od report rotation-impact "cn=pf-signing-key,ou=credentials,dc=ciam-ops"

step "3b. Applications and what they depend on"
echo "-- everything the Customer Parts Portal touches in the target, each row naming its entry"
od application customer-portal --env target/prod
echo "-- what depends on the Skyline Air signing cert, as a graph (Graphviz DOT)"
od graph "cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops" --direction up --format dot
echo "-- the estate in counts, each with its evidence"; od summary source/prod target/prod

step "4. The record extended by its operators, and the files it holds"
echo "-- custom fields and record types";    od report custom
echo "-- config files held in the record";   od report capture
echo "-- bundles deployed as they are";      od report bundles
echo "-- jobs: what runs, when, where, who owns it"; od report jobs
echo "-- host baselines: OS, Java and its truststore additions, limits, agents, per server role"; od report baselines
echo "-- compute groups and clusters, per environment"; od report compute
echo "-- outside services, the addresses mail comes from, where identity events go"
od report external-services; od report mail-senders; od report event-streams
echo "-- run.properties rebuilt from the record for production"; od file run.properties --env source/prod

step "5. Drift and hygiene"
echo "-- config drift (declared vs observed)"; od report drift
echo "-- what the source cloud runs against the record: its Terraform state (--dry-run: nothing is applied)"
od import --dry-run aws/terraform-state exports/cloud
echo "-- applied, it waits for a decision on each conflict: take the live value or keep the record's (nothing applied)"
od import --change CHG-2004 --at 20260920030000Z aws/terraform-state exports/cloud
echo "-- when each part of the record was last read back from the live system, and the scopes of each set read"
od report imports
od report import-scopes
echo "-- the second environment, from the Azure CLI (roles.json gives the new subnet its role)"
od import --dry-run azure/cli-inventory exports/cloud
echo "-- the warm standby, from a Cloud Asset Inventory export and gcloud (project numbers read as its ID)"
od import --dry-run gcp/cli-inventory exports/cloud
echo "-- stale work instructions";           od report stale
echo "-- the unknowns register: open questions and who must answer them"; od report unknowns
echo "-- unowned";                           od report unowned

step "6. Guardrails: these writes must be REJECTED"
od modify --change CHG-2002 changes/rejected/CHG-2002-unapproved.ldif
od modify --change CHG-2001 changes/rejected/delete-cert-in-use.ldif
od modify --change CHG-2003 changes/rejected/secret-value.ldif
od modify --change CHG-2001 changes/rejected/missing-required.ldif

step "7. Render each environment from the record"
rm -rf out/source-prod out/source-stage out/target-prod out/standby-prod
od render source/prod && od render source/stage
echo "-- the warm standby on Google Cloud: its replicas join production's deployment; PingFederate lists its nodes"
od render standby/prod
od report keys standby/prod
grep '^pf.cluster' out/standby-prod/pingfederate/cluster/jgroups.properties
echo "-- per-environment overrides of shared intent (stage is an overlay of prod)"; od report overrides
echo "-- stage renders prod's shared configuration with its own overrides:"
diff out/source-prod/ds/dsconfig.batch out/source-stage/ds/dsconfig.batch | grep '^[<>]' || true

step "8. Moving production to a second environment (Azure), from the same record"
od report keys target/prod
od render target/prod
for f in ds/dsconfig.batch ds/acis.ldif pingfederate/sp-connections.json pingfederate/oidc-clients.json pingfederate/idp-connections.json; do
  cmp -s "out/source-prod/$f" "out/target-prod/$f" && echo "identical in both environments: $f" || echo "DIFFERS: $f"
done
TERRAFORM=${TERRAFORM:-$(cd ../.. && pwd)/tools/bin/terraform}  # the local one (opsdir/scripts/fetch-tools.sh)
if [ -x "$TERRAFORM" ]; then
  echo "-- every rendered Terraform root (stack, landing zone, each keeper's), checked by terraform fmt and validate"
  TERRAFORM=$TERRAFORM "$CORE/scripts/validate-terraform.sh" out/source-prod out/target-prod out/standby-prod
fi
echo "-- the plan (before changes). The estate is deliberately broken; blockers are planted problems the planner must find."
od plan source/prod target/prod | sed -n '1,8p'
"$PY" scripts/check-findings.py before
echo "-- fixes the findings offer: record changes to propose (for a person to approve) or apply under a change"
od fix list source/prod target/prod
od fix show source/prod target/prod egress-proxy:pf-engine:bin/run.properties
echo "-- a fix that is a choice: which secret holds PingFederate's SMTP password is never guessed; a person picks"
od fix show source/prod target/prod credential-role:notification-publishers/smtp | sed -n '1,12p'
echo "-- a fix that takes inputs: the target's backup bucket is the operator's to give (the source's is only the example)"
od fix show source/prod target/prod binding:backup-target
echo "-- approved changes are entries; re-render and diff"
rm -rf out/before && cp -r out/target-prod out/before
od modify --change CHG-2001 changes/CHG-2001-mro-firewall-target.ldif
od modify --change CHG-2003 changes/CHG-2003-stable-ldaps-name.ldif
od modify --change CHG-2005 changes/CHG-2005-credential-roles.ldif
od modify --change CHG-2011 changes/CHG-2011-job-owners.ldif
od modify --change CHG-2013 changes/CHG-2013-corporate-ca.ldif
od modify --change CHG-2015 changes/CHG-2015-target-ad-forwarder.ldif
od modify --change CHG-2016 changes/CHG-2016-grant-database-protection.ldif
od modify --change CHG-2017 changes/CHG-2017-target-backup-container.ldif
od modify --change CHG-2018 changes/CHG-2018-target-directory-volume-size.ldif
od modify --change CHG-2019 changes/CHG-2019-target-disk-backup.ldif
echo "-- the providers' region lists (prerequisites: here the saved CLI output; --run runs the CLI under your login)"
od import --change CHG-2020 --at 20260923090000Z aws/regions exports/regions/aws
od import --change CHG-2021 --at 20260923090000Z azure/regions exports/regions/azure
od import --change CHG-2022 --at 20260923090000Z gcp/regions exports/regions/gcp
od prerequisites
echo "-- the estate's residency: where each environment's data may be held"
od modify --change CHG-2023 changes/CHG-2023-us-residency.ldif
od report regions; od report residency
echo "-- the target records its configuration change history (Azure keeps 14 days of it)"
od modify --change CHG-2024 changes/CHG-2024-target-config-history.ldif
od report security-services
echo "-- the providers' quota limits for the environments' needs, the target's vCPU decision, the target's budget"
od import --change CHG-2025 --at 20260923090000Z aws/quotas exports/quotas/aws
od import --change CHG-2026 --at 20260923090000Z azure/quotas exports/quotas/azure
od import --change CHG-2027 --at 20260923090000Z gcp/quotas exports/quotas/gcp
od fix show source/prod target/prod quota:prod:vcpus
od modify --change CHG-2028 changes/CHG-2028-target-budget-and-quota.ldif
od report quotas; od report budgets
echo "-- incident reporting: the target is held to DFARS 252.204-7012 and Defender pages the incident process"
od modify --change CHG-2029 changes/CHG-2029-target-incident-reporting.ldif
od report incident-reporting; od report reportable-incidents
echo "-- the target's risk acceptance gets its expiry; a Defender false positive is suppressed (azapi add-on)"
od modify --change CHG-2030 changes/CHG-2030-target-exceptions.ldif
od report exceptions
echo "-- production's FedRAMP package overview; the target joins the SSP and records how it meets SC-12 on Azure"
od import --change CHG-2031 --at 20260923090000Z fedramp/cpo exports/fedramp
od modify --change CHG-2032 changes/CHG-2032-target-ssp-and-key-management.ldif
echo "-- the AD forwarder moves to the landing zone's DNS servers; the reset mail's service gets an exception"
od modify --change CHG-2033 changes/CHG-2033-target-boundary.ldif
echo "-- data discovery: the target turns on Defender's sensitive data discovery over its backups"
od modify --change CHG-2034 changes/CHG-2034-target-data-discovery.ldif
od report data-discovery
od report authorizations; od report responsibilities
echo "-- the on-prem lab (hq/lab): the organization's sites become the on-prem provider's regions; the AWS agents and"
echo "   the MRO export apply only where they run, the lab's servers get its site's agents"
od import --change CHG-2035 --at 20260923090000Z onprem/sites exports/sites/onprem
od modify --change CHG-2036 changes/CHG-2036-scoped-agents-and-jobs.ldif
echo "-- the target's hybrid identity: password hashes synced beside pass-through, passwords written back to the"
echo "   corporate AD, and Defender for Identity (kept by security operations) watching the AD"
od modify --change CHG-2037 changes/CHG-2037-target-hybrid-identity.ldif
echo "-- the target keeps its resource change history as long as the source (2557 days): an hourly export of"
echo "   Resource Graph's changes into its security workspace"
od modify --change CHG-2038 changes/CHG-2038-target-change-history.ldif
echo "-- the standby assesses itself against NIST SP 800-53 Rev. 5 and its CIS benchmark with Compliance Manager:"
echo "   Google's frameworks fetched into the record (prerequisite gcp-frameworks), then deployed from it"
od modify --change CHG-2039 changes/CHG-2039-standby-compliance-frameworks.ldif
od import --change CHG-2041 --at 20260923090000Z gcp/frameworks exports/frameworks/gcp
rm -rf out/standby-prod-compliance
od render standby/prod --binding cn=compliance,ou=bindings,env=prod,cloud=standby,ou=environments,dc=ciam-ops -o out/standby-prod-compliance
echo "-- the standby will hold ITAR technical data: its Assured Workloads folder takes Google's ITAR package"
od modify --change CHG-2042 changes/CHG-2042-standby-itar-data.ldif
echo "-- the target builds its products' configuration into its deployment: ForgeOps config profiles, PingFederate's"
echo "   server profile (fetched from the platform's profile repository); secrets only as variables from Secret keys"
od modify --change CHG-2043 changes/CHG-2043-target-profiles.ldif
echo "-- Skyline Air answers the question the move waited for (unknown q-skyline-signing)"
od modify --change CHG-2044 changes/CHG-2044-skyline-signing-answer.ldif
echo "-- compliance evidence: SSP-CIAM-2026's package (each control the target's authorization leaves to the platform,"
echo "   the record queries that show it met), recorded on the boundary under CHG-2046"
rm -rf out/evidence-SSP-CIAM-2026
od evidence --boundary SSP-CIAM-2026 --change CHG-2046 -o out/evidence-SSP-CIAM-2026
od report evidence
echo "-- the CyberArk safes' account inventory, metadata only: each reference present, missing or unconfirmed, rotation"
echo "   from the CPM's own successes, and the accounts nothing references (the target's PAM copy is vaulted elsewhere)"
od import --change CHG-2047 --at 20260923090000Z cyberark/accounts exports/cyberark
od report secret-inventory
echo "-- the lab's firewall rules as the HQ Panorama runs them (its running configuration, as the XML API answers"
echo "   type=config&action=show): the drift, then read back under CHG-2048 keeping the record's admin range"
od import --dry-run --at 20260923090000Z panos/running-config exports/panos
od import --change CHG-2048 --at 20260923090000Z --keep "cn=fw-admin,ou=bindings,env=lab,cloud=hq,ou=environments,dc=ciam-ops|ciamSourceCidr" \
  panos/running-config exports/panos
od report firewall-running
echo "-- the security team's Splunk: what production's index keeps and the detection Splunk runs, read in from its"
echo "   management API's answers (exports/splunk); the security events must be kept 365 days"
od import --change CHG-2049 --at 20260923090000Z splunk/rest exports/splunk
od report log-routes
echo "-- the AD CS issuing CA's issued-certificate inventory (metadata only, from the shipped exporter's JSON), its"
echo "   revocation endpoints and the forest's templates: the directory's LDAPS certificate was revoked as superseded"
od import --change CHG-2050 --at 20260923090000Z adcs/inventory exports/adcs
od modify --change CHG-2051 changes/CHG-2051-issuing-ca-and-template-owners.ldif
od report certificate-authorities
od report issued-certificates
echo "-- the change records name their ServiceNow tickets (CHG-2055), and the tickets are read as evidence (CHG-2056:"
echo "   change_request and its approval records, as the Table API answers): what ITSM says against the record"
od modify --change CHG-2055 changes/CHG-2055-ticket-links.ldif
od import --change CHG-2056 --at 20260923090000Z servicenow/change-requests exports/servicenow
od report tickets
echo "-- PingAccess in front of Tech Pubs in both environments (CHG-2060); its configuration, read from the Admin API as"
echo "   an Auditor collects it, objects named by name and the client secret withheld whole (CHG-2061); the session's"
echo "   secret role and the header Tech Pubs trusts for who the user is (CHG-2062)"
od modify --change CHG-2060 changes/CHG-2060-pingaccess-servers.ldif
od import --change CHG-2061 --at 20260923090000Z pingaccess/admin-api exports/pingaccess
od modify --change CHG-2062 changes/CHG-2062-pingaccess-session-and-header.ldif
od report header-contracts
echo "-- production's SiteMinder still protects the crew portal: its policy store export read in (CHG-2063, secrets"
echo "   withheld), what has no standard equivalent carried as source objects, and AOG Parts Exchange moved to"
echo "   PingFederate's sso (CHG-2064), whose SP connection the platform team then configures and reads back (CHG-2065)"
od import --change CHG-2063 --at 20260923090000Z siteminder/xps exports/siteminder
od modify --change CHG-2064 changes/CHG-2064-siteminder-owners-and-aog-to-sso.ldif
od import --change CHG-2065 --at 20260923090000Z pingfederate/bulk exports/pingfederate-aog
od report source-objects
echo "-- cloud-managed identity services: the partners sign-in service is to run on Microsoft Entra External ID in the"
echo "   target (CHG-2066), the tech-pubs team's Amazon Cognito user pool relies on the platform's sign-on (a neighbour,"
echo "   CHG-2067), and Microsoft confirms the tenant's RS256 signing (CHG-2068, the plan's question answered)"
od modify --change CHG-2066 changes/CHG-2066-target-partners-external-id.ldif
od modify --change CHG-2067 changes/CHG-2067-source-tech-pubs-user-pool.ldif
od modify --change CHG-2068 changes/CHG-2068-external-id-signing-answer.ldif
od report managed-identity
echo "-- the directory's LDAPS certificate chains to Example Aero Issuing CA 2 (CHG-2051), which no check runtime trusts:"
echo "   the source's directory-bind canary isn't rendered until the CA's certificate is recorded (CHG-2069, public"
echo "   material); then it is given it to trust"
od report canary-coverage
od modify --change CHG-2069 changes/CHG-2069-issuing-ca-certificate.ldif
od report canary-coverage
echo "-- the PingAccess servers' own files read in as the pa-admin and pa-engine host baselines (CHG-2075), their AWS"
echo "   agents then scoped to AWS environments (CHG-2076), so the target's VMs can be checked against them"
od import --change CHG-2075 --at 20260923090000Z linux/baseline exports/hosts-pingaccess
od modify --change CHG-2076 changes/CHG-2076-pingaccess-scoped-agents.ldif
echo "-- the applications PingAccess, SiteMinder and PingGateway protect, as their imports projected them onto the"
echo "   neutral protected-application layer; then the target moves two of them to another product: its PingAccess"
echo "   takes the crew portal over from SiteMinder (the portal's client and the target's bindings, CHG-2081; the"
echo "   target's overrides, CHG-2082), and its gateways take Tech Pubs over from PingAccess (CHG-2083)"
od report protected-applications
od modify --change CHG-2081 changes/CHG-2081-crew-portal-client-and-target-bindings.ldif
od modify --change CHG-2082 changes/CHG-2082-target-pingaccess-protects-crew-portal.ldif
od modify --change CHG-2083 changes/CHG-2083-target-pinggateway-protects-tech-pubs.ldif
od report protected-applications
od report regulated-data
echo "-- the forest's certificate templates collected again over LDAPS with their access rights (CHG-2086,"
echo "   adcs/inventory's template collector): CIAM-WebServer now also issues client authentication, takes the"
echo "   subject from the request and lets Domain Users enroll (ESC1-style): an action for its renewal owner; the"
echo "   import takes the live values where the record held CHG-2050's (who may enroll was unknown then)"
od import --change CHG-2086 --at 20260923090000Z --take all adcs/inventory exports/adcs-templates
echo "-- the issuing CA's revocation endpoints observed from the data center (CHG-2092, x509/revocation's collector):"
echo "   the CRL distribution point serves a CRL the CA certificate the record holds doesn't verify, the delta CRL is"
echo "   gone (HTTP 404) and the OCSP responder refuses to answer for the CA: three actions for the CA's owners"
od import --change CHG-2092 --at 20260923090000Z x509/revocation exports/revocation
od report revocation-endpoints
echo "-- the partners external tenant the render created is recorded (CHG-2089): the target adopts it and registers the"
echo "   partner portal in it; then its Graph configuration (the portal's registration, the partners' user flow and"
echo "   token extension) is read back (CHG-2090)"
od modify --change CHG-2089 changes/CHG-2089-partners-external-tenant.ldif
od import --change CHG-2090 --at 20260923090000Z azure/external-id exports/external-id
od report managed-identity
echo "-- crew-web-1's SiteMinder agent files read in (CHG-2095, siteminder/agent-files): its Web Agent instance (linked"
echo "   to the server), acting as crew-web-agent, linked to its ACO, HCO, trusted host and sm-ps-1 (its shared secret"
echo "   withheld); its LocalConfig.conf's IgnoreUrl is named, since crew-aco doesn't allow local configuration"
od import --change CHG-2095 --at 20260923090000Z siteminder/agent-files exports/siteminder-agents
echo "-- the platform team's changes name their Jira Service Management tickets and the site's workflow and fields are"
echo "   mapped (CHG-2098); the tickets and their approval steps are read as evidence (CHG-2099: as the REST APIs answer)"
od modify --change CHG-2098 changes/CHG-2098-jira-sm-ticket-links.ldif
od import --change CHG-2099 --at 20260923090000Z jira-sm/change-requests exports/jira-sm
echo "-- the security operations team's changes name their BMC Helix ITSM change requests (CHG-2105); the change requests"
echo "   and their approval signatures are read as evidence (CHG-2106: as the AR System REST API answers)"
od modify --change CHG-2105 changes/CHG-2105-bmc-helix-ticket-links.ldif
od import --change CHG-2106 --at 20260923090000Z bmc-helix/change-requests exports/bmc-helix
echo "-- the ServiceNow instance's legacy change model is named, so its pre-Geneva state codes read in neutral terms, and"
echo "   CHG-2117 names its ticket (CHG-2115); the tickets are read again (CHG-2116): CHG-2117's ticket says its work"
echo "   began after the export was read (evidence from after the read)"
od modify --change CHG-2115 changes/CHG-2115-servicenow-legacy-model-and-links.ldif
od import --change CHG-2116 --at 20260923090000Z servicenow/change-requests exports/servicenow
od report tickets
echo "-- the same report as of today: the record's own writes under each linked change (its history) against the"
echo "   ticket's planned window"
"$CORE/opsdir.sh" report tickets
echo "-- the corporate identity team's managed domain in the target is recorded (CHG-2110): Entra Domain Services, a"
echo "   neighbour directory with a forest trust to the corporate forest (kept) and an external trust with the lab's"
echo "   domain, which a managed domain can't keep (a blocker); the target's authorization doesn't list the service"
od modify --change CHG-2110 changes/CHG-2110-target-corporate-managed-domain.ldif
od report managed-directory
echo "-- the lab's internal CA is a Vault PKI mount, read as the Vault add-on's collector saves it (CHG-2120): the CA,"
echo "   its endpoints, its roles (ciam-client: any name, client authentication, requested through the default policy)"
echo "   and the certificates Vault keeps; the lab's SSO certificate was renewed there, and the record names the old one"
od import --change CHG-2120 --at 20260923090000Z hashicorp-vault/pki exports/vault-pki
od report issued-certificates
echo "-- production's AWS Private CA (CHG-2122) and the standby's Google Cloud CA pools (CHG-2123), read as the cloud"
echo "   add-ons' collectors save them: each CA's state, key and parent, its endpoints, its templates with who may"
echo "   request from them, and the certificates the newest audit report lists or the pool keeps; Harbor MRO's"
echo "   account may issue client certificates in any name, the standby's client template is open to the whole domain,"
echo "   and the mesh's DevOps pool keeps no certificates and publishes no CRL"
od import --change CHG-2122 --at 20260923090000Z aws/private-ca exports/aws-private-ca
od import --change CHG-2123 --at 20260923090000Z gcp/private-ca exports/gcp-private-ca
od report certificate-authorities
rm -rf out/standby-prod-landing-zone
od render standby/prod --keeper cloud-landing-zone -o out/standby-prod-landing-zone
od report baselines
rm -rf out/hq-lab
od render hq/lab
od report keys hq/lab
ANSIBLE_TOOLS=$(cd ../.. && pwd)/tools/ansible/venv/bin/ansible-playbook   # opsdir/scripts/fetch-tools.sh
if [ -x "$ANSIBLE_TOOLS" ]; then
  echo "-- every rendered Ansible folder, checked by ansible-inventory, syntax, ansible-lint and the AS3 schema"
  "$CORE/scripts/validate-ansible.sh" out/source-prod/ansible out/hq-lab/ansible
fi
od history
od render target/prod >/dev/null
diff -ru out/before/terraform out/target-prod/terraform
echo "-- the plan (after changes)"
od plan source/prod target/prod | sed -n '1,20p'
"$PY" scripts/check-findings.py after
echo
echo "Full outputs: out/source-prod, out/source-stage, out/target-prod, out/standby-prod, out/hq-lab,"
echo "              out/plan-source-prod-to-target-prod"
