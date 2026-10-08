#!/usr/bin/env bash
# Walk-through of operating an identity platform from the opsdir record, on a fictional estate.
#   ./demo.sh                 run everything (output under out/)
#   TERRAFORM=/path/terraform ./demo.sh   run terraform fmt/validate on the rendered code with that terraform
#                                          (default: tools/bin/terraform when opsdir/scripts/fetch-tools.sh fetched it)
set -uo pipefail
cd "$(dirname "$0")"                           # the showcase; outputs go to out/ here
CORE=$(cd ../../opsdir && pwd)
PY=$CORE/.venv/bin/python
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
echo "-- when each part of the record was last read back from the live system"
od report imports
echo "-- the second environment, from the Azure CLI (roles.json gives the new subnet its role)"
od import --dry-run azure/cli-inventory exports/cloud
echo "-- the warm standby, from a Cloud Asset Inventory export and gcloud (project numbers read as its ID)"
od import --dry-run gcp/cli-inventory exports/cloud
echo "-- stale work instructions";           od report stale
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
od report authorizations; od report responsibilities
od history
od render target/prod >/dev/null
diff -ru out/before/terraform out/target-prod/terraform
echo "-- the plan (after changes)"
od plan source/prod target/prod | sed -n '1,20p'
"$PY" scripts/check-findings.py after
echo
echo "Full outputs: out/source-prod, out/source-stage, out/target-prod, out/standby-prod,"
echo "              out/plan-source-prod-to-target-prod"
