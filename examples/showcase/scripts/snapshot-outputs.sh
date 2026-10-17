#!/usr/bin/env bash
# Capture every opsdir output into one directory, so a refactor can be checked byte for byte:
#   OPSDIR_DSN=... scripts/snapshot-outputs.sh OUTDIR
#   diff -r golden OUTDIR
# Regenerates data/ and the core's published schema in place, then DROPS and reloads the opsdir schema in OPSDIR_DSN.
# Paths under OUTDIR, history timestamps (also in the evidence package and the hashes that cover them:
# scripts/mask-evidence.py) and internal row ids are masked so snapshots taken anywhere compare equal.
set -uo pipefail
cd "$(dirname "$0")/.."                          # the showcase
CORE=$(cd ../../opsdir && pwd)                   # the opsdir core: its venv, schema and gen-schema.py
OUT=$(realpath -m "${1:?usage: snapshot-outputs.sh OUTDIR}")
: "${OPSDIR_DSN:?set OPSDIR_DSN to the database to use (its opsdir schema is dropped)}"
AS_OF=2026-09-23                                # the synthetic data is dated relative to this day
PY=$CORE/.venv/bin/python
unset PYTHONPATH                                # a folder a shell exports there would shadow the venv's packages
BLAST="cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops"
ROTATE="cn=pf-signing-key,ou=credentials,dc=ciam-ops"
UNTESTED='(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))'

od() { "$PY" -m opsdir --as-of "$AS_OF" "$@"; }

# cap NAME CMD...: run CMD, keep stdout+stderr and the exit status in $OUT/cmd/NAME.txt
cap() {
  local name=$1; shift
  { "$@" 2>&1; echo "exit $?"; } | sed -e "s#$OUT#<OUT>#g" -e 's/Key (id)=([0-9]*)/Key (id)=(<ROW>)/' > "$OUT/cmd/$name.txt"
}

rm -rf "$OUT" && mkdir -p "$OUT/cmd"

# The generators must reproduce the published schema and data files exactly (independent of git state).
generated() { (cd "$CORE" && sha256sum schema/*.ldif); sha256sum data/*.ldif data/*.json;
              find exports/ds-config exports/ds-access-logs exports/cloud exports/ds-data exports/regions \
                exports/panos -type f | sort |
                xargs sha256sum; }
generated > "$OUT/cmd/.generated-before"
cap 00-gen-schema    "$PY" "$CORE/scripts/gen-schema.py"
cap 00-gen-synthetic "$PY" scripts/gen-synthetic.py
cap 00-generated-diff diff "$OUT/cmd/.generated-before" <(generated)
rm "$OUT/cmd/.generated-before"

cap 01-init od init
cap 02-load od load data/*.ldif
cap 02-import od import --change CHG-2004 --at 20260920030000Z pingam exports/amster
cap 02-import-idm od import --change CHG-2004 --at 20260920030000Z pingidm exports/idm
cap 02-import-ig od import --change CHG-2004 --at 20260920030000Z pinggateway exports/ig
cap 02-import-ds od import --change CHG-2006 --at 20260920030000Z pingds/config exports/ds-config
cap 02-import-ds-logs od import --change CHG-2007 --at 20260920030000Z pingds/access-log exports/ds-access-logs
cap 02-import-pf od import --change CHG-2008 --at 20260920030000Z pingfederate/bulk exports/pingfederate
cap 02-import-pf-nodes od import --change CHG-2008 --at 20260920030000Z pingfederate/node-files exports/pingfederate-nodes
cap 02-import-jobs od import --change CHG-2010 --at 20260920030000Z linux/jobs exports/hosts
cap 02-import-pipelines od import --change CHG-2010 --at 20260920030000Z github-actions/workflows exports/pipelines
cap 02-import-baselines od import --change CHG-2012 --at 20260920030000Z linux/baseline exports/hosts
cap 02-data-profile od data-profile --env source/prod --at 20260920030000Z --term last-login=lastLoginTime \
  --term kba=challengeAnswer --term pending=registrationStatus=pending --term disabled=registrationStatus=disabled \
  -o "$OUT/data-profile/source-prod.json" exports/ds-data/source-prod.ldif
cap 02-import-data-profile od import --change CHG-2014 --at 20260920030000Z ldap/data-profile "$OUT/data-profile"
cap 02-census od census --change CHG-2009 exports/census
cap 02-check od check
for r in portability expiring credentials pii drift stale unowned custom capture bundles consumers census jobs baselines compute external-services mail-senders event-streams data-profile data-profile-attributes alerts log-routes canaries monitors audit-trails security-services quotas budgets incident-reporting reportable-incidents poam exceptions assessments authorizations responsibilities evidence imports import-scopes unknowns user-schema databases object-stores volumes backups restore-tests settings recovery standbys failover-drills tags routes private-endpoints endpoint-services egress-sites dns edge-policies edge-services header-contracts identities principals guardrails access-paths workloads; do cap "03-report-$r" od report "$r"; done
# the stale report dates a dependency's change from history: a change this run imports is dated the day it runs
sed -i -e "s/$(date +%F)/<RUN-DATE>/g" -e "s/$(date -u +%F)/<RUN-DATE>/g" "$OUT/cmd/03-report-stale.txt"
cap 03-cloud-drift-source od import --dry-run aws/terraform-state exports/cloud
cap 03-cloud-drift-target od import --dry-run azure/cli-inventory exports/cloud
cap 03-cloud-drift-standby od import --dry-run gcp/cli-inventory exports/cloud
cap 03-import-undecided od import --change CHG-2004 --at 20260920030000Z aws/terraform-state exports/cloud
cap 03-report-blast-radius od report blast-radius "$BLAST"
cap 03-report-keys-source od report keys source/prod
cap 03-report-keys-target od report keys target/prod
cap 03-report-log-collection-source od report log-collection source/prod
cap 03-report-log-collection-target od report log-collection target/prod
cap 03-report-canary-coverage od report canary-coverage
cap 03-report-rotation-impact od report rotation-impact "$ROTATE"
cap 03-application-customer-portal od application customer-portal --env target/prod
cap 03-application-customer-portal-json od application customer-portal --format json
cap 03-graph-customer-portal od graph customer-portal --depth 2
cap 03-graph-blast-dot od graph "$BLAST" --direction up --format dot
cap 03-summary od summary source/prod target/prod
cap 03-report-overrides od report overrides
cap 03-report-keys-stage od report keys source/stage
cap 03-report-keys-standby od report keys standby/prod
cap 04-search-table od search -b ou=consumers,dc=ciam-ops "$UNTESTED" ciamMigrationStatus ciamOwner
cap 04-search-ldif  od search -b ou=integrations,dc=ciam-ops '(objectClass=ciamIntegration)'
cap 04-file-run-properties od file run.properties --env target/prod
cap 04-file-run-properties-stage od file run.properties --env source/stage

cap 05-render-source  od render source/prod -o "$OUT/render-before/source-prod"
cap 05-render-target  od render target/prod    -o "$OUT/render-before/target-prod"
cap 05-render-stage   od render source/stage   -o "$OUT/render-before/source-stage"
cap 05-render-standby od render standby/prod   -o "$OUT/render-before/standby-prod"
cap 06-plan-before od plan source/prod target/prod -o "$OUT/plan-before"
cap 06-check-before "$PY" scripts/check-findings.py before
cap 06-fix-list od fix list source/prod target/prod
cap 06-fix-show od fix show source/prod target/prod egress-proxy:pf-engine:bin/run.properties
cap 06-fix-show-choice od fix show source/prod target/prod credential-role:notification-publishers/smtp
cap 06-fix-show-inputs od fix show source/prod target/prod binding:backup-target

cap 07-reject-unapproved   od modify --change CHG-2002 changes/rejected/CHG-2002-unapproved.ldif
cap 07-reject-cert-in-use  od modify --change CHG-2001 changes/rejected/delete-cert-in-use.ldif
cap 07-reject-secret-value od modify --change CHG-2003 changes/rejected/secret-value.ldif
cap 07-reject-missing-attr od modify --change CHG-2001 changes/rejected/missing-required.ldif

cap 08-apply-chg-2001 od modify --change CHG-2001 changes/CHG-2001-mro-firewall-target.ldif
cap 08-apply-chg-2003 od modify --change CHG-2003 changes/CHG-2003-stable-ldaps-name.ldif
cap 08-apply-chg-2005 od modify --change CHG-2005 changes/CHG-2005-credential-roles.ldif
cap 08-apply-chg-2011 od modify --change CHG-2011 changes/CHG-2011-job-owners.ldif
cap 08-apply-chg-2013 od modify --change CHG-2013 changes/CHG-2013-corporate-ca.ldif
cap 08-apply-chg-2015 od modify --change CHG-2015 changes/CHG-2015-target-ad-forwarder.ldif
cap 08-apply-chg-2016 od modify --change CHG-2016 changes/CHG-2016-grant-database-protection.ldif
cap 08-apply-chg-2017 od modify --change CHG-2017 changes/CHG-2017-target-backup-container.ldif
cap 08-apply-chg-2018 od modify --change CHG-2018 changes/CHG-2018-target-directory-volume-size.ldif
cap 08-apply-chg-2019 od modify --change CHG-2019 changes/CHG-2019-target-disk-backup.ldif
cap 08-apply-chg-2020 od import --change CHG-2020 --at 20260923090000Z aws/regions exports/regions/aws
cap 08-apply-chg-2021 od import --change CHG-2021 --at 20260923090000Z azure/regions exports/regions/azure
cap 08-apply-chg-2022 od import --change CHG-2022 --at 20260923090000Z gcp/regions exports/regions/gcp
cap 08-apply-chg-2023 od modify --change CHG-2023 changes/CHG-2023-us-residency.ldif
cap 08-apply-chg-2024 od modify --change CHG-2024 changes/CHG-2024-target-config-history.ldif
cap 08-apply-chg-2025 od import --change CHG-2025 --at 20260923090000Z aws/quotas exports/quotas/aws
cap 08-apply-chg-2026 od import --change CHG-2026 --at 20260923090000Z azure/quotas exports/quotas/azure
cap 08-apply-chg-2027 od import --change CHG-2027 --at 20260923090000Z gcp/quotas exports/quotas/gcp
cap 08-fix-show-quota od fix show source/prod target/prod quota:prod:vcpus
cap 08-apply-chg-2028 od modify --change CHG-2028 changes/CHG-2028-target-budget-and-quota.ldif
cap 08-apply-chg-2029 od modify --change CHG-2029 changes/CHG-2029-target-incident-reporting.ldif
cap 08-apply-chg-2030 od modify --change CHG-2030 changes/CHG-2030-target-exceptions.ldif
cap 08-apply-chg-2031 od import --change CHG-2031 --at 20260923090000Z fedramp/cpo exports/fedramp
cap 08-apply-chg-2032 od modify --change CHG-2032 changes/CHG-2032-target-ssp-and-key-management.ldif
cap 08-apply-chg-2033 od modify --change CHG-2033 changes/CHG-2033-target-boundary.ldif
cap 08-apply-chg-2034 od modify --change CHG-2034 changes/CHG-2034-target-data-discovery.ldif
cap 08-apply-chg-2035 od import --change CHG-2035 --at 20260923090000Z onprem/sites exports/sites/onprem
cap 08-apply-chg-2036 od modify --change CHG-2036 changes/CHG-2036-scoped-agents-and-jobs.ldif
cap 08-apply-chg-2037 od modify --change CHG-2037 changes/CHG-2037-target-hybrid-identity.ldif
cap 08-apply-chg-2038 od modify --change CHG-2038 changes/CHG-2038-target-change-history.ldif
cap 08-apply-chg-2039 od modify --change CHG-2039 changes/CHG-2039-standby-compliance-frameworks.ldif
cap 08-apply-chg-2041 od import --change CHG-2041 --at 20260923090000Z gcp/frameworks exports/frameworks/gcp
cap 08-apply-chg-2042 od modify --change CHG-2042 changes/CHG-2042-standby-itar-data.ldif
cap 08-apply-chg-2043 od modify --change CHG-2043 changes/CHG-2043-target-profiles.ldif
cap 08-apply-chg-2044 od modify --change CHG-2044 changes/CHG-2044-skyline-signing-answer.ldif
cap 08-apply-chg-2046 od evidence --boundary SSP-CIAM-2026 --change CHG-2046 -o "$OUT/evidence/SSP-CIAM-2026"
cap 08-report-evidence od report evidence
cap 08-apply-chg-2047 od import --change CHG-2047 --at 20260923090000Z cyberark/accounts exports/cyberark
cap 08-firewall-drift-lab od import --dry-run --at 20260923090000Z panos/running-config exports/panos
cap 08-apply-chg-2048 od import --change CHG-2048 --at 20260923090000Z --keep "cn=fw-admin,ou=bindings,env=lab,cloud=hq,ou=environments,dc=ciam-ops|ciamSourceCidr" \
  panos/running-config exports/panos
cap 08-report-firewall-running od report firewall-running
cap 08-apply-chg-2049 od import --change CHG-2049 --at 20260923090000Z splunk/rest exports/splunk
cap 08-report-log-routes od report log-routes
cap 08-apply-chg-2050 od import --change CHG-2050 --at 20260923090000Z adcs/inventory exports/adcs
cap 08-apply-chg-2051 od modify --change CHG-2051 changes/CHG-2051-issuing-ca-and-template-owners.ldif
cap 08-report-certificate-authorities od report certificate-authorities
cap 08-report-issued-certificates od report issued-certificates
cap 08-apply-chg-2055 od modify --change CHG-2055 changes/CHG-2055-ticket-links.ldif
cap 08-apply-chg-2056 od import --change CHG-2056 --at 20260923090000Z servicenow/change-requests exports/servicenow
cap 08-report-tickets od report tickets
cap 08-apply-chg-2060 od modify --change CHG-2060 changes/CHG-2060-pingaccess-servers.ldif
cap 08-apply-chg-2061 od import --change CHG-2061 --at 20260923090000Z pingaccess/admin-api exports/pingaccess
cap 08-apply-chg-2062 od modify --change CHG-2062 changes/CHG-2062-pingaccess-session-and-header.ldif
cap 08-report-header-contracts od report header-contracts
cap 08-apply-chg-2063 od import --change CHG-2063 --at 20260923090000Z siteminder/xps exports/siteminder
cap 08-apply-chg-2064 od modify --change CHG-2064 changes/CHG-2064-siteminder-owners-and-aog-to-sso.ldif
cap 08-apply-chg-2065 od import --change CHG-2065 --at 20260923090000Z pingfederate/bulk exports/pingfederate-aog
cap 08-report-source-objects od report source-objects
cap 08-apply-chg-2066 od modify --change CHG-2066 changes/CHG-2066-target-partners-external-id.ldif
cap 08-apply-chg-2067 od modify --change CHG-2067 changes/CHG-2067-source-tech-pubs-user-pool.ldif
cap 08-apply-chg-2068 od modify --change CHG-2068 changes/CHG-2068-external-id-signing-answer.ldif
cap 08-report-managed-identity od report managed-identity
cap 08-report-canary-coverage-private-ca od report canary-coverage
cap 08-apply-chg-2069 od modify --change CHG-2069 changes/CHG-2069-issuing-ca-certificate.ldif
cap 08-report-canary-coverage-after od report canary-coverage
cap 08-apply-chg-2075 od import --change CHG-2075 --at 20260923090000Z linux/baseline exports/hosts-pingaccess
cap 08-apply-chg-2076 od modify --change CHG-2076 changes/CHG-2076-pingaccess-scoped-agents.ldif
cap 08-report-protected-applications od report protected-applications
cap 08-apply-chg-2081 od modify --change CHG-2081 changes/CHG-2081-crew-portal-client-and-target-bindings.ldif
cap 08-apply-chg-2082 od modify --change CHG-2082 changes/CHG-2082-target-pingaccess-protects-crew-portal.ldif
cap 08-apply-chg-2083 od modify --change CHG-2083 changes/CHG-2083-target-pinggateway-protects-tech-pubs.ldif
cap 08-report-protected-applications-after od report protected-applications
cap 08-apply-chg-2086 od import --change CHG-2086 --at 20260923090000Z --take all adcs/inventory \
  exports/adcs-templates
cap 08-apply-chg-2092 od import --change CHG-2092 --at 20260923090000Z x509/revocation exports/revocation
cap 08-report-revocation-endpoints od report revocation-endpoints
cap 08-report-regulated-data od report regulated-data
cap 08-apply-chg-2089 od modify --change CHG-2089 changes/CHG-2089-partners-external-tenant.ldif
cap 08-apply-chg-2090 od import --change CHG-2090 --at 20260923090000Z azure/external-id exports/external-id
cap 08-report-managed-identity-tenant od report managed-identity
cap 08-apply-chg-2095 od import --change CHG-2095 --at 20260923090000Z siteminder/agent-files exports/siteminder-agents
cap 08-apply-chg-2098 od modify --change CHG-2098 changes/CHG-2098-jira-sm-ticket-links.ldif
cap 08-apply-chg-2099 od import --change CHG-2099 --at 20260923090000Z jira-sm/change-requests exports/jira-sm
cap 08-apply-chg-2105 od modify --change CHG-2105 changes/CHG-2105-bmc-helix-ticket-links.ldif
cap 08-apply-chg-2106 od import --change CHG-2106 --at 20260923090000Z bmc-helix/change-requests exports/bmc-helix
cap 08-apply-chg-2115 od modify --change CHG-2115 changes/CHG-2115-servicenow-legacy-model-and-links.ldif
cap 08-apply-chg-2116 od import --change CHG-2116 --at 20260923090000Z servicenow/change-requests exports/servicenow
# the record's own writes under each linked change against its ticket's window: as of a far day, so every write this
# run made counts; the write times (this run's) are masked, every fixture time is before October 2026
cap 08-report-tickets-applied "$PY" -m opsdir --as-of 2099-12-31 report tickets
sed -i -E 's/(2026-1[0-2]|202[7-9]-[0-9]{2}|20[3-9][0-9]-[0-9]{2})-[0-9]{2} [0-9]{2}:[0-9]{2}Z/<RUN-DATE> --:--Z/g' \
  "$OUT/cmd/08-report-tickets-applied.txt"
cap 08-report-tickets-jira-sm od report tickets
cap 08-apply-chg-2110 od modify --change CHG-2110 changes/CHG-2110-target-corporate-managed-domain.ldif
cap 08-report-managed-directory od report managed-directory
cap 08-apply-chg-2120 od import --change CHG-2120 --at 20260923090000Z hashicorp-vault/pki exports/vault-pki
cap 08-report-issued-certificates-vault od report issued-certificates
cap 08-apply-chg-2121 od import --change CHG-2121 --at 20260923090000Z ejbca/inventory exports/ejbca-pki
cap 08-report-certificate-authorities-ejbca od report certificate-authorities
cap 08-report-issued-certificates-ejbca od report issued-certificates
cap 08-prerequisites od prerequisites
cap 08-report-regions od report regions
cap 08-report-residency od report residency
cap 08-report-security-services od report security-services
cap 08-report-data-discovery od report data-discovery
cap 08-report-quotas od report quotas
cap 08-report-budgets od report budgets
cap 08-report-incident-reporting od report incident-reporting
cap 08-report-reportable-incidents od report reportable-incidents
cap 08-report-exceptions od report exceptions
cap 08-report-authorizations od report authorizations
cap 08-report-responsibilities od report responsibilities
cap 08-report-secret-inventory od report secret-inventory
od history 2>&1 | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/<TIMESTAMP>        /' \
  > "$OUT/cmd/09-history.txt"

cap 10-render-target-after od render target/prod -o "$OUT/render-after/target-prod"
cap 10-render-lab-after od render hq/lab -o "$OUT/render-after/hq-lab"
cap 10-render-standby-compliance od render standby/prod --binding cn=compliance,ou=bindings,env=prod,cloud=standby,ou=environments,dc=ciam-ops \
    -o "$OUT/render-after/standby-prod-compliance"
cap 10-render-standby-landing-zone od render standby/prod --keeper cloud-landing-zone \
    -o "$OUT/render-after/standby-prod-landing-zone"
cap 10-report-keys-lab od report keys hq/lab
cap 10-file-run-properties-lab od file run.properties --env hq/lab
cap 10-report-baselines-after od report baselines
cap 10-report-jobs-after od report jobs
cap 11-plan-after  od plan source/prod target/prod -o "$OUT/plan-after"
cap 11-summary-after od summary source/prod target/prod
cap 11-check-after "$PY" scripts/check-findings.py after
od export > "$OUT/export.ldif" 2>&1
"$PY" scripts/mask-evidence.py "$OUT/evidence/SSP-CIAM-2026" "$OUT/export.ldif"

echo "snapshot written to $OUT"
