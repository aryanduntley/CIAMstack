#!/usr/bin/env bash
# Capture every opsdir output into one directory, so a refactor can be checked byte for byte:
#   OPSDIR_DSN=... scripts/snapshot-outputs.sh OUTDIR
#   diff -r golden OUTDIR
# Regenerates data/ and the core's published schema in place, then DROPS and reloads the opsdir schema in OPSDIR_DSN.
# Paths under OUTDIR, history timestamps and internal row ids are masked so snapshots taken anywhere
# compare equal.
set -uo pipefail
cd "$(dirname "$0")/.."                          # the showcase
CORE=$(cd ../../opsdir && pwd)                   # the opsdir core: its venv, schema and gen-schema.py
OUT=$(realpath -m "${1:?usage: snapshot-outputs.sh OUTDIR}")
: "${OPSDIR_DSN:?set OPSDIR_DSN to the database to use (its opsdir schema is dropped)}"
AS_OF=2026-09-23                                # the synthetic data is dated relative to this day
PY=$CORE/.venv/bin/python
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
              find exports/ds-config exports/ds-access-logs exports/cloud exports/ds-data exports/regions -type f | sort |
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
for r in portability expiring credentials pii drift stale unowned custom capture bundles consumers census jobs baselines compute external-services mail-senders event-streams data-profile data-profile-attributes alerts log-routes canaries monitors audit-trails security-services quotas budgets imports user-schema databases object-stores volumes backups restore-tests settings recovery standbys failover-drills tags routes private-endpoints endpoint-services egress-sites dns edge-policies edge-services header-contracts identities principals guardrails access-paths workloads; do cap "03-report-$r" od report "$r"; done
# the stale report dates a dependency's change from history: a change this run imports is dated the day it runs
sed -i -e "s/$(date +%F)/<RUN-DATE>/g" -e "s/$(date -u +%F)/<RUN-DATE>/g" "$OUT/cmd/03-report-stale.txt"
cap 03-cloud-drift-source od import --dry-run aws/terraform-state exports/cloud
cap 03-cloud-drift-target od import --dry-run azure/cli-inventory exports/cloud
cap 03-cloud-drift-standby od import --dry-run gcp/cli-inventory exports/cloud
cap 03-import-undecided od import --change CHG-2004 --at 20260920030000Z aws/terraform-state exports/cloud
cap 03-report-blast-radius od report blast-radius "$BLAST"
cap 03-report-keys-source od report keys source/prod
cap 03-report-keys-target od report keys target/prod
cap 03-report-rotation-impact od report rotation-impact "$ROTATE"
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
cap 08-prerequisites od prerequisites
cap 08-report-regions od report regions
cap 08-report-residency od report residency
cap 08-report-security-services od report security-services
cap 08-report-quotas od report quotas
cap 08-report-budgets od report budgets
od history 2>&1 | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/<TIMESTAMP>        /' \
  > "$OUT/cmd/09-history.txt"

cap 10-render-target-after od render target/prod -o "$OUT/render-after/target-prod"
cap 11-plan-after  od plan source/prod target/prod -o "$OUT/plan-after"
cap 11-check-after "$PY" scripts/check-findings.py after
od export > "$OUT/export.ldif" 2>&1

echo "snapshot written to $OUT"
