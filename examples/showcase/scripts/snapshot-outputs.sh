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
              find exports/ds-config exports/ds-access-logs exports/cloud -type f | sort | xargs sha256sum; }
generated > "$OUT/cmd/.generated-before"
cap 00-gen-schema    "$PY" "$CORE/scripts/gen-schema.py"
cap 00-gen-synthetic "$PY" scripts/gen-synthetic.py
cap 00-generated-diff diff "$OUT/cmd/.generated-before" <(generated)
rm "$OUT/cmd/.generated-before"

cap 01-init od init
cap 02-load od load data/*.ldif
cap 02-import od import --change CHG-2004 pingam exports/amster
cap 02-import-idm od import --change CHG-2004 pingidm exports/idm
cap 02-import-ig od import --change CHG-2004 pinggateway exports/ig
cap 02-import-ds od import --change CHG-2006 --at 20260920030000Z pingds/config exports/ds-config
cap 02-import-ds-logs od import --change CHG-2007 pingds/access-log exports/ds-access-logs
cap 02-import-pf od import --change CHG-2008 pingfederate/bulk exports/pingfederate
cap 02-import-pf-nodes od import --change CHG-2008 pingfederate/node-files exports/pingfederate-nodes
cap 02-import-jobs od import --change CHG-2010 linux/jobs exports/hosts
cap 02-import-pipelines od import --change CHG-2010 github-actions/workflows exports/pipelines
cap 02-import-baselines od import --change CHG-2012 linux/baseline exports/hosts
cap 02-census od census --change CHG-2009 exports/census
cap 02-check od check
for r in portability expiring credentials pii drift stale unowned custom capture bundles consumers census jobs baselines compute external-services mail-senders event-streams; do cap "03-report-$r" od report "$r"; done
# the stale report dates a dependency's change from history: a change this run imports is dated the day it runs
sed -i -e "s/$(date +%F)/<RUN-DATE>/g" -e "s/$(date -u +%F)/<RUN-DATE>/g" "$OUT/cmd/03-report-stale.txt"
cap 03-cloud-drift-source od import --dry-run aws/terraform-state exports/cloud
cap 03-cloud-drift-target od import --dry-run azure/cli-inventory exports/cloud
cap 03-report-blast-radius od report blast-radius "$BLAST"
cap 03-report-keys-source od report keys source/prod
cap 03-report-keys-target od report keys target/prod
cap 03-report-rotation-impact od report rotation-impact "$ROTATE"
cap 03-report-overrides od report overrides
cap 03-report-keys-stage od report keys source/stage
cap 04-search-table od search -b ou=consumers,dc=ciam-ops "$UNTESTED" ciamMigrationStatus ciamOwner
cap 04-search-ldif  od search -b ou=integrations,dc=ciam-ops '(objectClass=ciamIntegration)'
cap 04-file-run-properties od file run.properties --env target/prod
cap 04-file-run-properties-stage od file run.properties --env source/stage

cap 05-render-source  od render source/prod -o "$OUT/render-before/source-prod"
cap 05-render-target  od render target/prod    -o "$OUT/render-before/target-prod"
cap 05-render-stage   od render source/stage   -o "$OUT/render-before/source-stage"
cap 06-plan-before od plan source/prod target/prod -o "$OUT/plan-before"
cap 06-check-before "$PY" scripts/check-findings.py before

cap 07-reject-unapproved   od modify --change CHG-2002 changes/rejected/CHG-2002-unapproved.ldif
cap 07-reject-cert-in-use  od modify --change CHG-2001 changes/rejected/delete-cert-in-use.ldif
cap 07-reject-secret-value od modify --change CHG-2003 changes/rejected/secret-value.ldif
cap 07-reject-missing-attr od modify --change CHG-2001 changes/rejected/missing-required.ldif

cap 08-apply-chg-2001 od modify --change CHG-2001 changes/CHG-2001-mro-firewall-target.ldif
cap 08-apply-chg-2003 od modify --change CHG-2003 changes/CHG-2003-stable-ldaps-name.ldif
cap 08-apply-chg-2005 od modify --change CHG-2005 changes/CHG-2005-credential-roles.ldif
cap 08-apply-chg-2011 od modify --change CHG-2011 changes/CHG-2011-job-owners.ldif
cap 08-apply-chg-2013 od modify --change CHG-2013 changes/CHG-2013-corporate-ca.ldif
od history 2>&1 | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/<TIMESTAMP>        /' \
  > "$OUT/cmd/09-history.txt"

cap 10-render-target-after od render target/prod -o "$OUT/render-after/target-prod"
cap 11-plan-after  od plan source/prod target/prod -o "$OUT/plan-after"
cap 11-check-after "$PY" scripts/check-findings.py after
od export > "$OUT/export.ldif" 2>&1

echo "snapshot written to $OUT"
