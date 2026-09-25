#!/usr/bin/env bash
# End-to-end demo of the operations directory on synthetic data.
#   ./demo.sh                 run everything (output under out/)
#   TERRAFORM=/path/terraform ./demo.sh   also run terraform fmt/validate on the rendered code
set -uo pipefail
cd "$(dirname "$0")"
AS_OF=2026-09-23                               # the synthetic data is dated relative to this day
od() { ./opsdir.sh --as-of "$AS_OF" "$@"; }
[ -S .pgsock/.s.PGSQL.54329 ] || scripts/pg-local.sh start >/dev/null
export OPSDIR_DSN=${OPSDIR_DSN:-"host=$PWD/.pgsock port=54329 user=opsdir dbname=opsdir"}
step() { printf '\n\033[1m══ %s\033[0m\n' "$*"; }

step "1. Build the directory: LDAP schema + synthetic estate (all LDIF) into Postgres"
.venv/bin/python scripts/gen-synthetic.py
od init && od load
od report portability

step "2. Ask it questions"
echo "-- certificates by expiry";            od report expiring
echo "-- what depends on the Skyline Air signing cert?"
od report blast-radius "cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops"
echo "-- who can read privacy-classified attributes?"; od report pii
echo "-- config drift (declared vs observed)"; od report drift
echo "-- stale work instructions";           od report stale
echo "-- unowned";                           od report unowned
echo "-- LDAP filter search: consumers not yet tested"
od search -b ou=consumers,dc=ciam-ops '(&(objectClass=ciamConsumer)(!(ciamMigrationStatus=tested)))' ciamMigrationStatus ciamOwner

step "3. Render BOTH clouds from the same databases"
rm -rf out/aws-current-prod out/rtx-next-prod
od render aws-current/prod && od render rtx-next/prod
for f in ds/dsconfig.batch ds/acis.ldif pingfederate/sp-connections.json pingfederate/oidc-clients.json pingfederate/idp-connections.json; do
  cmp -s "out/aws-current-prod/$f" "out/rtx-next-prod/$f" && echo "identical in both clouds: $f" || echo "DIFFERS: $f"
done
if [ -n "${TERRAFORM:-}" ]; then
  for e in aws-current-prod rtx-next-prod; do
    "$TERRAFORM" -chdir="out/$e/terraform" fmt -check >/dev/null && echo "terraform fmt ok: $e"
    ( cd "out/$e/terraform" && "$TERRAFORM" init -backend=false -input=false >/dev/null && "$TERRAFORM" validate -no-color )
  done
fi

step "4. Migration plan (before changes)"
echo "The synthetic estate is deliberately broken; blockers are planted problems the planner must find."
od plan aws-current/prod rtx-next/prod | sed -n '1,8p'
.venv/bin/python scripts/check-findings.py before

step "5. Guardrails: these writes must be REJECTED"
od modify --change CHG-2002 changes/rejected/CHG-2002-unapproved.ldif
od modify --change CHG-2001 changes/rejected/delete-cert-in-use.ldif
od modify --change CHG-2003 changes/rejected/secret-value.ldif
od modify --change CHG-2001 changes/rejected/missing-required.ldif

step "6. Approved changes are just directory entries; re-render and diff"
rm -rf out/before && cp -r out/rtx-next-prod out/before
od modify --change CHG-2001 changes/CHG-2001-mro-firewall-rtx-next.ldif
od modify --change CHG-2003 changes/CHG-2003-stable-ldaps-name.ldif
od history
od render rtx-next/prod >/dev/null
diff -ru out/before/terraform out/rtx-next-prod/terraform

step "7. Migration plan (after changes)"
od plan aws-current/prod rtx-next/prod | sed -n '1,20p'
.venv/bin/python scripts/check-findings.py after
echo
echo "Full outputs: out/aws-current-prod, out/rtx-next-prod, out/plan-aws-current-prod-to-rtx-next-prod"
