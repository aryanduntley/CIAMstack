#!/usr/bin/env bash
# End-to-end demo of the operations directory on synthetic data.
#   ./demo.sh                 run everything (output under out/)
#   TERRAFORM=/path/terraform ./demo.sh   also run terraform fmt/validate on the rendered code
set -uo pipefail
cd "$(dirname "$0")"
AS_OF=2026-09-23                               # the synthetic data is dated relative to this day
od() { ./opsdir.sh --as-of "$AS_OF" "$@"; }
. scripts/dev-env.sh          # OPSDIR_DSN: the local dev database unless already set (init below drops its opsdir schema)
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
rm -rf out/source-prod out/target-prod
od render source/prod && od render target/prod
for f in ds/dsconfig.batch ds/acis.ldif pingfederate/sp-connections.json pingfederate/oidc-clients.json pingfederate/idp-connections.json; do
  cmp -s "out/source-prod/$f" "out/target-prod/$f" && echo "identical in both clouds: $f" || echo "DIFFERS: $f"
done
if [ -n "${TERRAFORM:-}" ]; then
  for e in source-prod target-prod; do
    "$TERRAFORM" -chdir="out/$e/terraform" fmt -check >/dev/null && echo "terraform fmt ok: $e"
    ( cd "out/$e/terraform" && "$TERRAFORM" init -backend=false -input=false >/dev/null && "$TERRAFORM" validate -no-color )
  done
fi

step "4. Migration plan (before changes)"
echo "The synthetic estate is deliberately broken; blockers are planted problems the planner must find."
od plan source/prod target/prod | sed -n '1,8p'
.venv/bin/python scripts/check-findings.py before

step "5. Guardrails: these writes must be REJECTED"
od modify --change CHG-2002 changes/rejected/CHG-2002-unapproved.ldif
od modify --change CHG-2001 changes/rejected/delete-cert-in-use.ldif
od modify --change CHG-2003 changes/rejected/secret-value.ldif
od modify --change CHG-2001 changes/rejected/missing-required.ldif

step "6. Approved changes are just directory entries; re-render and diff"
rm -rf out/before && cp -r out/target-prod out/before
od modify --change CHG-2001 changes/CHG-2001-mro-firewall-target.ldif
od modify --change CHG-2003 changes/CHG-2003-stable-ldaps-name.ldif
od history
od render target/prod >/dev/null
diff -ru out/before/terraform out/target-prod/terraform

step "7. Migration plan (after changes)"
od plan source/prod target/prod | sed -n '1,20p'
.venv/bin/python scripts/check-findings.py after
echo
echo "Full outputs: out/source-prod, out/target-prod, out/plan-source-prod-to-target-prod"
