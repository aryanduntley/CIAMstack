#!/usr/bin/env bash
# Walk-through of operating an identity platform from the opsdir record, on a fictional estate.
#   ./demo.sh                 run everything (output under out/)
#   TERRAFORM=/path/terraform ./demo.sh   also run terraform fmt/validate on the rendered code
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
od import --change CHG-2004 pingam exports/amster
echo "-- the partner identity sync's PingIDM project (same change)"
od import --change CHG-2004 pingidm exports/idm
echo "-- the partner portal's PingGateway routes (same change)"
od import --change CHG-2004 pinggateway exports/ig
echo "-- what the production directory servers actually run: each one's config.ldif (and ds-2's archived one)"
od import --change CHG-2006 --at 20260920030000Z pingds/config exports/ds-config
echo "-- who uses the directory: consumers found in its access logs (values-free; end users only counted)"
od import --change CHG-2007 pingds/access-log exports/ds-access-logs
echo "-- each environment's declared stack against the installed adapters"; od check
echo "-- what each kind of value is: intent, contract, binding, secret reference, observed, meta"; od report portability

step "2. Ask it questions"
echo "-- certificates by expiry";            od report expiring
echo "-- what depends on the Skyline Air signing cert?"
od report blast-radius "cn=skyline-air-idp-signing,ou=certificates,dc=ciam-ops"
echo "-- who can read privacy-classified attributes?"; od report pii
echo "-- the consumers to review: what they do, who owns them, what to check"; od report consumers
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
echo "-- run.properties rebuilt from the record for production"; od file run.properties --env source/prod

step "5. Drift and hygiene"
echo "-- config drift (declared vs observed)"; od report drift
echo "-- stale work instructions";           od report stale
echo "-- unowned";                           od report unowned

step "6. Guardrails: these writes must be REJECTED"
od modify --change CHG-2002 changes/rejected/CHG-2002-unapproved.ldif
od modify --change CHG-2001 changes/rejected/delete-cert-in-use.ldif
od modify --change CHG-2003 changes/rejected/secret-value.ldif
od modify --change CHG-2001 changes/rejected/missing-required.ldif

step "7. Render each environment from the record"
rm -rf out/source-prod out/source-stage out/target-prod
od render source/prod && od render source/stage
echo "-- per-environment overrides of shared intent (stage is an overlay of prod)"; od report overrides
echo "-- stage renders prod's shared configuration with its own overrides:"
diff out/source-prod/ds/dsconfig.batch out/source-stage/ds/dsconfig.batch | grep '^[<>]' || true

step "8. Moving production to a second environment (Azure), from the same record"
od report keys target/prod
od render target/prod
for f in ds/dsconfig.batch ds/acis.ldif pingfederate/sp-connections.json pingfederate/oidc-clients.json pingfederate/idp-connections.json; do
  cmp -s "out/source-prod/$f" "out/target-prod/$f" && echo "identical in both environments: $f" || echo "DIFFERS: $f"
done
if [ -n "${TERRAFORM:-}" ]; then
  for e in source-prod target-prod; do
    "$TERRAFORM" -chdir="out/$e/terraform" fmt -check >/dev/null && echo "terraform fmt ok: $e"
    ( cd "out/$e/terraform" && "$TERRAFORM" init -backend=false -input=false >/dev/null && "$TERRAFORM" validate -no-color )
  done
fi
echo "-- the plan (before changes). The estate is deliberately broken; blockers are planted problems the planner must find."
od plan source/prod target/prod | sed -n '1,8p'
"$PY" scripts/check-findings.py before
echo "-- approved changes are entries; re-render and diff"
rm -rf out/before && cp -r out/target-prod out/before
od modify --change CHG-2001 changes/CHG-2001-mro-firewall-target.ldif
od modify --change CHG-2003 changes/CHG-2003-stable-ldaps-name.ldif
od modify --change CHG-2005 changes/CHG-2005-idm-connector-credentials.ldif
od history
od render target/prod >/dev/null
diff -ru out/before/terraform out/target-prod/terraform
echo "-- the plan (after changes)"
od plan source/prod target/prod | sed -n '1,20p'
"$PY" scripts/check-findings.py after
echo
echo "Full outputs: out/source-prod, out/source-stage, out/target-prod, out/plan-source-prod-to-target-prod"
