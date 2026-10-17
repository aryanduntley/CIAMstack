#!/usr/bin/env bash
# Export one Vault PKI mount for the importer hashicorp-vault/pki, read-only and metadata only, with the Vault CLI
# under the operator's own login (VAULT_ADDR, VAULT_TOKEN or the token helper): what `opsdir collect` saves, for a
# mount keeping more certificates than one collection may read. Every file is a `vault read -format=json` answer (a
# listing the CLI's bare array), written where the importer reads it:
#   OUTDIR/pki/<mount>/{issuers,roles,certs,policies}.json and issuers/ roles/ certs/ config/ policies/ per item.
# The certificates are public; no private key is read (Vault keeps none of an issued certificate's). The ACL
# policies are optional: a token not granted them leaves them out (who may request from the roles is then unknown).
# Usage: export-vault-pki.sh MOUNT OUTDIR      then: opsdir import --change CHG-... --at <when> hashicorp-vault/pki OUTDIR
set -euo pipefail

mount=${1:?usage: export-vault-pki.sh MOUNT OUTDIR}
out=${2:?usage: export-vault-pki.sh MOUNT OUTDIR}
mount=${mount%/}
dir="$out/pki/$mount"
mkdir -p "$dir/issuers" "$dir/roles" "$dir/certs" "$dir/config" "$dir/policies"

# A listing saved as FILE, its keys on standard output; an empty listing (Vault: "No value found", exit 2) saves
# nothing; with "optional", a refused one too.
listing() {
  local path=$1 file=$2 optional=${3:-}
  local err
  if ! vault list -format=json "$path" > "$file" 2> "$file.err"; then
    err=$(cat "$file.err")
    rm -f "$file" "$file.err"
    case "$err" in
      *"No value found"*) return 0 ;;
      *"permission denied"*) [ -n "$optional" ] && return 0 ;;
    esac
    echo "$err" >&2
    return 1
  fi
  rm -f "$file.err"
  # the CLI's JSON listing: one quoted key per line
  sed -n 's/^  "\(.*\)",\{0,1\}$/\1/p' "$file"
}

# One answer saved as FILE; with "optional", a missing or refused one saves nothing.
answer() {
  local path=$1 file=$2 optional=${3:-}
  if ! vault read -format=json "$path" > "$file" 2> "$file.err"; then
    rm -f "$file"
    if [ -n "$optional" ]; then rm -f "$file.err"; return 0; fi
    cat "$file.err" >&2
    rm -f "$file.err"
    return 1
  fi
  rm -f "$file.err"
}

issuers=$(listing "$mount/issuers" "$dir/issuers.json")
for id in $issuers; do answer "$mount/issuer/$id" "$dir/issuers/$id.json"; done
roles=$(listing "$mount/roles" "$dir/roles.json")
for role in $roles; do answer "$mount/roles/$role" "$dir/roles/$role.json"; done
serials=$(listing "$mount/certs" "$dir/certs.json")
for serial in $serials; do answer "$mount/cert/$serial" "$dir/certs/${serial//:/-}.json"; done
for config in urls issuers cluster crl auto-tidy; do
  answer "$mount/config/$config" "$dir/config/$config.json" optional
done
policies=$(listing sys/policies/acl "$dir/policies.json" optional)
for policy in $policies; do answer "sys/policies/acl/$policy" "$dir/policies/$policy.json" optional; done
echo "exported $mount to $dir"
