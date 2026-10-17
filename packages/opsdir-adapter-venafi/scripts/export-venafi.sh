#!/usr/bin/env bash
# Export one Certificate Manager – Self-Hosted (Venafi) policy folder, its subfolders included, for the importer
# venafi/certificates, read-only (GETs only) and metadata only, with curl and jq: what `opsdir collect` saves, for a
# folder holding more certificates than one collection reads the details of. Every answer is trimmed to what the
# importer reads (as collect.py trims it) and written where the importer reads it:
#   OUTDIR/venafi/<source>/certificates-<offset>.json   the listing, 500 per page, with the folder and address
#   OUTDIR/venafi/<source>/details/<guid>.json          each certificate's details
# A refused listing (HTTP 401 or 403) is written as the first page's Error, so the import records the inventory as
# denied with what to grant. The public certificates and private keys are never fetched.
# The OAuth access token (scope `certificate`) is read from VENAFI_TOKEN and sent only as a request header, never on
# a command line; get it as you get any (POST /vedauth/authorize/oauth, /certificate or /integrated). VENAFI_CA
# optionally names the CA certificate (PEM) the Web SDK's TLS certificate is trusted by; VENAFI_LIMIT the page
# size (500).
# Usage: export-venafi.sh SOURCE ADDRESS FOLDER OUTDIR
#   e.g. export-venafi.sh venafi-prod https://tpp.example.test/vedsdk '\VED\Policy\Example Aero' ./export
#   then: opsdir import --change CHG-... --at <when> venafi/certificates ./export
set -euo pipefail

usage="usage: export-venafi.sh SOURCE ADDRESS FOLDER OUTDIR (token in VENAFI_TOKEN)"
source=${1:?$usage}
address=${2:?$usage}
folder=${3:?$usage}
out=${4:?$usage}
: "${VENAFI_TOKEN:?$usage}"
address=${address%/}
limit=${VENAFI_LIMIT:-500}          # certificates per page (as collect.py asks)
dir="$out/venafi/$source"
mkdir -p "$dir/details"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# GET URL into $tmp, printing the HTTP status; the token reaches curl as a header file on a pipe, not an argument.
get() {
  local ca=()
  [ -n "${VENAFI_CA:-}" ] && ca=(--cacert "$VENAFI_CA")
  curl -sS -o "$tmp" -w '%{http_code}' "${ca[@]}" -H @<(printf 'Authorization: Bearer %s\n' "$VENAFI_TOKEN") "$1"
}

page_filter='{Folder: $folder, Address: $address, TotalCount: .TotalCount,
  Certificates: [(.Certificates // [])[] | {DN, Guid, Name, ParentDn, SchemaClass, CreatedOn, X509}
    | with_entries(select(.value != null))
    | if .X509 then .X509 |= (with_entries(select(.key | IN("CN", "Issuer", "Subject", "Serial", "Thumbprint",
        "ValidFrom", "ValidTo", "SANS")))) else . end]}'
detail_filter='{Guid, DN, CreatedBy, Disabled, Consumers, ManagementType, CertificateAuthorityDN, Contact,
  ProcessingDetails: (.ProcessingDetails // null | if . then {InError, InProcess, Stage, Status} | with_entries(select(.value != null)) else . end),
  CertificateDetails: (.CertificateDetails // null | if . then {Issuer, Subject, Serial, Thumbprint, ValidFrom,
    ValidTo, SubjectAltNameDNS, SubjectAltNameIPAddress, RevocationStatus, RevocationDate} | with_entries(select(.value != null)) else . end)}
  | with_entries(select(.value != null))'

offset=0
total=1
while [ "$offset" -lt "$total" ]; do
  query=$(jq -rn --arg f "$folder" --arg o "$offset" --arg l "$limit" \
    '"ParentDnRecursive=\($f|@uri)&Limit=\($l)&Offset=\($o)&OptionalFields=Issuer%2CSubject"')
  status=$(get "$address/certificates/?$query")
  case "$status" in
    200) ;;
    401|403)
      jq -n --arg folder "$folder" --arg address "$address" --arg e "HTTP $status" \
        '{Folder: $folder, Address: $address, Error: $e}' > "$dir/certificates-0.json"
      echo "export-venafi: the listing of $folder was refused (HTTP $status): written as denied" >&2
      exit 0 ;;
    *) echo "export-venafi: GET certificates (offset $offset): HTTP $status" >&2; exit 1 ;;
  esac
  jq --arg folder "$folder" --arg address "$address" "$page_filter" "$tmp" > "$dir/certificates-$offset.json"
  total=$(jq '.TotalCount // 0' "$tmp")
  offset=$((offset + limit))
done

jq -r '.Certificates[].Guid' "$dir"/certificates-*.json | while read -r guid; do
  key=$(printf '%s' "$guid" | tr -d '{}' | tr '[:upper:]' '[:lower:]')
  status=$(get "$address/certificates/$(jq -rn --arg g "$guid" '$g|@uri')")
  case "$status" in
    200) jq "$detail_filter" "$tmp" > "$dir/details/$key.json" ;;
    403|404) echo "export-venafi: $guid: HTTP $status: its details are left out" >&2 ;;
    *) echo "export-venafi: GET certificates/$guid: HTTP $status" >&2; exit 1 ;;
  esac
done
echo "export-venafi: $(ls "$dir/details" | wc -l) certificate(s) of $folder written to $dir" >&2
