#!/usr/bin/env bash
# Download the third-party tools the tests use on rendered output into tools/ at the repository root. That folder is
# gitignored and holds nothing else: delete it to remove them. Idempotent: what is already there is kept.
#   opsdir/scripts/fetch-tools.sh
# Terraform: the release zip, checked against HashiCorp's SHA256SUMS, whose signature is checked against HashiCorp's
# release key (fingerprint pinned below) in a keyring inside tools/, never the user's.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TOOLS=$ROOT/tools
TF_VERSION=1.16.5
HASHICORP_KEY=C874011F0AB405110D02105534365D9472D7468F    # https://www.hashicorp.com/security (release signing key)

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported: $(uname -m)" >&2; exit 1 ;; esac
mkdir -p "$TOOLS/bin" "$TOOLS/terraform-plugins"

terraform_fetch() {
  local zip=terraform_${TF_VERSION}_${os}_${arch}.zip url=https://releases.hashicorp.com/terraform/$TF_VERSION
  local work=$TOOLS/downloads/terraform-$TF_VERSION
  mkdir -p "$work" && chmod 700 "$TOOLS/downloads"
  (cd "$work" &&
   curl -fsSLO "$url/$zip" && curl -fsSLO "$url/terraform_${TF_VERSION}_SHA256SUMS" &&
   curl -fsSLO "$url/terraform_${TF_VERSION}_SHA256SUMS.sig" &&
   curl -fsSL https://www.hashicorp.com/.well-known/pgp-key.txt -o hashicorp.asc)
  local gnupg=$work/gnupg
  mkdir -p "$gnupg" && chmod 700 "$gnupg"
  gpg --homedir "$gnupg" --quiet --import "$work/hashicorp.asc" 2>/dev/null
  gpg --homedir "$gnupg" --quiet --with-colons --fingerprint | grep -q "^fpr:::::::::$HASHICORP_KEY:" ||
    { echo "HashiCorp's key doesn't have the pinned fingerprint $HASHICORP_KEY" >&2; exit 1; }
  gpg --homedir "$gnupg" --quiet --verify "$work/terraform_${TF_VERSION}_SHA256SUMS.sig" \
    "$work/terraform_${TF_VERSION}_SHA256SUMS" 2>/dev/null || { echo "SHA256SUMS signature doesn't verify" >&2; exit 1; }
  (cd "$work" && grep " $zip\$" "terraform_${TF_VERSION}_SHA256SUMS" | sha256sum -c --quiet -) ||
    { echo "$zip doesn't match its checksum" >&2; exit 1; }
  unzip -oq "$work/$zip" terraform -d "$TOOLS/bin"
  rm -rf "$work"
}

if [ -x "$TOOLS/bin/terraform" ] && "$TOOLS/bin/terraform" version | grep -q "^Terraform v$TF_VERSION\$"; then
  echo "terraform $TF_VERSION: already in tools/bin"
else
  terraform_fetch && echo "terraform $TF_VERSION: tools/bin/terraform (verified)"
fi
