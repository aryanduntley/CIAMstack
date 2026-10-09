#!/usr/bin/env bash
# Download the third-party tools the tests use on rendered output into tools/ at the repository root. That folder is
# gitignored and holds nothing else: delete it to remove them. Idempotent: what is already there is kept.
#   opsdir/scripts/fetch-tools.sh
# Terraform: the release zip, checked against HashiCorp's SHA256SUMS, whose signature is checked against HashiCorp's
# release key (fingerprint pinned below) in a keyring inside tools/, never the user's.
# Helm, Kustomize, kubeconform (Kubernetes output, opsdir/scripts/validate-kubernetes.sh): each release archive checked
# against the SHA-256 pinned below (Linux amd64 and arm64), taken from the project's own published sums when the
# version was pinned (Helm's archives also verified then against their signatures by a key in Helm's KEYS file).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TOOLS=$ROOT/tools
TF_VERSION=1.16.5
HASHICORP_KEY=C874011F0AB405110D02105534365D9472D7468F    # https://www.hashicorp.com/security (release signing key)
HELM_VERSION=4.3.0                # 2026-09-09; ForgeOps 2026.3 works with Helm 3 or 4 and recommends the latest
KUSTOMIZE_VERSION=5.8.2           # 2026-09-30
KUBECONFORM_VERSION=0.8.0         # 2026-06-04

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

# The pinned SHA-256 of a release archive for this OS/arch: pinned_sha <tool>
pinned_sha() {
  case "$1-$os-$arch" in
    helm-linux-amd64) echo 86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb ;;
    helm-linux-arm64) echo 31c5794dd55c66a51e6b7d2e2ac7a114ae8b1de41ff1d9ba51748ac973b06a08 ;;
    kustomize-linux-amd64) echo 06af0a202c2b831207d0173f9c9cdb1b30abceca0747cb3fbb72792d26055c95 ;;
    kustomize-linux-arm64) echo 0991957191951cb7dddd142403b5bb98a1fcd6378ba0079dddc1e2c309080a7f ;;
    kubeconform-linux-amd64) echo 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883 ;;
    kubeconform-linux-arm64) echo 1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87 ;;
    *) return 1 ;;
  esac
}

# Download a release archive, check it against its pinned SHA-256, put one member in tools/bin under the tool's name:
#   pinned_fetch <tool> <url> <member in the archive>
pinned_fetch() {
  local tool=$1 url=$2 member=$3 sha work=$TOOLS/downloads/$1
  sha=$(pinned_sha "$tool") || { echo "$tool: no pinned archive for $os/$arch" >&2; return 1; }
  mkdir -p "$work" && chmod 700 "$TOOLS/downloads"
  curl -fsSL "$url" -o "$work/archive.tar.gz"
  echo "$sha  $work/archive.tar.gz" | sha256sum -c --quiet - || { echo "$tool: archive doesn't match its pinned SHA-256" >&2; exit 1; }
  tar -xzf "$work/archive.tar.gz" -C "$work" "$member"
  install -m 0755 "$work/$member" "$TOOLS/bin/$tool"
  rm -rf "$work"
}

if [ -x "$TOOLS/bin/helm" ] && "$TOOLS/bin/helm" version --template '{{.Version}}' | grep -qx "v$HELM_VERSION"; then
  echo "helm $HELM_VERSION: already in tools/bin"
else
  pinned_fetch helm "https://get.helm.sh/helm-v$HELM_VERSION-$os-$arch.tar.gz" "$os-$arch/helm" &&
    echo "helm $HELM_VERSION: tools/bin/helm (verified)"
fi
if [ -x "$TOOLS/bin/kustomize" ] && "$TOOLS/bin/kustomize" version | grep -qx "v$KUSTOMIZE_VERSION"; then
  echo "kustomize $KUSTOMIZE_VERSION: already in tools/bin"
else
  pinned_fetch kustomize "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv$KUSTOMIZE_VERSION/kustomize_v${KUSTOMIZE_VERSION}_${os}_$arch.tar.gz" kustomize &&
    echo "kustomize $KUSTOMIZE_VERSION: tools/bin/kustomize (verified)"
fi
if [ -x "$TOOLS/bin/kubeconform" ] && "$TOOLS/bin/kubeconform" -v | grep -qx "v$KUBECONFORM_VERSION"; then
  echo "kubeconform $KUBECONFORM_VERSION: already in tools/bin"
else
  pinned_fetch kubeconform "https://github.com/yannh/kubeconform/releases/download/v$KUBECONFORM_VERSION/kubeconform-$os-$arch.tar.gz" kubeconform &&
    echo "kubeconform $KUBECONFORM_VERSION: tools/bin/kubeconform (verified)"
fi
