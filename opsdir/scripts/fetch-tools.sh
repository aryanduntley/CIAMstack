#!/usr/bin/env bash
# Download the third-party tools the tests use on rendered output into tools/ at the repository root. That folder is
# gitignored and holds nothing else: delete it to remove them. Idempotent: what is already there is kept.
#   opsdir/scripts/fetch-tools.sh
# Terraform: the release zip, checked against HashiCorp's SHA256SUMS, whose signature is checked against HashiCorp's
# release key (fingerprint pinned below) in a keyring inside tools/, never the user's.
# Helm, Kustomize, kubeconform (Kubernetes output, opsdir/scripts/validate-kubernetes.sh) and Prometheus's promtool
# (rule files): each release archive checked
# against the SHA-256 pinned below (Linux amd64 and arm64), taken from the project's own published sums when the
# version was pinned (Helm's archives also verified then against their signatures by a key in Helm's KEYS file).
# Ansible (opsdir/scripts/validate-ansible.sh): ansible-core and ansible-lint at the versions pinned below in their own
# venv (tools/ansible/venv; their own dependencies resolved by pip, not hash-pinned), and the Galaxy collections and
# roles opsdir-adapter-ansible pins (requirements.py) into tools/ansible/collections and tools/ansible/roles; F5's AS3
# JSON schema (checked against the SHA-256 pinned below) into tools/ansible.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TOOLS=$ROOT/tools
TF_VERSION=1.16.5
HASHICORP_KEY=C874011F0AB405110D02105534365D9472D7468F    # https://www.hashicorp.com/security (release signing key)
HELM_VERSION=4.3.0                # 2026-09-09; ForgeOps 2026.3 works with Helm 3 or 4 and recommends the latest
KUSTOMIZE_VERSION=5.8.2           # 2026-09-30
KUBECONFORM_VERSION=0.8.0         # 2026-06-04
PROMETHEUS_VERSION=3.15.0         # 2026-09-24: its promtool checks opsdir-adapter-prometheus's rule files
ANSIBLE_CORE_VERSION=2.21.4       # 2026-09-08 (controller Python 3.12-3.14)
ANSIBLE_LINT_VERSION=26.9.0       # 2026-09-22
AS3_SCHEMA=3.54.0-6               # F5 AS3 LTS JSON schema (opsdir-adapter-f5's declarations)
AS3_SHA256=9bef9d9e8f2fc6e52eef7491683f09dbacd572d87018b68c49013f9857d38fd3

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
    promtool-linux-amd64) echo 2a542df32eac02ee17b9d844fb2aa1de00dafa5476579ba8a3ba862e9d572ea0 ;;
    promtool-linux-arm64) echo f1f90ec08e849d494ca66c611470afc50192f0355f1a61c33f2cbde02d067823 ;;
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
if [ -x "$TOOLS/bin/promtool" ] && "$TOOLS/bin/promtool" --version 2>&1 | grep -q "version $PROMETHEUS_VERSION "; then
  echo "promtool $PROMETHEUS_VERSION: already in tools/bin"
else
  pinned_fetch promtool "https://github.com/prometheus/prometheus/releases/download/v$PROMETHEUS_VERSION/prometheus-$PROMETHEUS_VERSION.$os-$arch.tar.gz" \
    "prometheus-$PROMETHEUS_VERSION.$os-$arch/promtool" &&
    echo "promtool $PROMETHEUS_VERSION: tools/bin/promtool (verified)"
fi

# Ansible: a venv of its own, run without the caller's PYTHONPATH (packages there would shadow the venv's)
ANSIBLE=$TOOLS/ansible
if [ -x "$ANSIBLE/venv/bin/ansible-playbook" ] &&
   env -u PYTHONPATH "$ANSIBLE/venv/bin/python" -m pip show ansible-core 2>/dev/null | grep -x "Version: $ANSIBLE_CORE_VERSION" >/dev/null &&
   env -u PYTHONPATH "$ANSIBLE/venv/bin/python" -m pip show ansible-lint 2>/dev/null | grep -x "Version: $ANSIBLE_LINT_VERSION" >/dev/null; then
  echo "ansible-core $ANSIBLE_CORE_VERSION, ansible-lint $ANSIBLE_LINT_VERSION: already in tools/ansible/venv"
else
  python3 -m venv "$ANSIBLE/venv"
  env -u PYTHONPATH PIP_USER=0 "$ANSIBLE/venv/bin/pip" install --no-cache-dir -q \
    "ansible-core==$ANSIBLE_CORE_VERSION" "ansible-lint==$ANSIBLE_LINT_VERSION"
  echo "ansible-core $ANSIBLE_CORE_VERSION, ansible-lint $ANSIBLE_LINT_VERSION: tools/ansible/venv"
fi
"$ROOT/opsdir/.venv/bin/python" -c '
from opsdir.core.interchange.yaml_text import dump
from opsdir_adapter_ansible.requirements import all_requirements
print(dump(all_requirements()), end="")' > "$ANSIBLE/requirements.yml"
env -u PYTHONPATH ANSIBLE_COLLECTIONS_PATH="$ANSIBLE/collections" "$ANSIBLE/venv/bin/ansible-galaxy" collection install --force -r "$ANSIBLE/requirements.yml" \
  -p "$ANSIBLE/collections" >/dev/null
env -u PYTHONPATH "$ANSIBLE/venv/bin/ansible-galaxy" role install --force -r "$ANSIBLE/requirements.yml" -p "$ANSIBLE/roles" \
  >/dev/null
echo "ansible collections and roles (opsdir-adapter-ansible's pins): tools/ansible/collections, tools/ansible/roles"
schema=$ANSIBLE/as3-schema-$AS3_SCHEMA.json
if ! { [ -f "$schema" ] && echo "$AS3_SHA256  $schema" | sha256sum -c --quiet - 2>/dev/null; }; then
  curl -fsSL "https://raw.githubusercontent.com/F5Networks/f5-appsvcs-extension/main/schema/${AS3_SCHEMA%-*}/as3-schema-$AS3_SCHEMA.json" -o "$schema"
  echo "$AS3_SHA256  $schema" | sha256sum -c --quiet - || { rm -f "$schema"; echo "AS3 schema doesn't match its checksum" >&2; exit 1; }
fi
echo "AS3 schema $AS3_SCHEMA: tools/ansible (verified)"
