#!/usr/bin/env bash
# Download the third-party tools the tests use on rendered output into tools/ at the repository root. That folder is
# gitignored and holds nothing else: delete it to remove them. Idempotent: what is already there is kept.
#   opsdir/scripts/fetch-tools.sh
# Terraform and the Vault CLI (opsdir-adapter-hashicorp-vault's inventory collector, marker `vault`): each release
# zip checked against HashiCorp's SHA256SUMS, whose signature is checked against HashiCorp's
# release key (fingerprint pinned below) in a keyring inside tools/, never the user's.
# Helm, Kustomize, kubeconform (Kubernetes output, opsdir/scripts/validate-kubernetes.sh) and Prometheus's promtool
# (rule files): each release archive checked
# against the SHA-256 pinned below (Linux amd64 and arm64), taken from the project's own published sums when the
# version was pinned (Helm's archives also verified then against their signatures by a key in Helm's KEYS file).
# Ansible (opsdir/scripts/validate-ansible.sh): ansible-core and ansible-lint at the versions pinned below in their own
# venv (tools/ansible/venv; their own dependencies resolved by pip, not hash-pinned), and the Galaxy collections and
# roles opsdir-adapter-ansible pins (requirements.py) into tools/ansible/collections and tools/ansible/roles; F5's AS3
# JSON schema (checked against the SHA-256 pinned below) into tools/ansible.
# kind and kubectl (opsdir/scripts/validate-csi-sync.sh: a throwaway local cluster): each release's standalone binary,
# checked against the SHA-256 pinned below (the sums the projects publish beside the binaries).
# The Bicep CLI (opsdir/scripts/validate-bicep.sh): the release's standalone binary, checked against the SHA-256 pinned
# below (the digest GitHub reports for the release asset when the version was pinned).
# cfn-lint (opsdir/scripts/validate-cloudformation.sh): at the version pinned below in its own venv
# (tools/cfn-lint/venv; its dependencies resolved by pip, not hash-pinned). The wheel ships the region resource specs,
# so it checks offline.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TOOLS=$ROOT/tools
TF_VERSION=1.16.5
VAULT_VERSION=2.2.0               # 2026-10-15 (the current release); its dev server proves the KV metadata collector
HASHICORP_KEY=C874011F0AB405110D02105534365D9472D7468F    # https://www.hashicorp.com/security (release signing key)
HELM_VERSION=4.3.0                # 2026-09-09; ForgeOps 2026.3 works with Helm 3 or 4 and recommends the latest
KUSTOMIZE_VERSION=5.8.3           # 2026-10-08 (no functional change from 5.8.2)
KUBECONFORM_VERSION=0.8.0         # 2026-06-04
PROMETHEUS_VERSION=3.15.0         # 2026-09-24: its promtool checks opsdir-adapter-prometheus's rule files
ANSIBLE_CORE_VERSION=2.21.5       # 2026-10-05 (controller Python 3.12-3.14)
ANSIBLE_LINT_VERSION=26.9.0       # 2026-09-22
BICEP_VERSION=0.48.1              # 2026-10-05
KIND_VERSION=0.33.0               # 2026-08-26 (default node image kindest/node v1.37.0)
KUBECTL_VERSION=1.37.1            # the stable release (dl.k8s.io/release/stable.txt) on 2026-10-14
CFN_LINT_VERSION=1.57.2           # 2026-10-06 (Python 3.10-3.14)
AS3_SCHEMA=3.54.0-6               # F5 AS3 LTS JSON schema (opsdir-adapter-f5's declarations)
AS3_SHA256=9bef9d9e8f2fc6e52eef7491683f09dbacd572d87018b68c49013f9857d38fd3
OSCAL_VERSION=1.2.3               # 2026-08-07: NIST OSCAL JSON schemas (opsdir-format-oscal's documents)
OSCAL_SHA256="complete:384324105c7a817af0f65b120a963146caa0e0d55d969cf0daf60e063b87a206
poam:f4fd94487408a9589954b5b92d88965c984d4f79b85365cc574b860898759437
ssp:99b1bee2df5604a7d4f1faeab43148e0bd4c4a1f513cd0d2d0c7896aa216a1e7
assessment-results:4034e2032332dbf597e59e0646ec16c2c31df992962490371e91f47b219ff42c
catalog:ab95836e9e8dfeb6fde80007f6cc76fa3192f595d427c751a3f3923c3f474fc2
profile:7c5ff5a92683b6a80ce6a3474dea04e0ea8680a4ecb60702ffa08ebfc677e6cb"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) echo "unsupported: $(uname -m)" >&2; exit 1 ;; esac
mkdir -p "$TOOLS/bin" "$TOOLS/terraform-plugins"

# A HashiCorp release binary into tools/bin, its SHA256SUMS signature and checksum verified: hashicorp_fetch <product> <version>
hashicorp_fetch() {
  local product=$1 version=$2
  local zip=${product}_${version}_${os}_${arch}.zip url=https://releases.hashicorp.com/$product/$version
  local work=$TOOLS/downloads/$product-$version
  mkdir -p "$work" && chmod 700 "$TOOLS/downloads"
  (cd "$work" &&
   curl -fsSLO "$url/$zip" && curl -fsSLO "$url/${product}_${version}_SHA256SUMS" &&
   curl -fsSLO "$url/${product}_${version}_SHA256SUMS.sig" &&
   curl -fsSL https://www.hashicorp.com/.well-known/pgp-key.txt -o hashicorp.asc)
  local gnupg=$work/gnupg
  mkdir -p "$gnupg" && chmod 700 "$gnupg"
  gpg --homedir "$gnupg" --quiet --import "$work/hashicorp.asc" 2>/dev/null
  gpg --homedir "$gnupg" --quiet --with-colons --fingerprint | grep -q "^fpr:::::::::$HASHICORP_KEY:" ||
    { echo "HashiCorp's key doesn't have the pinned fingerprint $HASHICORP_KEY" >&2; exit 1; }
  gpg --homedir "$gnupg" --quiet --verify "$work/${product}_${version}_SHA256SUMS.sig" \
    "$work/${product}_${version}_SHA256SUMS" 2>/dev/null || { echo "SHA256SUMS signature doesn't verify" >&2; exit 1; }
  (cd "$work" && grep " $zip\$" "${product}_${version}_SHA256SUMS" | sha256sum -c --quiet -) ||
    { echo "$zip doesn't match its checksum" >&2; exit 1; }
  unzip -oq "$work/$zip" "$product" -d "$TOOLS/bin"
  rm -rf "$work"
}

if [ -x "$TOOLS/bin/terraform" ] && "$TOOLS/bin/terraform" version | grep -q "^Terraform v$TF_VERSION\$"; then
  echo "terraform $TF_VERSION: already in tools/bin"
else
  hashicorp_fetch terraform "$TF_VERSION" && echo "terraform $TF_VERSION: tools/bin/terraform (verified)"
fi
if [ -x "$TOOLS/bin/vault" ] && "$TOOLS/bin/vault" version | grep -q "^Vault v$VAULT_VERSION "; then
  echo "vault $VAULT_VERSION: already in tools/bin"
else
  hashicorp_fetch vault "$VAULT_VERSION" && echo "vault $VAULT_VERSION: tools/bin/vault (verified)"
fi

# The pinned SHA-256 of a release archive for this OS/arch: pinned_sha <tool>
pinned_sha() {
  case "$1-$os-$arch" in
    helm-linux-amd64) echo 86584a54def73570558f66f5111cc53dfed56689637ae32c1201205d494f54fb ;;
    helm-linux-arm64) echo 31c5794dd55c66a51e6b7d2e2ac7a114ae8b1de41ff1d9ba51748ac973b06a08 ;;
    kustomize-linux-amd64) echo cb9e31198d3f63b44848bd0afc4c8efc56e6cfef9c93a4a39a211940e6decd61 ;;
    kustomize-linux-arm64) echo 9867b76482cfc6d25b546abc1d2b5a32bd137505aba640649b4b378f64f6d68f ;;
    kubeconform-linux-amd64) echo 9bc2bffbf71f261128533edaf912153948b7ff238f9a531ae6d34466ec287883 ;;
    kubeconform-linux-arm64) echo 1f53fc8e81258197a35e8603054162a5af1de8c5af13746c71ab680d9534ed87 ;;
    promtool-linux-amd64) echo 2a542df32eac02ee17b9d844fb2aa1de00dafa5476579ba8a3ba862e9d572ea0 ;;
    promtool-linux-arm64) echo f1f90ec08e849d494ca66c611470afc50192f0355f1a61c33f2cbde02d067823 ;;
    bicep-linux-amd64) echo b09ec25a9d376c1f8e33ede6ed22b587f915ad68488d5db77a6f9541748c7f6e ;;
    bicep-linux-arm64) echo 9cbf6a211137e894a863fbc842e355c2197fc2124a7bda902afe1bceffa35245 ;;
    kind-linux-amd64) echo aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
    kind-linux-arm64) echo 20022bee6cfcd5086cb7234d218e3454e6090022f2a8f55d1fa7fcf42c3867a2 ;;
    kubectl-linux-amd64) echo 65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8 ;;
    kubectl-linux-arm64) echo ff749f4b78d9c4f1ec87307df9b50119ed819e2094aa9810cb9acffc3286c8c7 ;;
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

# Download a release's standalone binary, check it against its pinned SHA-256, put it in tools/bin:
#   pinned_binary <tool> <url>
pinned_binary() {
  local tool=$1 url=$2 sha work=$TOOLS/downloads/$1
  sha=$(pinned_sha "$tool") || { echo "$tool: no pinned binary for $os/$arch" >&2; return 1; }
  mkdir -p "$work" && chmod 700 "$TOOLS/downloads"
  curl -fsSL "$url" -o "$work/$tool"
  echo "$sha  $work/$tool" | sha256sum -c --quiet - || { echo "$tool: binary doesn't match its pinned SHA-256" >&2; exit 1; }
  install -m 0755 "$work/$tool" "$TOOLS/bin/$tool"
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
if [ -x "$TOOLS/bin/kind" ] && "$TOOLS/bin/kind" version | grep -q "^kind v$KIND_VERSION "; then
  echo "kind $KIND_VERSION: already in tools/bin"
else
  pinned_binary kind "https://github.com/kubernetes-sigs/kind/releases/download/v$KIND_VERSION/kind-$os-$arch" &&
    echo "kind $KIND_VERSION: tools/bin/kind (verified)"
fi
if [ -x "$TOOLS/bin/kubectl" ] && "$TOOLS/bin/kubectl" version --client 2>/dev/null | grep -q "v$KUBECTL_VERSION\$"; then
  echo "kubectl $KUBECTL_VERSION: already in tools/bin"
else
  pinned_binary kubectl "https://dl.k8s.io/release/v$KUBECTL_VERSION/bin/$os/$arch/kubectl" &&
    echo "kubectl $KUBECTL_VERSION: tools/bin/kubectl (verified)"
fi
if [ -x "$TOOLS/bin/promtool" ] && "$TOOLS/bin/promtool" --version 2>&1 | grep -q "version $PROMETHEUS_VERSION "; then
  echo "promtool $PROMETHEUS_VERSION: already in tools/bin"
else
  pinned_fetch promtool "https://github.com/prometheus/prometheus/releases/download/v$PROMETHEUS_VERSION/prometheus-$PROMETHEUS_VERSION.$os-$arch.tar.gz" \
    "prometheus-$PROMETHEUS_VERSION.$os-$arch/promtool" &&
    echo "promtool $PROMETHEUS_VERSION: tools/bin/promtool (verified)"
fi
if [ -x "$TOOLS/bin/bicep" ] && "$TOOLS/bin/bicep" --version | grep -q "version $BICEP_VERSION "; then
  echo "bicep $BICEP_VERSION: already in tools/bin"
else
  pinned_binary bicep "https://github.com/Azure/bicep/releases/download/v$BICEP_VERSION/bicep-$os-$([ "$arch" = amd64 ] && echo x64 || echo arm64)" &&
    echo "bicep $BICEP_VERSION: tools/bin/bicep (verified)"
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

# OSCAL JSON schemas (draft-07), one per model plus the complete one, each SHA-256 pinned
OSCAL=$TOOLS/oscal/$OSCAL_VERSION
mkdir -p "$OSCAL"
while IFS=: read -r model sha; do
  schema=$OSCAL/oscal_${model}_schema.json
  if ! { [ -f "$schema" ] && echo "$sha  $schema" | sha256sum -c --quiet - 2>/dev/null; }; then
    curl -fsSL "https://github.com/usnistgov/OSCAL/releases/download/v$OSCAL_VERSION/oscal_${model}_schema.json" -o "$schema"
    echo "$sha  $schema" | sha256sum -c --quiet - || { rm -f "$schema"; echo "OSCAL $model schema doesn't match its checksum" >&2; exit 1; }
  fi
done <<< "$OSCAL_SHA256"
echo "OSCAL $OSCAL_VERSION schemas: tools/oscal/$OSCAL_VERSION (verified)"

# cfn-lint: a venv of its own, run without the caller's PYTHONPATH
CFN=$TOOLS/cfn-lint
if [ -x "$CFN/venv/bin/cfn-lint" ] &&
   env -u PYTHONPATH "$CFN/venv/bin/python" -m pip show cfn-lint 2>/dev/null | grep -x "Version: $CFN_LINT_VERSION" >/dev/null; then
  echo "cfn-lint $CFN_LINT_VERSION: already in tools/cfn-lint/venv"
else
  python3 -m venv "$CFN/venv"
  env -u PYTHONPATH PIP_USER=0 "$CFN/venv/bin/pip" install --no-cache-dir -q "cfn-lint==$CFN_LINT_VERSION"
  echo "cfn-lint $CFN_LINT_VERSION: tools/cfn-lint/venv"
fi
