#!/usr/bin/env bash
# Validate, on a throwaway local cluster, how Secrets the Secrets Store CSI driver syncs reach workloads whose
# deployment kit can't mount a SecretProviderClass (ForgeOps' charts): a sync pod mounts the class so the driver keeps
# the Kubernetes Secret, and the product's pods read it by secretKeyRef. Checks, with a real provider (HashiCorp Vault
# in dev mode and its CSI provider; Kubernetes auth bound to the sync pod's service account):
#   identity       the provider authenticates as the sync pod's service account; another account is refused
#   rbac           that account holds no Kubernetes RBAC (the driver writes the Secret, not the pod)
#   pod security   the namespace enforces restricted; the sync pod (pause, non-root, no privilege escalation, no
#                  capabilities, RuntimeDefault seccomp, read-only root) and its csi volume are admitted
#   startup order  a product pod created before the sync waits (its Secret missing) and starts once the Secret exists
#   sync           the Secret holds the value Vault holds
#   rotation       a value changed in Vault reaches the Secret (driver rotation on, 10s poll)
#   lifecycle      deleting the sync pod's Deployment deletes the Secret (the driver's documented rule)
# Needs Docker and opsdir/scripts/fetch-tools.sh's kind, kubectl and helm; pulls the images below. Never prints a
# secret value (compares digests). The sync pods are the ones opsdir renders (opsdir_adapter_kubernetes.render.
# sync_deployment), so what is validated is what is rendered. The cluster is deleted at the end unless KEEP=1.
#   opsdir/scripts/validate-csi-sync.sh
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN=$ROOT/tools/bin
KIND=$BIN/kind KUBECTL=$BIN/kubectl HELM=$BIN/helm PY=$ROOT/opsdir/.venv/bin/python
unset PYTHONPATH                  # a folder a shell exports there would shadow the venv's packages
CLUSTER=opsdir-csi-sync
NODE_IMAGE=kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5
CSI_CHART_VERSION=1.6.1           # secrets-store-csi-driver, 2026-09-09
VAULT_CHART_VERSION=0.34.1        # vault-helm, 2026-08-13 (its CSI provider 1.7.4)
VAULT_VERSION=2.1.2               # 2026-10-07 (the chart defaults to 2.0.4)
PAUSE_IMAGE=$("$ROOT/opsdir/.venv/bin/python" -c \
  'from opsdir_adapter_kubernetes.render import SYNC_IMAGE; print(SYNC_IMAGE)')   # the image the sync pods run
CONSUMER_IMAGE=busybox:1.37.0
NS=ciam SA=pf-admin OTHER_SA=other SECRET=pf-secrets KEY=ADMIN_PASSWORD
for t in "$KIND" "$KUBECTL" "$HELM" "$PY"; do [ -x "$t" ] || { echo "missing $t: run opsdir/scripts/fetch-tools.sh" >&2; exit 2; }; done
k() { "$KUBECTL" --context "kind-$CLUSTER" "$@"; }
failures=()
check() {                                   # check <label> <command...>: ok / FAILED, failures collected
  local label=$1; shift
  if "$@"; then echo "ok      $label"; else echo "FAILED  $label"; failures+=("$label"); fi
}
digest() { sha256sum | cut -c1-16; }
vault_put() { k -n vault exec vault-0 -- vault kv put -mount=secret ciam/pf admin-password="$1" >/dev/null; }
secret_digest() { k -n "$NS" get secret "$SECRET" -o "jsonpath={.data.$KEY}" 2>/dev/null | base64 -d | digest; }
wait_for() {                                # wait_for <seconds> <command...>: until the command succeeds
  local n=$1; shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done; return 1
}
cleanup() { [ "${KEEP:-}" = 1 ] || "$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1; }
trap cleanup EXIT

"$KIND" delete cluster --name "$CLUSTER" >/dev/null 2>&1
"$KIND" create cluster --name "$CLUSTER" --image "$NODE_IMAGE" --wait 120s >/dev/null || { echo "kind failed" >&2; exit 1; }
"$HELM" --kube-context "kind-$CLUSTER" install csi secrets-store-csi-driver \
  --repo https://kubernetes-sigs.github.io/secrets-store-csi-driver/charts --version "$CSI_CHART_VERSION" \
  -n kube-system --set syncSecret.enabled=true --set enableSecretRotation=true --set rotationPollInterval=10s \
  --wait >/dev/null || { echo "CSI driver install failed" >&2; exit 1; }
"$HELM" --kube-context "kind-$CLUSTER" install vault vault --repo https://helm.releases.hashicorp.com \
  --version "$VAULT_CHART_VERSION" -n vault --create-namespace --set server.dev.enabled=true \
  --set server.image.tag="$VAULT_VERSION" --set injector.enabled=false --set csi.enabled=true --wait >/dev/null ||
  { echo "Vault install failed" >&2; exit 1; }
wait_for 120 k -n vault exec vault-0 -- vault status

# Vault: a value, a read policy, Kubernetes auth with a role bound to the sync pod's service account only
vault_put first-value-1
k -n vault exec -i vault-0 -- sh -c '
  vault auth enable kubernetes >/dev/null &&
  vault write auth/kubernetes/config kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443" >/dev/null &&
  printf "path \"secret/data/ciam/pf\" { capabilities = [\"read\"] }\n" | vault policy write pf-read - >/dev/null &&
  vault write auth/kubernetes/role/pf bound_service_account_names='"$SA"' bound_service_account_namespaces='"$NS"' \
    policies=pf-read ttl=10m >/dev/null 2>&1' || { echo "Vault setup failed" >&2; exit 1; }

spc() {                                     # spc <name> <secret name>: a SecretProviderClass syncing <secret name>
  cat <<EOF
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: {name: $1, namespace: $NS}
spec:
  provider: vault
  parameters:
    vaultAddress: http://vault.vault:8200
    roleName: pf
    objects: |
      - objectName: $2-$KEY
        secretPath: secret/data/ciam/pf
        secretKey: admin-password
  secretObjects:
  - secretName: $2
    type: Opaque
    data: [{objectName: $2-$KEY, key: $KEY}]
EOF
}
restricted() {                              # a restricted container security context
  cat <<EOF
        securityContext:
          runAsNonRoot: true
          runAsUser: 65535
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities: {drop: [ALL]}
          seccompProfile: {type: RuntimeDefault}
EOF
}
sync_pod() {                                # sync_pod <service account> <class>: the sync pod opsdir renders
  "$PY" -c 'import sys
from opsdir.core.interchange.yaml_text import dump
from opsdir_adapter_kubernetes.render import sync_deployment
print(dump(sync_deployment(sys.argv[1], sys.argv[2], (sys.argv[3],))))' "$NS" "$1" "$2"
}

k create namespace "$NS" >/dev/null
k label namespace "$NS" pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest >/dev/null
k -n "$NS" create serviceaccount "$SA" >/dev/null
k -n "$NS" create serviceaccount "$OTHER_SA" >/dev/null
{ spc pf-vault "$SECRET"; echo ---; spc other-vault other-secrets; } | k apply -f - >/dev/null

# the product pod first: its Secret doesn't exist yet
cat <<EOF | k apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata: {name: product, namespace: $NS}
spec:
  replicas: 1
  selector: {matchLabels: {app: product}}
  template:
    metadata: {labels: {app: product}}
    spec:
      automountServiceAccountToken: false
      containers:
      - name: product
        image: $CONSUMER_IMAGE
        command: [sh, -c, 'printf %s "\$$KEY" | sha256sum | cut -c1-16 > /tmp/seen; sleep 3600']
        env: [{name: $KEY, valueFrom: {secretKeyRef: {name: $SECRET, key: $KEY}}}]
        resources: {requests: {cpu: 1m, memory: 4Mi}, limits: {memory: 16Mi}}
$(restricted)
        volumeMounts: [{name: tmp, mountPath: /tmp}]
      volumes: [{name: tmp, emptyDir: {}}]
EOF
waiting_for_secret() {
  k -n "$NS" get pods -l app=product -o jsonpath='{.items[0].status.containerStatuses[0].state.waiting.reason}' |
    grep -qx CreateContainerConfigError
}
check "startup order: the product waits while its Secret is missing" wait_for 60 waiting_for_secret

sync_pod "$SA" pf-vault | k apply -f - >/dev/null
check "pod security: the restricted namespace admits the sync pod" \
  wait_for 120 k -n "$NS" rollout status "deployment/$SA-secret-sync" --timeout=5s
check "sync: the Secret exists once the sync pod mounts the class" wait_for 60 k -n "$NS" get secret "$SECRET"
expected=$(printf %s first-value-1 | digest)
check "sync: the Secret holds Vault's value" test "$(secret_digest)" = "$expected"
check "startup order: the product starts once the Secret exists" \
  wait_for 120 k -n "$NS" rollout status deployment/product --timeout=5s
seen() { test "$(k -n "$NS" exec deploy/product -- cat /tmp/seen)" = "$expected"; }
check "sync: the product reads Vault's value" wait_for 30 seen

can_read_secrets() { k auth can-i get secrets -n "$NS" --as "system:serviceaccount:$NS:$SA" >/dev/null 2>&1; }
check "rbac: the sync pod's service account can't read Secrets" eval '! can_read_secrets'

sync_pod "$OTHER_SA" other-vault | k apply -f - >/dev/null
refused() {                                # its pod's mount fails with Vault's 403, and no Secret is made
  k -n "$NS" get events --field-selector reason=FailedMount \
    -o jsonpath='{range .items[*]}{.involvedObject.name}{" "}{.message}{"\n"}{end}' |
    tr '\n' ' ' | grep -q "$OTHER_SA-secret-sync.*service account name not authorized" &&
    ! k -n "$NS" get secret other-secrets >/dev/null 2>&1
}
check "identity: Vault refuses a pod of another service account" wait_for 90 refused

vault_put rotated-value-2
rotated() { test "$(secret_digest)" = "$(printf %s rotated-value-2 | digest)"; }
check "rotation: a value changed in Vault reaches the Secret" wait_for 90 rotated

k -n "$NS" delete deployment "$SA-secret-sync" --wait=true >/dev/null
gone() { ! k -n "$NS" get secret "$SECRET" >/dev/null 2>&1; }
check "lifecycle: deleting the sync pod deletes the Secret" wait_for 120 gone

echo
echo "versions: kind node $(k version -o json 2>/dev/null | python3 -I -c 'import json,sys;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])'), CSI driver chart $CSI_CHART_VERSION, Vault $VAULT_VERSION (chart $VAULT_CHART_VERSION), $PAUSE_IMAGE"
if [ ${#failures[@]} -gt 0 ]; then
  echo "FAILED: ${failures[*]}"; exit 1
fi
echo "all checks passed"
