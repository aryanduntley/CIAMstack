#!/bin/sh
# Ask Google Cloud's evaluator about each permission of the identities standby/prod binds; the answers are saved
# under <folder>/evaluations/ and read back by the cloud's CLI importer (opsdir import <cloud>/cli-inventory).
# Run where the cloud's CLI is signed in, with the environment's export folder (<cloud>/<env>/):
#   sh access/evaluate.sh export/standby/prod
set -eu
OUT="${1:?usage: evaluate.sh <export folder for the environment>}"

# identity identity-ci (ciam-standby-deploy@example-aero-ciam-standby.iam.gserviceaccount.com): ciam-ops-ci
mkdir -p "$OUT/evaluations/ciam-standby-deploy"
# manage pf-sso-service: not asked (its role isn't bound here, Google Cloud has no mapping for it, or its evaluator can't answer for it)
gcloud policy-intelligence troubleshoot-policy iam //secretmanager.googleapis.com/projects/example-aero-ciam-standby/secrets/pf-admin-password --principal-email=ciam-standby-deploy@example-aero-ciam-standby.iam.gserviceaccount.com --permission=secretmanager.versions.add --format=json > "$OUT/evaluations/ciam-standby-deploy/write-secret__pf-admin-password.json"

# identity identity-ds (ciam-standby-ds@example-aero-ciam-standby.iam.gserviceaccount.com): pingds
mkdir -p "$OUT/evaluations/ciam-standby-ds"
gcloud policy-intelligence troubleshoot-policy iam //secretmanager.googleapis.com/projects/example-aero-ciam-standby/secrets/ds-root-password --principal-email=ciam-standby-ds@example-aero-ciam-standby.iam.gserviceaccount.com --permission=secretmanager.versions.access --format=json > "$OUT/evaluations/ciam-standby-ds/read-secret__ds-root-password.json"
gcloud policy-intelligence troubleshoot-policy iam //cloudkms.googleapis.com/projects/example-aero-ciam-standby/locations/us-central1/keyRings/ciam/cryptoKeys/disk --principal-email=ciam-standby-ds@example-aero-ciam-standby.iam.gserviceaccount.com --permission=cloudkms.cryptoKeyVersions.useToDecrypt --format=json > "$OUT/evaluations/ciam-standby-ds/use-key__disk-encryption.json"
gcloud policy-intelligence troubleshoot-policy iam //logging.googleapis.com/projects/example-aero-ciam-standby/locations/global/buckets/ciam-audit --principal-email=ciam-standby-ds@example-aero-ciam-standby.iam.gserviceaccount.com --permission=logging.logEntries.create --format=json > "$OUT/evaluations/ciam-standby-ds/write-logs__audit-logs.json"
gcloud policy-intelligence troubleshoot-policy iam //storage.googleapis.com/projects/_/buckets/example-aero-ciam-standby-ds-backups --principal-email=ciam-standby-ds@example-aero-ciam-standby.iam.gserviceaccount.com --permission=storage.objects.create --format=json > "$OUT/evaluations/ciam-standby-ds/write-storage__backup-target.json"

# identity identity-pf (ciam-standby-pf@example-aero-ciam-standby.iam.gserviceaccount.com): pingfederate
mkdir -p "$OUT/evaluations/ciam-standby-pf"
gcloud policy-intelligence troubleshoot-policy iam //secretmanager.googleapis.com/projects/example-aero-ciam-standby/secrets/pf-admin-password --principal-email=ciam-standby-pf@example-aero-ciam-standby.iam.gserviceaccount.com --permission=secretmanager.versions.access --format=json > "$OUT/evaluations/ciam-standby-pf/read-secret__pf-admin-password.json"
gcloud policy-intelligence troubleshoot-policy iam //secretmanager.googleapis.com/projects/example-aero-ciam-standby/secrets/pf-ds-bind-password --principal-email=ciam-standby-pf@example-aero-ciam-standby.iam.gserviceaccount.com --permission=secretmanager.versions.access --format=json > "$OUT/evaluations/ciam-standby-pf/read-secret__pf-ds-bind-password.json"
gcloud policy-intelligence troubleshoot-policy iam //secretmanager.googleapis.com/projects/example-aero-ciam-standby/secrets/pf-signing-key --principal-email=ciam-standby-pf@example-aero-ciam-standby.iam.gserviceaccount.com --permission=secretmanager.versions.access --format=json > "$OUT/evaluations/ciam-standby-pf/read-secret__pf-signing-key.json"
gcloud policy-intelligence troubleshoot-policy iam //logging.googleapis.com/projects/example-aero-ciam-standby/locations/global/buckets/ciam-audit --principal-email=ciam-standby-pf@example-aero-ciam-standby.iam.gserviceaccount.com --permission=logging.logEntries.create --format=json > "$OUT/evaluations/ciam-standby-pf/write-logs__audit-logs.json"
