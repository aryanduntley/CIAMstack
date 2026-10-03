#!/bin/sh
# Ask AWS's evaluator about each permission of the identities source/stage binds; the answers are saved
# under <folder>/evaluations/ and read back by the cloud's CLI importer (opsdir import <cloud>/cli-inventory).
# Run where the cloud's CLI is signed in, with the environment's export folder (<cloud>/<env>/):
#   sh access/evaluate.sh export/source/stage
set -eu
OUT="${1:?usage: evaluate.sh <export folder for the environment>}"

# identity identity-ds (arn:aws:iam::111122223333:role/ciam-prod-ds): pingds
mkdir -p "$OUT/evaluations/ciam-prod-ds"
# read-secret ds-root-password: not asked (its role isn't bound here, AWS has no mapping for it, or its evaluator can't answer for it)
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/ciam-prod-ds --action-names kms:Decrypt kms:Encrypt kms:GenerateDataKey --resource-arns arn:aws:kms:us-east-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab --output json > "$OUT/evaluations/ciam-prod-ds/use-key__disk-encryption.json"
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/ciam-prod-ds --action-names logs:PutLogEvents logs:CreateLogStream --resource-arns 'arn:aws:logs:us-east-1:111122223333:log-group:/ciam/prod/audit:*' arn:aws:logs:us-east-1:111122223333:log-group:/ciam/prod/audit --output json > "$OUT/evaluations/ciam-prod-ds/write-logs__audit-logs.json"
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/ciam-prod-ds --action-names s3:PutObject --resource-arns 'arn:aws:s3:::example-aero-ciam-stage-ds-backups/*' arn:aws:s3:::example-aero-ciam-stage-ds-backups --output json > "$OUT/evaluations/ciam-prod-ds/write-storage__backup-target.json"

# identity identity-pf (arn:aws:iam::111122223333:role/ciam-prod-pf): pingfederate
mkdir -p "$OUT/evaluations/ciam-prod-pf"
# read-secret pf-admin-password: not asked (its role isn't bound here, AWS has no mapping for it, or its evaluator can't answer for it)
# read-secret pf-ds-bind-password: not asked (its role isn't bound here, AWS has no mapping for it, or its evaluator can't answer for it)
# read-secret pf-signing-key: not asked (its role isn't bound here, AWS has no mapping for it, or its evaluator can't answer for it)
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/ciam-prod-pf --action-names logs:PutLogEvents logs:CreateLogStream --resource-arns 'arn:aws:logs:us-east-1:111122223333:log-group:/ciam/prod/audit:*' arn:aws:logs:us-east-1:111122223333:log-group:/ciam/prod/audit --output json > "$OUT/evaluations/ciam-prod-pf/write-logs__audit-logs.json"
