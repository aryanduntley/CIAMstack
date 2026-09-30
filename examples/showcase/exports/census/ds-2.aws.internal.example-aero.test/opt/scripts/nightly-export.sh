#!/bin/sh
# Nightly entitlement export for MRO analytics (fictional; part of the Example Aero showcase)
set -eu
ldapsearch -H ldaps://ds-1.aws.internal.example-aero.test:1636 \
  -D "uid=mro-export, ou=service-accounts, dc=partners, dc=example-aero, dc=test" -y /etc/ciam/mro-export.pw \
  -b "ou=people,dc=partners,dc=example-aero,dc=test" "(objectClass=exampleAeroPerson)" mail companyId soldToAccount \
  > /var/tmp/entitlements.ldif
scp /var/tmp/entitlements.ldif mro@10.20.1.11:/incoming/
