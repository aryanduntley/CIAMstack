# IDM project of the partner identity sync (synthetic)

A made-up PingIDM project (`conf/` and `script/`): partner users come from the HR database and are provisioned into the user directory. The demo reads it into the record with `opsdir import --change CHG-2004 pingidm exports/idm`: the directory connector's host becomes the `ds-ldaps-service` role and its bind account is linked to the `idm-sync` consumer record; both connectors' credentials are withheld, and approved change CHG-2005 names the secret roles they come from.
