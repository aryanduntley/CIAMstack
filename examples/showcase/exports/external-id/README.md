# The partners external tenant's Graph configuration (synthetic)

Made-up Microsoft Graph outputs of the target's partners external tenant (Microsoft Entra External ID), as `opsdir
collect --env target/prod --adapter azure` saves them (`external-id`: each read kept to its allowlist), laid out under
`<cloud>/<env>/external-id/`. They're read after CHG-2089 records the tenant: `opsdir import --change CHG-2090
azure/external-id exports/external-id` matches the partner portal's app registration to its integration (Entra gave
it a client ID of its own: a notice, the record's is kept until the portal moves) and records the tenant's sign-up and
sign-in user flow (email one-time passcode, sign-up allowed, the partner's organization collected) and its custom
authentication extension (the partner organization claim at token issuance) beneath the binding. Microsoft's own
b2c-extensions-app is skipped.
