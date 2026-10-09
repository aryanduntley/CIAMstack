# PingFederate Admin API specs

`admin-api-<version>.json` are derived from Ping Identity's OpenAPI documents of the PingFederate Administrative API,
as published in github.com/pingidentity/pingfederate-go-client (`configurationapi/api/openapi.yaml` at the tag of each
PingFederate version, named in each file's `source`), under the Apache License 2.0 (`LICENSE-pingfederate-go-client.md`).

They are modified: `scripts/vendor-admin-api-specs.py` keeps only what offline validation needs (each POST and PUT
request's body schema, and the schemas' validation keywords) and leaves out descriptions, examples and formats.
Regenerate them with that script; don't edit them by hand.

# PingFederate Terraform provider schemas

`terraform-provider-<release>.json` are derived from the resource schemas of Ping Identity's Terraform provider for
PingFederate (github.com/pingidentity/terraform-provider-pingfederate, the release named in each file), as
`terraform providers schema -json` prints them, under the Apache License 2.0 (`LICENSE-terraform-provider-pingfederate.txt`).

They are modified: `scripts/vendor-provider-schemas.py` keeps only the resources the terraform render target maps,
each attribute with its flags, type and nested attributes, and leaves out descriptions. Regenerate them with that
script; don't edit them by hand.
