#!/usr/bin/env python3
"""Vendor PingFederate's Admin API specs, one per supported version, as this package's data
(src/opsdir_adapter_pingfederate/specs/admin-api-<major.minor>.json): what opsdir_adapter_pingfederate.admin_api_spec
validates rendered payloads against, offline.

The specs are Ping Identity's own: the OpenAPI document each release of github.com/pingidentity/pingfederate-go-client
is generated from (configurationapi/api/openapi.yaml at the tag of that PingFederate version; Apache License 2.0, a copy
kept beside the specs). Only what validation needs is kept: for each POST and PUT, the schema of its request body, and
the schemas with their validation keywords (prose and examples left out). Reads a local clone, never the network:

  git clone --filter=blob:none --no-checkout https://github.com/pingidentity/pingfederate-go-client.git /tmp/pf-go
  packages/opsdir-adapter-pingfederate/scripts/vendor-admin-api-specs.py /tmp/pf-go
"""
import json
import pathlib
import subprocess
import sys

import yaml

# PingFederate version (major.minor) -> the pingfederate-go-client tag generated from its Admin API
TAGS = (("12.1", "v1210.0.5"), ("12.2", "v1220.0.0"), ("12.3", "v1230.0.3"), ("13.0", "v1300.1.0"),
        ("13.1", "v1310.0.0"))
SPEC = "configurationapi/api/openapi.yaml"
KEEP = ("type", "properties", "required", "items", "$ref", "allOf", "oneOf", "discriminator", "additionalProperties",
        "enum", "pattern", "minLength", "maxLength", "uniqueItems", "readOnly")
OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "opsdir_adapter_pingfederate" / "specs"


def _schema_name(ref):
    return ref.rsplit("/", 1)[-1]


def trimmed_schema(schema):
    """A schema with only the validation keywords (prose, examples and formats left out), its parts trimmed too."""
    if isinstance(schema, list):
        return [trimmed_schema(s) for s in schema]
    if not isinstance(schema, dict):
        return schema
    kept = {k: v for k, v in schema.items() if k in KEEP}
    return {**kept,
            **({"properties": {n: trimmed_schema(p) for n, p in kept["properties"].items()}}
               if "properties" in kept else {}),
            **{k: trimmed_schema(kept[k]) for k in ("items", "allOf", "oneOf") if k in kept},
            **({"additionalProperties": trimmed_schema(kept["additionalProperties"])}
               if isinstance(kept.get("additionalProperties"), dict) else {}),
            **({"discriminator": {k: v for k, v in kept["discriminator"].items() if k in ("propertyName", "mapping")}}
               if "discriminator" in kept else {})}


def _body_ref(operation):
    """The $ref of an operation's request body schema: its JSON content's, else its only content's (older specs
    declare */*), or None."""
    content = (operation.get("requestBody") or {}).get("content") or {}
    found = content.get("application/json") or next(iter(content.values()), None) or {}
    return (found.get("schema") or {}).get("$ref")


def trimmed_spec(spec, tag):
    """The vendored form of an OpenAPI document: its version and source, each POST/PUT request's body schema by
    'METHOD path', and the trimmed component schemas."""
    requests = {f"{method.upper()} {path}": _schema_name(ref)
                for path, operations in spec["paths"].items() for method, op in operations.items()
                if method in ("post", "put") for ref in [_body_ref(op)] if ref}
    return {"version": spec["info"]["version"], "source": f"pingfederate-go-client {tag} {SPEC}",
            "requests": dict(sorted(requests.items())),
            "schemas": {n: trimmed_schema(s) for n, s in sorted(spec["components"]["schemas"].items())}}


def _show(clone, ref, path):
    return subprocess.run(["git", "-C", str(clone), "show", f"{ref}:{path}"], check=True, capture_output=True,
                          text=True).stdout


def main(clone):
    """Effect: write each version's trimmed spec and the upstream license under OUT."""
    OUT.mkdir(parents=True, exist_ok=True)
    for version, tag in TAGS:
        spec = trimmed_spec(yaml.safe_load(_show(clone, tag, SPEC)), tag)
        (OUT / f"admin-api-{version}.json").write_text(json.dumps(spec, sort_keys=True, separators=(",", ":")) + "\n")
        print(f"{version}: {tag} (Admin API {spec['version']}), {len(spec['requests'])} requests, "
              f"{len(spec['schemas'])} schemas")
    (OUT / "LICENSE-pingfederate-go-client.md").write_text(_show(clone, TAGS[-1][1], "LICENSE.md"))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(pathlib.Path(sys.argv[1]))
