#!/usr/bin/env python3
"""Vendor the resource schemas of the pingidentity/pingfederate Terraform provider releases the terraform target pins
(opsdir_adapter_pingfederate.terraform_target.PROVIDERS) as this package's data
(src/opsdir_adapter_pingfederate/specs/terraform-provider-<release>.json): what the target converts each Admin API
body against.

The schemas are the provider's own (github.com/pingidentity/terraform-provider-pingfederate, Apache License 2.0), as
`terraform providers schema -json` prints them; only the resources the target maps (RESOURCES) are kept, each attribute
with its flags (required, optional, computed, sensitive), its type and its nested attributes (descriptions left out).
Reads schema dumps made beforehand (terraform needs network access to install the provider once):

  mkdir /tmp/pf && printf 'terraform {\\n  required_providers {\\n    pingfederate = {\\n      source  = "pingidentity/pingfederate"\\n      version = "1.10.0"\\n    }\\n  }\\n}\\n' > /tmp/pf/main.tf
  tools/bin/terraform -chdir=/tmp/pf init -backend=false && tools/bin/terraform -chdir=/tmp/pf providers schema -json > /tmp/pf-1.10.0.json
  packages/opsdir-adapter-pingfederate/scripts/vendor-provider-schemas.py 1.10.0=/tmp/pf-1.10.0.json 1.8.1=/tmp/pf-1.8.1.json
"""
import json
import pathlib
import sys

from opsdir_adapter_pingfederate.terraform_target import RESOURCES, SOURCE

OUT = pathlib.Path(__file__).resolve().parents[1] / "src" / "opsdir_adapter_pingfederate" / "specs"
FLAGS = ("required", "optional", "computed", "sensitive")


def trimmed_attributes(attributes):
    """Attributes with their flags, type and nested attributes only."""
    return {name: {**{f: True for f in FLAGS if a.get(f)}, **({"type": a["type"]} if "type" in a else {}),
                   **({"nested": {"mode": a["nested_type"]["nesting_mode"],
                                  "attributes": trimmed_attributes(a["nested_type"]["attributes"])}}
                      if "nested_type" in a else {})}
            for name, a in sorted(attributes.items())}


def trimmed_schema(dump, release):
    """The vendored form of a provider schema dump: the release and the mapped resources' attributes."""
    found = dump["provider_schemas"][f"registry.terraform.io/{SOURCE}"]["resource_schemas"]
    wanted = sorted({tf_type for tf_type, _ in RESOURCES.values()} & set(found))
    return {"provider": SOURCE, "release": release,
            "resources": {r: trimmed_attributes(found[r]["block"].get("attributes") or {}) for r in wanted}}


def main(pairs):
    """Effect: write each release's trimmed schema (pairs: 'release=dump.json') and the upstream license note."""
    OUT.mkdir(parents=True, exist_ok=True)
    for pair in pairs:
        release, path = pair.split("=", 1)
        schema = trimmed_schema(json.loads(pathlib.Path(path).read_text()), release)
        (OUT / f"terraform-provider-{release}.json").write_text(
            json.dumps(schema, sort_keys=True, separators=(",", ":")) + "\n")
        print(f"{release}: {len(schema['resources'])} resources")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
