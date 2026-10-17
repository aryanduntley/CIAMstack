"""The showcase's AWS environments rendered as CloudFormation (the aws render target cloudformation), before and after
the approved changes, checked by the pinned cfn-lint against AWS's resource schemas for each template's region
(tools/cfn-lint, opsdir/scripts/fetch-tools.sh; skipped without it). The only errors allowed are the record's own
gaps, which Terraform's apply fails on as well: an HTTPS listener whose certificate the environment doesn't bind
(its comments say UNBOUND), an application load balancer on fewer than two subnets (an environment binding one
zone), and a load balancer on no subnet (no server serves its service's role there). Warnings (an availability zone
the record names, Lambda code `aws cloudformation package` uploads) don't fail."""
import json
import os
import pathlib
import subprocess

import pytest

from opsdir.connectors.registry import ADAPTERS, environment_specs, services
from opsdir.connectors.render import render_env, render_parts
from opsdir_adapter_aws.cfn_types import cloudformation_files, cloudformation_translation
from opsdir_adapter_aws.terraform import WHAT, render_files
from opsdir_format_cloudformation.template import template_data
import cloudformation_sample

ROOT = pathlib.Path(__file__).resolve().parents[4]
LINT = ROOT / "tools" / "cfn-lint" / "venv" / "bin" / "cfn-lint"
pytestmark = [pytest.mark.cloudformation,
              pytest.mark.skipif(not LINT.exists(), reason="no tools/cfn-lint (opsdir/scripts/fetch-tools.sh)")]
CLOUDFORMATION = {"aws": ("cloudformation",)}


def _record_gap(template, error):
    """Whether a cfn-lint error is one of the record's own gaps (see the module docstring)."""
    path = error["Location"]["Path"]
    if len(path) < 2 or path[0] != "Resources":
        return False
    r = template["Resources"][path[1]]
    comments = " ".join(r.get("Metadata", {}).get("Comments", []))
    rule = error["Rule"]["Id"]
    if rule == "E3676" and r["Type"] == "AWS::ElasticLoadBalancingV2::Listener":
        return "UNBOUND" in comments and "Certificates" in error["Message"]
    if rule == "E3680" and r["Type"] == "AWS::ElasticLoadBalancingV2::LoadBalancer":
        props = r["Properties"]
        return props.get("Type") == "application" and len(props.get("Subnets", [])) < 2
    if rule == "E3014" and r["Type"] == "AWS::ElasticLoadBalancingV2::LoadBalancer":
        props = r["Properties"]
        return "Subnets" not in props and "SubnetMappings" not in props
    return False


def _rendered(d, out):
    """(spec, path, written file, template document) of the cloudformation-yaml files of each AWS environment's
    render, written under out; the document is the translation's (what the file was written from)."""
    written, found = [], services(ADAPTERS)
    for spec in environment_specs(d):
        m, adapters, _, _, _ = render_parts(d, spec)
        if not any(a.name == "aws" for a in adapters):
            continue
        _, files = render_env(d, spec, wanted=CLOUDFORMATION)
        templates = cloudformation_translation(m, render_files(m, found), WHAT).templates
        formats = json.loads(files["MANIFEST.json"])["files"]
        for p, text in files.items():
            if formats.get(p, {}).get("format") == "cloudformation-yaml":
                f = out / spec.replace("/", "-") / p
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(text)
                written.append((spec, p, f, template_data(templates[p])))
    return written


def _sample(region, out):
    """(name, path, written file, template document) of the CloudFormation sample's templates in region, written under
    out."""
    written = []
    for name, m, files in cloudformation_sample.renders(region):
        t = cloudformation_translation(m, files, WHAT)
        for p, text in cloudformation_files(m, files, WHAT).items():
            if p in t.templates:
                f = out / region / name / p
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(text)
                written.append((name, p, f, template_data(t.templates[p])))
    return written


def _linted(rendered):
    """(cfn-lint's errors that aren't the record's own gaps, all its errors, its stderr) over rendered."""
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    done = subprocess.run([str(LINT), "--format", "json", "--non-zero-exit-code", "none", "--",
                           *(str(f) for _, _, f, _ in rendered)], capture_output=True, text=True, env=env)
    found = json.loads(done.stdout or "[]")
    by_file = {str(f): (spec, p, document) for spec, p, f, document in rendered}
    errors = [e for e in found if e["Level"] == "Error"]
    return ([(by_file[e["Filename"]][:2], e["Rule"]["Id"], e["Location"]["Path"], e["Message"]) for e in errors
             if not _record_gap(by_file[e["Filename"]][2], e)], errors, done.stderr)


@pytest.mark.parametrize("state", ["before", "after"])
def test_the_showcase_cloudformation_passes_cfn_lint_but_for_the_records_own_gaps(estate, tmp_path, state):
    rendered = _rendered(estate[state], tmp_path)
    assert rendered
    unexpected, errors, stderr = _linted(rendered)
    assert errors, "the record's gaps are expected to show (an unbound certificate, a one-zone load balancer)"
    assert unexpected == [], stderr


@pytest.mark.parametrize("region", ["us-east-1", "us-gov-west-1"])
def test_every_type_the_renderers_write_passes_cfn_lint_in_the_region(tmp_path, region):
    """The CloudFormation sample (every resource and data source type beyond the showcase), each template checked
    against its own region's schemas: in GovCloud, what GovCloud's CloudFormation lacks stays Terraform."""
    rendered = _sample(region, tmp_path)
    assert {name for name, *_ in rendered} == {"plumbing", "gateway", "dns", "services", "logs", "siem"}
    unexpected, _, stderr = _linted(rendered)
    assert unexpected == [], stderr
