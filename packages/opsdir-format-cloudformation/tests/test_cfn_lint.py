"""Templates as the writers give them, checked by the pinned cfn-lint (tools/cfn-lint, opsdir/scripts/fetch-tools.sh)
for the regions their metadata names."""
import os
import subprocess
from pathlib import Path

import pytest

from opsdir_format_cloudformation.format import as_json, as_yaml
from opsdir_format_cloudformation.template import Resource, Template, get_att, lint_metadata, ref, sub

ROOT = Path(__file__).resolve().parents[3]
LINT = ROOT / "tools" / "cfn-lint" / "venv" / "bin" / "cfn-lint"
pytestmark = [pytest.mark.cloudformation,
              pytest.mark.skipif(not LINT.exists(), reason="no tools/cfn-lint (opsdir/scripts/fetch-tools.sh)")]

BUCKET = Resource("Backups", "AWS::S3::Bucket", {
    "VersioningConfiguration": {"Status": "Enabled"},
    "PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True,
                                       "RestrictPublicBuckets": True}})
ROLE = Resource("Writer", "AWS::IAM::Role", {
    "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]},
    "Policies": [{"PolicyName": "write", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Action": ["s3:PutObject"], "Resource": sub("${Backups.Arn}/*")}]}}]})
PROFILE = Resource("WriterProfile", "AWS::IAM::InstanceProfile", {"Roles": [ref("Writer")]})
CDN = Resource("Cdn", "AWS::CloudFront::Distribution", {"DistributionConfig": {
    "Enabled": True, "Origins": [{"Id": "o", "DomainName": get_att("Backups", "RegionalDomainName"),
                                  "S3OriginConfig": {"OriginAccessIdentity": ""}}],
    "DefaultCacheBehavior": {"TargetOriginId": "o", "ViewerProtocolPolicy": "https-only",
                             "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6"}}})


def _lint(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    return subprocess.run([str(LINT), "--", str(path)], capture_output=True, text=True, env=env)


@pytest.mark.parametrize("name, write", [("t.yaml", as_yaml), ("t.json", as_json)])
def test_a_written_template_passes_for_its_regions(tmp_path, name, write):
    t = Template("backups", (BUCKET, ROLE, PROFILE), metadata=lint_metadata(("us-east-1", "us-gov-west-1")))
    done = _lint(tmp_path, name, write(t))
    assert done.returncode == 0, done.stdout + done.stderr


def test_a_type_its_region_lacks_fails_there(tmp_path):
    t = Template("edge", (BUCKET, CDN), metadata=lint_metadata(("us-gov-west-1",)))
    done = _lint(tmp_path, "gov.yaml", as_yaml(t))
    assert done.returncode != 0 and "E3006" in done.stdout          # CloudFront isn't in GovCloud
    assert _lint(tmp_path, "std.yaml", as_yaml(t._replace(metadata=lint_metadata(("us-east-1",))))).returncode == 0
