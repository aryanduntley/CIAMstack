"""Synthetic checks on AWS (core observability: domains/observability/canaries) as CloudWatch Synthetics canaries.
Pure.

Each canary the environment can run whose request the record describes (canary_specs) is an aws_synthetics_canary
named as its canary binding (lowercase letters, digits, - and _), running a Python script opsdir renders
(terraform/canaries/<name>/python/canary.py, zipped by the archive provider; handler canary.handler) on the runtime
the estate setting aws-canary-runtime names (syn-python-selenium-12.0 by default: GovCloud may lag, the setting says
which), at its interval (rate(n minutes)), its artifacts where its canary binding says (ciamStorageRef, an s3://
bucket and optional prefix: the location is the environment's, so other clouds' checks, which keep their own
results, need no such store), tagged Realizes and BindingRole so the inventory reads it back. The script
requests the URL: GET for health and login-page (any answer below 400 passes); for oidc-token a client-credentials
POST to the token endpoint with the client's id and secret read when it runs from the canary's credentials secret
(Secrets Manager, its JSON holding client_id and client_secret), passing when the answer holds an access_token. The
secret is never written anywhere opsdir renders.

One execution role for the environment's canaries (aws_iam_role ciam-<env>-canaries, trusted by Lambda) with the
permissions CloudWatch Synthetics documents for a canary without KMS or VPC access: its artifacts at each location, its
own log groups (/aws/lambda/cwsyn-<name>-*), s3:ListAllMyBuckets, xray:PutTraceSegments, cloudwatch:PutMetricData in
the CloudWatchSynthetics namespace; and secretsmanager:GetSecretValue on each credentials secret.

Not rendered, and said so: what canary_specs names; a service name that isn't internet-facing (a canary outside a VPC
can't reach it; one in a VPC isn't rendered yet); credentials that aren't a Secrets Manager secret; no artifact
location (no canary binding, or one without an s3:// ciamStorageRef). A canary someone else keeps, or an overlay
inherits from its base, is named with its keeper.
"""
import json
import re

from opsdir.core.contract import Setting
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import one_role
from opsdir.core.formats import PYTHON
from opsdir.core.manifest import header
from opsdir.core.settings import setting_value
from opsdir.domains.edge.exposure import service_exposure
from opsdir.domains.observability.canaries import canary_specs
from opsdir_format_terraform.hcl import Block, block, ref, tf_name
from .budgets import govcloud

CANARY = "aws_synthetics_canary"
SECRETS = "aws-sm://"
RUNTIME = Setting("aws-canary-runtime", "string", "syn-python-selenium-12.0",
                  "The CloudWatch Synthetics runtime the canaries opsdir renders run on (a Python Selenium runtime: "
                  "GovCloud may offer only older ones)")


def canary_name(name):
    """A canary name as CloudWatch Synthetics allows it (lowercase letters, digits, - and _)."""
    return re.sub(r"[^a-z0-9_-]", "-", name.lower())


def _partition(m):
    return "aws-us-gov" if govcloud(m) else "aws"


def _secret_arn(spec):
    uri = one(spec.secret, "ciamRefUri") if spec.secret is not None else None
    return uri[len(SECRETS):] if uri and uri.startswith(SECRETS) else None


GET_SCRIPT = '''import urllib.request

from aws_synthetics.common import synthetics_logger as logger

URL = {url!r}


def handler(event, context):
    """{flow} check: GET the URL; urllib raises on an answer of 400 or more, failing the canary."""
    with urllib.request.urlopen(urllib.request.Request(URL, method="GET"), timeout=10) as response:
        logger.info(f"{{URL}}: HTTP {{response.status}}")
'''

TOKEN_SCRIPT = '''import base64
import json
import urllib.parse
import urllib.request

import boto3
from aws_synthetics.common import synthetics_logger as logger

URL = {url!r}
# the client's credentials, read when the canary runs: {{"client_id", "client_secret"}}
SECRET_ID = {secret!r}


def handler(event, context):
    """oidc-token check: a client-credentials grant at the token endpoint must return an access token."""
    creds = json.loads(boto3.client("secretsmanager").get_secret_value(SecretId=SECRET_ID)["SecretString"])
    basic = base64.b64encode(f"{{creds['client_id']}}:{{creds['client_secret']}}".encode()).decode()
    request = urllib.request.Request(URL, data=urllib.parse.urlencode({{"grant_type": "client_credentials"}}).encode(),
                                     method="POST", headers={{"Authorization": f"Basic {{basic}}",
                                                              "Content-Type": "application/x-www-form-urlencoded"}})
    with urllib.request.urlopen(request, timeout=10) as response:
        if not json.loads(response.read()).get("access_token"):
            raise Exception(f"{{URL}}: no access_token in the answer")
        logger.info(f"{{URL}}: HTTP {{response.status}}, access token issued")
'''


def script(m, spec):
    """The canary's Python script, with its do-not-edit header."""
    body = (TOKEN_SCRIPT.format(url=spec.url, secret=_secret_arn(spec)) if spec.flow == "oidc-token"
            else GET_SCRIPT.format(url=spec.url, flow=spec.flow))
    return header(m, f"CloudWatch Synthetics canary {canary_name(spec.name)} ({spec.flow})", PYTHON) + body


def _schedule(every):
    minutes = max(1, every // 60)
    return f"rate({minutes} minute{'s' if minutes > 1 else ''})"


def artifact_location(spec):
    """(bucket, prefix) of where the canary keeps its artifacts (its binding's s3:// ciamStorageRef; the prefix ''
    or ending in /), else None."""
    uri = one(spec.binding, "ciamStorageRef") if spec.binding is not None else None
    if not (uri or "").startswith("s3://"):
        return None
    bucket, _, prefix = uri[len("s3://"):].partition("/")
    return (bucket, prefix.strip("/") + "/" if prefix.strip("/") else "") if bucket else None


def _why(m, spec):
    svc = one_role(m, one(spec.canary, "ciamCheckedService"))
    if spec.why:
        return spec.why
    if service_exposure(svc) != "internet":
        return (f"service name {rdn_value(svc)} isn't recorded as internet-facing: a canary outside a VPC can't reach "
                "it (canaries in a VPC aren't rendered yet)")
    if spec.flow == "oidc-token" and _secret_arn(spec) is None:
        return f"its credentials ({rdn_value(spec.secret)}) aren't a Secrets Manager secret (aws-sm://)"
    if spec.keeper is None and artifact_location(spec) is None:
        return ("no place for its artifacts: record its canary binding with an S3 location (ciamStorageRef "
                "s3://bucket/prefix)" if spec.binding is None else
                f"its canary binding {rdn_value(spec.binding)} records no S3 location for its artifacts "
                "(ciamStorageRef s3://bucket/prefix)")
    return None


def rendered(m, endpoints):
    """(CanarySpec, why not or None) of environment m's canaries, given the products' Endpoints."""
    return tuple((s, _why(m, s)) for s in canary_specs(m, endpoints))


def _canary(m, spec, why, runtime):
    cn = rdn_value(spec.canary)
    if why:
        return (f"# NOTE: canary {cn}: not rendered: {why}",)
    name = canary_name(spec.name)
    if spec.keeper is not None:
        return (f"# Canary {name} ({cn}): kept by {spec.keeper}, not rendered here",)
    zipped = f"canary_{tf_name(name)}"
    return (block("data", ["archive_file", zipped], [
                ("type", "zip"), ("source_dir", f"${{path.module}}/canaries/{name}"),
                ("output_path", f"${{path.module}}/.build/canary-{name}.zip")]),
            block("resource", [CANARY, tf_name(name)], [
                ("name", name), ("runtime_version", runtime), ("handler", "canary.handler"),
                ("zip_file", ref(f"data.archive_file.{zipped}.output_path")),
                ("artifact_s3_location", "s3://{}/{}".format(*artifact_location(spec))),
                ("execution_role_arn", ref("aws_iam_role.canaries.arn")), ("start_canary", True),
                ("schedule", Block((("expression", _schedule(spec.every)),))),
                ("tags", {"Realizes": cn, "BindingRole": one(spec.binding, "ciamBindingRole")
                          if spec.binding is not None else f"canary-{cn}"})]))


def _role(m, specs):
    names, part = [canary_name(s.name) for s in specs], _partition(m)
    places = sorted({artifact_location(s) for s in specs})
    secrets = sorted({_secret_arn(s) for s in specs if s.flow == "oidc-token"})
    statements = [
        {"Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": [f"arn:{part}:s3:::{bucket}/{prefix}*" for bucket, prefix in places]},
        {"Effect": "Allow", "Action": ["s3:GetBucketLocation"],
         "Resource": sorted({f"arn:{part}:s3:::{bucket}" for bucket, _ in places})},
        {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:CreateLogGroup"],
         "Resource": [f"arn:{part}:logs:*:*:log-group:/aws/lambda/cwsyn-{n}-*" for n in names]},
        {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets", "xray:PutTraceSegments"], "Resource": ["*"]},
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
         "Condition": {"StringEquals": {"cloudwatch:namespace": "CloudWatchSynthetics"}}},
        *(({"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secrets},) if secrets else ())]
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}
    return (block("resource", ["aws_iam_role", "canaries"], [
                ("name", f"ciam-{rdn_value(m.env)}-canaries"),
                ("assume_role_policy", json.dumps(trust, separators=(",", ":")))]),
            block("resource", ["aws_iam_role_policy", "canaries"], [
                ("name", "synthetics"), ("role", ref("aws_iam_role.canaries.id")),
                ("policy", json.dumps({"Version": "2012-10-17", "Statement": statements}, separators=(",", ":")))]))


def render_canaries(m, endpoints):
    """(HCL and comments, {path: script}) of environment m's canaries."""
    done = rendered(m, endpoints)
    live = tuple(s for s, why in done if why is None and s.keeper is None)
    runtime = setting_value(m.d, RUNTIME)
    hcl = (*(x for s, why in done for x in _canary(m, s, why, runtime)), *(_role(m, live) if live else ()))
    return hcl, {f"terraform/canaries/{canary_name(s.name)}/python/canary.py": script(m, s) for s in live}
