"""Synthetic checks on AWS (core observability: domains/observability/canaries) as CloudWatch Synthetics canaries.
Pure.

Each canary the environment can run whose request the record describes (canary_specs) is an aws_synthetics_canary
named as its canary binding (lowercase letters, digits, - and _), running a Python script opsdir renders
(terraform/canaries/<name>/python/canary.py, zipped by the archive provider; handler canary.handler) on the runtime
the estate setting aws-canary-runtime names (syn-python-selenium-12.0 by default: GovCloud may lag, the setting says
which), at its interval (rate(n minutes)), its artifacts where its canary binding says (ciamStorageRef, an s3://
bucket and optional prefix: the location is the environment's, so other clouds' checks, which keep their own
results, need no such store), tagged Realizes and BindingRole so the inventory reads it back. The script
makes its flow's request (observability.probes: a GET, a client-credentials token request, an LDAPS simple bind) with
the credentials it reads when it runs from the canary's credentials secret (Secrets Manager, its JSON holding client_id
and client_secret, or bind_dn and password; an LDAP bind without credentials is anonymous). The secret is never
written anywhere opsdir renders. A check of a service name whose certificate a private CA issued trusts the CA
certificates the record holds for it (canary_specs' trust: their PEMs, public material, written into the script and
added to the runtime's trust store; CA_PARTIAL when an intermediate CA is the anchor); a CA rotation is a record change
and a re-render.

A canary of an internal service name runs in the VPC (vpc_config): in the subnets canary_specs gives (its binding's
ciamSubnetRole, else those the firewall rules admit to the service), with the environment's canaries' security group
(aws_security_group canaries: out to each checked service on its port, at its frontend address or else the network's
ranges, and out on 443 to the AWS APIs it calls: S3, CloudWatch, CloudWatch Logs, Secrets Manager, through NAT or the
VPC endpoints com.amazonaws.<region>.monitoring, logs and secretsmanager and an S3 gateway endpoint, as AWS
documents).

One execution role for the environment's canaries (aws_iam_role ciam-<env>-canaries, trusted by Lambda) with the
permissions CloudWatch Synthetics documents: its artifacts at each location, its own log groups
(/aws/lambda/cwsyn-<name>-*), s3:ListAllMyBuckets, xray:PutTraceSegments, cloudwatch:PutMetricData in the
CloudWatchSynthetics namespace; ec2:CreateNetworkInterface, DescribeNetworkInterfaces and DeleteNetworkInterface when a
canary runs in the VPC; and secretsmanager:GetSecretValue on each credentials secret.

Not rendered, and said so: what canary_specs names; a service name whose exposure isn't recorded; an internal one
with no subnet to run from; credentials that aren't a Secrets Manager secret; no artifact location (no canary binding,
or one without an s3:// ciamStorageRef). A canary someone else keeps, or an overlay inherits from its base, is named
with its keeper. What isn't rendered is a render note (canary_notes: why and how to handle it; flow 43), written as
its comment.
"""
import json
import re
from urllib.parse import urlsplit

from opsdir.core.contract import Setting
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import one_role
from opsdir.core.formats import PYTHON
from opsdir.core.manifest import header
from opsdir.core.settings import setting_value
from opsdir.core.notes import note_comment
from opsdir.domains.observability.canaries import (RECORD, Reason, canary_specs, no_subnet, unknown_exposure,
                                                   unrendered_note)
from opsdir.domains.observability.probes import PYTHON_PROBES
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import partition

CANARY = "aws_synthetics_canary"
SECRETS = "aws-sm://"
RUNTIME = Setting("aws-canary-runtime", "string", "syn-python-selenium-12.0",
                  "The CloudWatch Synthetics runtime the canaries opsdir renders run on (a Python Selenium runtime: "
                  "GovCloud may offer only older ones)")


def canary_name(name):
    """A canary name as CloudWatch Synthetics allows it (lowercase letters, digits, - and _)."""
    return re.sub(r"[^a-z0-9_-]", "-", name.lower())


def _secret_arn(spec):
    uri = one(spec.secret, "ciamRefUri") if spec.secret is not None else None
    return uri[len(SECRETS):] if uri and uri.startswith(SECRETS) else None


# The canary's handler, after the probes (observability.probes): the credentials read from Secrets Manager when it
# runs (oidc-token: {"client_id", "client_secret"}; ldap-bind: {"bind_dn", "password"}; none: an anonymous bind), and
# the CA certificates it trusts besides the runtime's (PEM, public; None: the runtime's alone)
HANDLER = '''
import boto3
from aws_synthetics.common import synthetics_logger as logger

FLOW = {flow!r}
URL = {url!r}
SECRET_ID = {secret!r}
CA = {ca!r}
CA_PARTIAL = {partial!r}


def handler(event, context):
    """{flow} check of URL: the probe raises when it fails, failing the canary."""
    creds = (json.loads(boto3.client("secretsmanager").get_secret_value(SecretId=SECRET_ID)["SecretString"])
             if SECRET_ID else None)
    logger.info(f"{{URL}}: {{probe(FLOW, URL, creds, CA, CA_PARTIAL)}}")
'''


def script(m, spec):
    """The canary's Python script, with its do-not-edit header."""
    trust = spec.trust
    return (header(m, f"CloudWatch Synthetics canary {canary_name(spec.name)} ({spec.flow})", PYTHON) + PYTHON_PROBES
            + HANDLER.format(flow=spec.flow, url=spec.url, secret=_secret_arn(spec),
                             ca=trust.pem if trust is not None else None,
                             partial=trust.partial if trust is not None else False))


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


def _reason(m, spec):
    """Why a canary isn't rendered (a Reason with how to handle it; the spec's own first), else None."""
    if spec.why:
        return Reason(spec.why, spec.how)
    if spec.exposure is None:
        return unknown_exposure(m, spec)
    if spec.exposure == "internal" and not spec.subnets:
        return no_subnet(m, spec)
    if spec.secret is not None and _secret_arn(spec) is None:
        return Reason(f"its credentials ({rdn_value(spec.secret)}) aren't a Secrets Manager secret (aws-sm://)",
                      (f"Keep the check's credentials in a Secrets Manager secret and point {rdn_value(spec.secret)} "
                       f"at it (ciamRefUri aws-sm://...), {RECORD}",))
    if spec.keeper is None and artifact_location(spec) is None:
        where = "its canary binding" if spec.binding is None else rdn_value(spec.binding)
        return Reason("no place for its artifacts: it has no canary binding" if spec.binding is None else
                      f"its canary binding {rdn_value(spec.binding)} records no S3 location for its artifacts "
                      "(ciamStorageRef s3://bucket/prefix)",
                      (f"Record {where} with the S3 location its artifacts go to (ciamStorageRef s3://bucket/prefix), "
                       f"{RECORD}",))
    return None


def rendered(m, endpoints):
    """(CanarySpec, Reason it isn't rendered or None) of environment m's canaries, given the products' Endpoints."""
    return tuple((s, _reason(m, s)) for s in canary_specs(m, endpoints))


def canary_notes(m, endpoints):
    """The render notes of environment m's canaries it doesn't render (render_canaries writes their comments)."""
    return tuple(unrendered_note(m, s, reason) for s, reason in rendered(m, endpoints) if reason)


def _canary(m, spec, reason, runtime):
    cn = rdn_value(spec.canary)
    if reason:
        return (comment(note_comment(unrendered_note(m, spec, reason))),)
    name = canary_name(spec.name)
    if spec.keeper is not None:
        return (comment(f"Canary {name} ({cn}): kept by {spec.keeper}, not rendered here"),)
    zipped = f"canary_{tf_name(name)}"
    return (tf_block("data", ["archive_file", zipped], [
                ("type", "zip"), ("source_dir", f"${{path.module}}/canaries/{name}"),
                ("output_path", f"${{path.module}}/.build/canary-{name}.zip")]),
            tf_block("resource", [CANARY, tf_name(name)], [
                ("name", name), ("runtime_version", runtime), ("handler", "canary.handler"),
                ("zip_file", ref(f"data.archive_file.{zipped}.output_path")),
                ("artifact_s3_location", "s3://{}/{}".format(*artifact_location(spec))),
                ("execution_role_arn", ref("aws_iam_role.canaries.arn")), ("start_canary", True),
                ("schedule", Block((("expression", _schedule(spec.every)),))),
                *((("vpc_config", Block((
                    ("subnet_ids", [ref(f"data.aws_subnet.{tf_name(rdn_value(s))}.id") for s in spec.subnets]),
                    ("security_group_ids", [ref("aws_security_group.canaries.id")])))),)
                  if spec.exposure == "internal" else ()),
                ("tags", {"Realizes": cn, "BindingRole": one(spec.binding, "ciamBindingRole")
                          if spec.binding is not None else f"canary-{cn}"})]))


def _destinations(m, specs):
    """((cidr, port), ...) the canaries in the VPC request: each checked service's frontend address, else the
    network's ranges, on its port."""
    def where(s):
        svc, url = one_role(m, one(s.canary, "ciamCheckedService")), urlsplit(s.url)
        net = one_role(m, "network")
        ip = one(svc, "ciamFrontendIp")
        return tuple((c, url.port or 443) for c in ((f"{ip}/32",) if ip else values(net, "ciamCidr") if net else ()))
    return tuple(dict.fromkeys(d for s in specs for d in where(s)))


def _security_group(m, specs):
    """The canaries' security group in the VPC: out to the services they check, and to the AWS APIs on 443."""
    rules = (*((c, p, "checked services") for c, p in _destinations(m, specs)), ("0.0.0.0/0", 443, "AWS APIs"))
    return (tf_block("resource", ["aws_security_group", "canaries"], [
                ("name", f"ciam-{rdn_value(m.env)}-canaries"),
                ("description", f"CIAM synthetic checks in the VPC ({m.label})"),
                ("vpc_id", ref("data.aws_vpc.main.id")), ("tags", {"ManagedBy": "opsdir"})]),
            *(tf_block("resource", ["aws_vpc_security_group_egress_rule", tf_name(f"canaries_{i}_{port}")], [
                ("security_group_id", ref("aws_security_group.canaries.id")), ("cidr_ipv4", cidr),
                ("from_port", port), ("to_port", port), ("ip_protocol", "tcp"), ("description", what)])
              for i, (cidr, port, what) in enumerate(rules)))


def _role(m, specs):
    names, part = [canary_name(s.name) for s in specs], partition(m)
    places = sorted({artifact_location(s) for s in specs})
    secrets = sorted({_secret_arn(s) for s in specs if s.secret is not None})
    inside = any(s.exposure == "internal" for s in specs)
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
        *(({"Effect": "Allow", "Action": ["ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces",
                                          "ec2:DeleteNetworkInterface"], "Resource": ["*"]},) if inside else ()),
        *(({"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secrets},) if secrets else ())]
    trust = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}
    return (tf_block("resource", ["aws_iam_role", "canaries"], [
                ("name", f"ciam-{rdn_value(m.env)}-canaries"),
                ("assume_role_policy", json.dumps(trust, separators=(",", ":")))]),
            tf_block("resource", ["aws_iam_role_policy", "canaries"], [
                ("name", "synthetics"), ("role", ref("aws_iam_role.canaries.id")),
                ("policy", json.dumps({"Version": "2012-10-17", "Statement": statements}, separators=(",", ":")))]))


def render_canaries(m, endpoints):
    """(HCL and comments, {path: script}) of environment m's canaries."""
    done = rendered(m, endpoints)
    live = tuple(s for s, why in done if why is None and s.keeper is None)
    inside = tuple(s for s in live if s.exposure == "internal")
    runtime = setting_value(m.d, RUNTIME)
    hcl = (*(x for s, why in done for x in (from_entry(s.binding.dn, _canary(m, s, why, runtime))
                                             if s.binding is not None else _canary(m, s, why, runtime))),
           *(_role(m, live) if live else ()),
           *(_security_group(m, inside) if inside else ()))
    return hcl, {f"terraform/canaries/{canary_name(s.name)}/python/canary.py": script(m, s) for s in live}
