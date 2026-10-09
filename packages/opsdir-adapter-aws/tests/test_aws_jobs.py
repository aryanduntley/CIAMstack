"""AWS jobs: Lambda functions, CodePipeline pipelines and CodeBuild projects read as job bindings, each with the
schedules the EventBridge rules and Scheduler schedules that target it run it on, from Terraform state, the CLI's
outputs and CloudFormation alike; a function a tag gives a role is placed as the environment's ciamJobBinding."""
import json

from opsdir.core.directory import one, values
from opsdir.core.interchange.ldif import parse
from opsdir.core.inventory import environment_groups
from opsdir_adapter_aws.cli import cli_resources
from opsdir_adapter_aws.cloudformation import cloudformation_resources
from opsdir_adapter_aws.inventory import state_resources
import mini_estate
from support import REGISTRY, build_directory

ACCT, REGION = "111122223333", "us-east-1"
FN = f"arn:aws:lambda:{REGION}:{ACCT}:function:cert-check"
PIPE = f"arn:aws:codepipeline:{REGION}:{ACCT}:ciam-infra"
BUILD = f"arn:aws:codebuild:{REGION}:{ACCT}:project/ciam-nightly"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


STATE = _state(
    ("aws_lambda_function", "cert_check", {"arn": FN, "function_name": "cert-check", "runtime": "python3.12",
                                           "tags": {"Role": "cert-check-function"},
                                           "environment": [{"variables": {"TOKEN": "not-read"}}]}),
    ("aws_cloudwatch_event_rule", "daily", {"name": "daily", "arn": "arn:x", "schedule_expression": "rate(1 day)"}),
    ("aws_cloudwatch_event_target", "daily_fn", {"rule": "daily", "arn": f"{FN}:live"}),
    ("aws_scheduler_schedule", "nightly", {"name": "nightly", "schedule_expression": "cron(0 2 * * ? *)",
                                           "target": [{"arn": BUILD}]}),
    ("aws_codepipeline", "infra", {"arn": PIPE, "name": "ciam-infra", "tags": {"Role": "infra-pipeline"}}),
    ("aws_codebuild_project", "nightly", {"arn": BUILD, "name": "ciam-nightly",
                                          "environment": [{"image": "aws/codebuild/standard:7.0"}]}))


def _jobs(resources):
    return {r.name: r for r in resources if r.kind == "job"}


def test_terraform_state():
    resources, _ = state_resources(STATE)
    jobs = _jobs(resources)
    assert (jobs["cert-check"].ref, jobs["cert-check"].role, jobs["cert-check"].attrs) == \
        (FN, "cert-check-function", {"ciamRuntime": ("python3.12",), "ciamSchedule": ("rate(1 day)",)})
    assert jobs["ciam-nightly"].attrs == {"ciamRuntime": ("aws/codebuild/standard:7.0",),
                                          "ciamSchedule": ("cron(0 2 * * ? *)",)}
    assert (jobs["ciam-infra"].ref, jobs["ciam-infra"].role) == (PIPE, "infra-pipeline")
    assert "not-read" not in repr(resources)


def test_cli_outputs():
    texts = {"functions.json": json.dumps({"Functions": [{"FunctionName": "cert-check", "FunctionArn": FN,
                                                          "Runtime": "python3.12"}]}),
             "lambda-tags/cert-check.json": json.dumps({"Tags": {"Role": "cert-check-function"}}),
             "rules.json": json.dumps({"Rules": [{"Name": "daily", "Arn": "arn:x", "State": "ENABLED",
                                                  "ScheduleExpression": "rate(1 day)"},
                                                 {"Name": "off", "State": "DISABLED",
                                                  "ScheduleExpression": "rate(1 hour)"}]}),
             "event-targets/daily.json": json.dumps({"Targets": [{"Id": "1", "Arn": FN}]}),
             "schedule-nightly.json": json.dumps({"Name": "nightly", "Arn": "arn:s", "State": "ENABLED",
                                                  "ScheduleExpression": "cron(0 2 * * ? *)", "Target": {"Arn": BUILD}}),
             "pipeline-infra.json": json.dumps({"pipeline": {"name": "ciam-infra"}, "metadata": {"pipelineArn": PIPE}}),
             "projects.json": json.dumps({"projects": [{"name": "ciam-nightly", "arn": BUILD,
                                                        "environment": {"image": "aws/codebuild/standard:7.0"},
                                                        "tags": [{"key": "Role", "value": "nightly-build"}]}]})}
    resources, notices = cli_resources(texts)
    jobs = _jobs(resources)
    assert (jobs["cert-check"].role, jobs["cert-check"].attrs["ciamSchedule"]) == ("cert-check-function",
                                                                                   ("rate(1 day)",))
    assert (jobs["ciam-nightly"].role, jobs["ciam-nightly"].attrs["ciamSchedule"]) == ("nightly-build",
                                                                                       ("cron(0 2 * * ? *)",))
    assert jobs["ciam-infra"].ref == PIPE
    assert "events/scheduler: 1 disabled rule(s) or schedule(s) not read" in notices


def test_cloudformation():
    template = {"Resources": {
        "CertCheck": {"Type": "AWS::Lambda::Function", "Properties": {
            "Runtime": "python3.12", "Tags": [{"Key": "Role", "Value": "cert-check-function"}]}},
        "Daily": {"Type": "AWS::Events::Rule", "Properties": {
            "ScheduleExpression": "rate(1 day)",
            "Targets": [{"Id": "1", "Arn": {"Fn::GetAtt": ["CertCheck", "Arn"]}}]}},
        "Build": {"Type": "AWS::CodeBuild::Project",
                  "Properties": {"Environment": {"Image": "aws/codebuild/standard:7.0"}}}}}
    stack = {"Stacks": [{"StackName": "ciam-jobs",
                         "StackId": f"arn:aws:cloudformation:{REGION}:{ACCT}:stack/ciam-jobs/1"}]}
    listed = {"StackResourceSummaries": [
        {"LogicalResourceId": "CertCheck", "PhysicalResourceId": "cert-check", "ResourceStatus": "CREATE_COMPLETE"},
        {"LogicalResourceId": "Daily", "PhysicalResourceId": "daily", "ResourceStatus": "CREATE_COMPLETE"},
        {"LogicalResourceId": "Build", "PhysicalResourceId": "ciam-nightly", "ResourceStatus": "CREATE_COMPLETE"}]}
    resources, _ = cloudformation_resources({"ciam-jobs/template.json": json.dumps(template),
                                             "ciam-jobs/stack.json": json.dumps(stack),
                                             "ciam-jobs/resources.json": json.dumps(listed)})
    jobs = _jobs(resources)
    assert (jobs["cert-check"].ref, jobs["cert-check"].role, jobs["cert-check"].attrs["ciamSchedule"]) == \
        (FN, "cert-check-function", ("rate(1 day)",))
    assert jobs["ciam-nightly"].ref == BUILD


def test_a_tagged_function_is_placed_as_a_job_binding():
    d = build_directory(REGISTRY, tuple(parse(mini_estate.LDIF)))
    resources, _ = state_resources(STATE)
    groups, notices = environment_groups(d, "alpha/prod", resources)
    placed = {e.dn: e for _, es in groups for e in es}
    fn = placed["cn=cert-check,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops"]
    assert (fn.classes, one(fn, "ciamBindingRole"), one(fn, "ciamProviderRef"), values(fn, "ciamSchedule")) == \
        (("top", "ciamJobBinding"), "cert-check-function", FN, ("rate(1 day)",))
    assert any("ciam-nightly" in n and "names no role" in n for n in notices)
