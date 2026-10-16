"""AWS collectors (`opsdir collect`, core.contract Collector): the exact AWS CLI calls whose outputs aws/cli-inventory
reads, and the Terraform state aws/terraform-state reads, for one environment, read-only. Pure: the core runs them.

Every call is `aws <service> <operation> ... --output json --region <the cloud's region>`, under the operator's own
login, with AWS_USE_FIPS_ENDPOINT=true when the cloud records FIPS endpoints. First `aws sts get-caller-identity`
must print the account the cloud records (ciamAccountRef); else nothing is read. The inventory is collected in
rounds as the README's script does it by hand: the listings first (network resources filtered to the environment's
VPC, the network binding's provider ref), then each listed item's details (listeners, tags, health, records, key
policies, schedules, ...), then theirs (a backup plan's selections). Per-bucket settings and policies are read for the
buckets the environment records only, resource policies for the secrets it references only. Lists only the
collector reads are kept out of the export (_work/).

Outputs that can carry secret material are projected to the fields the reader uses (--query), so the values are never
fetched: Lambda functions (environment variables), CodeBuild projects (environment variables), Scheduler schedules and
EventBridge targets (their input), CodePipeline pipelines (action configuration), CloudFront distributions (origin
custom headers). Messaging is projected to what the reader uses too: a queue's ARN and tags, an SES identity's type,
DKIM status and tags (not its sending authorization policies), a Cognito user pool's id, name, ARN, tags and custom
domain (describe-user-pool; no app client or identity provider is described: they carry secrets), and a managed
directory's ID, type, domain, NetBIOS name, edition, VPC and regions (describe-directories: its RADIUS settings carry a
shared secret), then each Microsoft AD directory's tags. Nothing reads
secret values (no get-secret-value, no SSM
parameters, no user data). Calls that answer "nothing there" for a resource without that setting (a bucket without a
policy, Shield without a subscription, a key without rotation support) leave their file out.

Security services: GuardDuty's detectors (each one's get-detector saved by its id), Inspector's account status, AWS
Config's recorders, delivery channels and retention, Security Hub's hub and enabled standards, and each service's
organization configuration, which only its delegated administrator's account answers: elsewhere the generic error its
API reference documents for the call (NOT_ADMIN) leaves the file out, as does a Security Hub not enabled, and the
importer reads the service as the account's own and says so.

Organization control policies (service and resource control policies) can be listed only from the organization's
management account or a delegated administrator, a login other than the environment's: a collection source for
aws/cli-inventory names an AWS CLI profile for it (ciamSourceRef aws-profile://<profile>, from the operator's own AWS
configuration: SSO or a role chain; opsdir never sees its credentials), and only the Organizations calls run with
--profile. First that profile's identity and organization: its Organization.Id must be the cloud's
ciamOrganizationRef, or the collection stops there. Then the account's parents up to the root, the policies of both
types attached to the account and to each parent (inherited ones apply too), and each policy once (org/<id>.json).
Without such a source the policies aren't collected, and the guardrails the record holds are kept (an import only notes
them).

CloudFormation: the stacks the environment's collection sources name (importer aws/cloudformation, ciamSourceRef
cfn://<stack name>, or the stack's ARN, in the cloud's account), each into its own folder as the README's script saves
it: describe-stacks projected to what the importer reads (Outputs, which may carry values, are never fetched),
list-stack-resources, and get-template of the processed template (transforms expanded); then each nested stack
(an AWS::CloudFormation::Stack resource that was created) the same way, in its own folder. A stack in another account
is a problem, never read.

Terraform state: (a) by default the state object a collection source names (ciamCollectionSource, importer
aws/terraform-state, ciamSourceRef s3://bucket/key, the workspace prefix included) read with `aws s3 cp URI -`: no
init, no lock, read access to one object; (b) with --terraform-dir, `terraform state pull` in that initialized
working directory (the backend as configured there)."""
import json
import re

from opsdir.core.contract import Collector, Command
from opsdir.core.directory import one, values
from opsdir.core.environment import of_class, one_role
from opsdir.core.sources import env_relative
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.governance.collection import collection_sources
from opsdir_format_terraform.state import TERRAFORM_DIR, state_steps as terraform_state_steps
from .account import account_id, govcloud, partition, standard_account
from .cli_budgets import budget_folder
from .cli_cognito import POOL_QUERY
from .cli_directory import DIRECTORY_QUERY, TAGS_FOLDER
from .cli_compute import launch_template_ref
from .cli_monitor import tags_path
from .cli_outputs import file_name
from .cloudformation import NOT_CREATED
from .storage import bucket_of

WORK = "_work/"
PROJECTIONS = {
    "functions": "{Functions: Functions[].{FunctionArn: FunctionArn, FunctionName: FunctionName, Runtime: Runtime}}",
    "projects": "{projects: projects[].{arn: arn, name: name, environment: {image: environment.image}, tags: tags}}",
    "schedule": "{Name: Name, Arn: Arn, GroupName: GroupName, State: State, ScheduleExpression: ScheduleExpression, "
                "Target: {Arn: Target.Arn}}",
    "targets": "{Targets: Targets[].{Id: Id, Arn: Arn}}",
    "pipeline": "{pipeline: {name: pipeline.name}, metadata: {pipelineArn: metadata.pipelineArn}}",
    "distributions": "{DistributionList: {Items: DistributionList.Items[].{ARN: ARN, Id: Id, DomainName: DomainName, "
                     "Comment: Comment, WebACLId: WebACLId, Origins: {Items: Origins.Items[].{DomainName: DomainName, "
                     "Id: Id}}, ViewerCertificate: {MinimumProtocolVersion: "
                     "ViewerCertificate.MinimumProtocolVersion}}}}",
    "stack": "{Stacks: Stacks[].{StackId: StackId, StackName: StackName, StackStatus: StackStatus, "
             "Parameters: Parameters}}",
    "launch-template-versions": "{LaunchTemplateVersions: LaunchTemplateVersions[].{LaunchTemplateId: "
                                "LaunchTemplateId, LaunchTemplateName: LaunchTemplateName, VersionNumber: "
                                "VersionNumber, DefaultVersion: DefaultVersion, LaunchTemplateData: {ImageId: "
                                "LaunchTemplateData.ImageId, InstanceType: LaunchTemplateData.InstanceType, "
                                "MetadataOptions: {HttpTokens: LaunchTemplateData.MetadataOptions.HttpTokens}, "
                                "BlockDeviceMappings: LaunchTemplateData.BlockDeviceMappings, TagSpecifications: "
                                "LaunchTemplateData.TagSpecifications}}}",
    "subscribers": "{Subscribers: Subscribers[?SubscriptionType=='SNS'].{SubscriptionType: SubscriptionType, "
                   "Address: Address}}",
    "canaries": "{Canaries: Canaries[].{Name: Name, Schedule: Schedule, Tags: Tags, EngineArn: EngineArn, "
                "ArtifactS3Location: ArtifactS3Location, ExecutionRoleArn: ExecutionRoleArn, "
                "RuntimeVersion: RuntimeVersion}}",
    "queue-arn": "{QueueArn: Attributes.QueueArn}",
    "queue-tags": "{Tags: Tags}",                     # always a Tags key, also for a queue without tags
    "email-identity": "{IdentityType: IdentityType, DkimAttributes: {Status: DkimAttributes.Status}, Tags: Tags}",
}
# What a service's organization configuration (and a Security Hub not enabled) answers in an account that isn't its
# delegated administrator: the error codes the API references document for these operations, generic ones (research:
# no more specific code is documented). The file is left out; the reader then names the service as the account's own.
NOTIFICATION_KEYS = ("NotificationType", "ComparisonOperator", "Threshold", "ThresholdType")
NOT_ADMIN = {"guardduty": ("BadRequestException",), "inspector2": ("AccessDeniedException",),
             "securityhub": ("InvalidAccessException",)}
STACK_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")
STACK_ARN = re.compile(r"^arn:aws[a-z-]*:cloudformation:([a-z0-9-]+):(\d{12}):stack/([A-Za-z][A-Za-z0-9-]{0,127})/"
                       r"[A-Za-z0-9-]+$")
NESTED = "AWS::CloudFormation::Stack"
PROFILE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
ORGANIZATION = re.compile(r"\bo-[a-z0-9]{10,32}\b")
TARGET = re.compile(r"^(\d{12}|ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|r-[0-9a-z]{4,32})$")
POLICY = re.compile(r"^p-[0-9A-Za-z_]{1,128}$")
POLICY_TYPES = ("SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY", "S3_POLICY")
BUCKET_SETTINGS = (("bucket-versioning", "get-bucket-versioning", ()),
                   ("bucket-object-lock", "get-object-lock-configuration", ("ObjectLockConfigurationNotFoundError",)),
                   ("bucket-encryption", "get-bucket-encryption", ("ServerSideEncryptionConfigurationNotFoundError",)),
                   ("bucket-public-access", "get-public-access-block", ("NoSuchPublicAccessBlockConfiguration",)),
                   ("bucket-lifecycle", "get-bucket-lifecycle-configuration", ("NoSuchLifecycleConfiguration",)),
                   ("bucket-replication", "get-bucket-replication", ("ReplicationConfigurationNotFoundError",)),
                   ("bucket-policy", "get-bucket-policy", ("NoSuchBucketPolicy",)))


def _aws(m, *args, query=None, absent=(), region=None, fips=True):
    """An AWS CLI call for environment m: JSON output, the cloud's region (or the one given: a stack ARN's), FIPS
    endpoints when it records them (fips False: a service AWS lists no FIPS endpoint for)."""
    region = region or one(m.cloud, "ciamRegion")
    return Command(("aws", *args, *(("--query", query) if query else ()), "--output", "json",
                    *(("--region", region) if region else ())),
                   env=(("AWS_USE_FIPS_ENDPOINT", "true"),) if fips and fips_endpoints(m) else (),
                   absent=tuple(absent))


def _doc(done, path):
    try:
        found = json.loads(done.get(path) or "{}")
    except ValueError:
        return {}
    return found if isinstance(found, dict) else {}


def _items(done, path, key, *fields):
    """Tuples of fields of each item a listing at path holds under key."""
    return tuple(tuple(i.get(f) for f in fields) for i in _doc(done, path).get(key) or () if isinstance(i, dict))


def _last(arn):
    return (arn or "").rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def _target_group_name(arn):
    found = re.search(r"targetgroup/([^/]+)/", arn or "")
    return found.group(1) if found else _last(arn)


def recorded_buckets(m):
    """The S3 buckets environment m's object stores name."""
    return tuple(dict.fromkeys(b for s in of_class(m, "ciamObjectStore")
                               for b in (bucket_of(one(s, "ciamStorageRef")),) if b))


def recorded_secrets(m):
    """The Secrets Manager secrets environment m's bindings reference (aws-sm://<name or ARN>)."""
    return tuple(dict.fromkeys(v[len("aws-sm://"):] for b in m.bindings for v in values(b, "ciamRefUri")
                               if v.startswith("aws-sm://")))


def _listings(m, vpc):
    """(path, call) of the first round: everything that needs no earlier output."""
    in_vpc = ("--filters", f"Name=vpc-id,Values={vpc}")
    return (
        ("vpcs.json", _aws(m, "ec2", "describe-vpcs", "--vpc-ids", vpc)),
        ("subnets.json", _aws(m, "ec2", "describe-subnets", *in_vpc)),
        ("instances.json", _aws(m, "ec2", "describe-instances", *in_vpc)),
        ("security-groups.json", _aws(m, "ec2", "describe-security-groups", *in_vpc)),
        ("security-group-rules.json", _aws(m, "ec2", "describe-security-group-rules")),
        ("nat-gateways.json", _aws(m, "ec2", "describe-nat-gateways", "--filter", f"Name=vpc-id,Values={vpc}")),
        ("load-balancers.json", _aws(m, "elbv2", "describe-load-balancers")),
        ("target-groups.json", _aws(m, "elbv2", "describe-target-groups")),
        ("secrets.json", _aws(m, "secretsmanager", "list-secrets")),
        (f"{WORK}kms-keys.json", _aws(m, "kms", "list-keys")),
        ("buckets.json", _aws(m, "s3api", "list-buckets")),
        ("functions.json", _aws(m, "lambda", "list-functions", query=PROJECTIONS["functions"])),
        ("rules.json", _aws(m, "events", "list-rules")),
        (f"{WORK}schedules.json", _aws(m, "scheduler", "list-schedules")),
        (f"{WORK}pipelines.json", _aws(m, "codepipeline", "list-pipelines")),
        (f"{WORK}build-projects.json", _aws(m, "codebuild", "list-projects")),
        (f"{WORK}web-acls.json", _aws(m, "wafv2", "list-web-acls", "--scope", "REGIONAL")),
        (f"{WORK}ip-sets.json", _aws(m, "wafv2", "list-ip-sets", "--scope", "REGIONAL")),
        ("protections.json", _aws(m, "shield", "list-protections", absent=("ResourceNotFoundException",))),
        ("distributions.json", _aws(m, "cloudfront", "list-distributions", query=PROJECTIONS["distributions"])),
        ("hosted-zones.json", _aws(m, "route53", "list-hosted-zones")),
        ("resolver-rules.json", _aws(m, "route53resolver", "list-resolver-rules")),
        ("route-tables.json", _aws(m, "ec2", "describe-route-tables", *in_vpc)),
        ("network-acls.json", _aws(m, "ec2", "describe-network-acls", *in_vpc)),
        ("vpc-endpoints.json", _aws(m, "ec2", "describe-vpc-endpoints", *in_vpc)),
        ("endpoint-services.json", _aws(m, "ec2", "describe-vpc-endpoint-service-configurations")),
        ("peering.json", _aws(m, "ec2", "describe-vpc-peering-connections")),
        ("tgw-attachments.json", _aws(m, "ec2", "describe-transit-gateway-vpc-attachments", *in_vpc)),
        ("vpn-connections.json", _aws(m, "ec2", "describe-vpn-connections")),
        ("customer-gateways.json", _aws(m, "ec2", "describe-customer-gateways")),
        ("vpn-gateways.json", _aws(m, "ec2", "describe-vpn-gateways")),
        ("flow-logs.json", _aws(m, "ec2", "describe-flow-logs")),
        (f"{WORK}rule-groups.json", _aws(m, "network-firewall", "list-rule-groups", "--scope", "ACCOUNT")),
        (f"{WORK}firewall-policies.json", _aws(m, "network-firewall", "list-firewall-policies")),
        (f"{WORK}firewalls.json", _aws(m, "network-firewall", "list-firewalls")),
        (f"{WORK}user-pools.json", _aws(m, "cognito-idp", "list-user-pools", "--max-results", "60")),
        ("directories.json", _aws(m, "ds", "describe-directories", query=DIRECTORY_QUERY)),
        ("rds-instances.json", _aws(m, "rds", "describe-db-instances")),
        ("rds-clusters.json", _aws(m, "rds", "describe-db-clusters")),
        ("rds-subnet-groups.json", _aws(m, "rds", "describe-db-subnet-groups")),
        (f"{WORK}db-parameter-groups.json", _aws(m, "rds", "describe-db-parameter-groups")),
        (f"{WORK}db-cluster-parameter-groups.json", _aws(m, "rds", "describe-db-cluster-parameter-groups")),
        ("volumes.json", _aws(m, "ec2", "describe-volumes")),
        (f"{WORK}dlm-policies.json", _aws(m, "dlm", "get-lifecycle-policies")),
        ("backup-vaults.json", _aws(m, "backup", "list-backup-vaults")),
        (f"{WORK}backup-plans.json", _aws(m, "backup", "list-backup-plans")),
        ("trails.json", _aws(m, "cloudtrail", "describe-trails")),
        ("autoscaling-groups.json", _aws(m, "autoscaling", "describe-auto-scaling-groups")),
        (f"{WORK}eks-clusters.json", _aws(m, "eks", "list-clusters")),
        ("alarms.json", _aws(m, "cloudwatch", "describe-alarms")),
        ("log-groups.json", _aws(m, "logs", "describe-log-groups")),
        ("canaries.json", _aws(m, "synthetics", "describe-canaries", query=PROJECTIONS["canaries"])),
        ("topics.json", _aws(m, "sns", "list-topics")),
        (f"{WORK}queues.json", _aws(m, "sqs", "list-queues")),
        ("event-buses.json", _aws(m, "events", "list-event-buses")),
        ("streams.json", _aws(m, "kinesis", "list-streams")),
        (f"{WORK}email-identities.json", _aws(m, "sesv2", "list-email-identities")),
        ("instance-connect-endpoints.json", _aws(m, "ec2", "describe-instance-connect-endpoints", *in_vpc)),
        (f"{WORK}guardduty-detectors.json", _aws(m, "guardduty", "list-detectors")),
        ("inspector2.json", _aws(m, "inspector2", "batch-get-account-status")),
        ("config-recorders.json", _aws(m, "configservice", "describe-configuration-recorders")),
        ("config-channels.json", _aws(m, "configservice", "describe-delivery-channels")),
        ("config-retention.json", _aws(m, "configservice", "describe-retention-configurations")),
        ("securityhub-hub.json", _aws(m, "securityhub", "describe-hub", absent=NOT_ADMIN["securityhub"])),
        ("securityhub-standards.json", _aws(m, "securityhub", "get-enabled-standards",
                                            absent=NOT_ADMIN["securityhub"])),
        *((f"organization-configuration/{service}.json",
           _aws(m, service, "describe-organization-configuration", absent=NOT_ADMIN[service]))
          for service in ("inspector2", "securityhub")),
        ("iam.json", _aws(m, "iam", "get-account-authorization-details")),
        (f"{WORK}sso-instances.json", _aws(m, "sso-admin", "list-instances")),
        *((f"bucket-policy/{b}.json" if folder == "bucket-policy" else f"{folder}/{b}.json",
           _aws(m, "s3api", op, "--bucket", b, absent=absent))
          for b in recorded_buckets(m) for folder, op, absent in BUCKET_SETTINGS),
        *((f"secret-policy-{_last(s)}.json", _aws(m, "secretsmanager", "get-resource-policy", "--secret-id", s))
          for s in recorded_secrets(m)))


def _details(m, done):
    """(path, call) of what the listings collected so far name (each round asks only for what is new)."""
    lbs, tgs = _items(done, "load-balancers.json", "LoadBalancers", "LoadBalancerArn", "LoadBalancerName"), \
        _items(done, "target-groups.json", "TargetGroups", "TargetGroupArn", "TargetGroupName")
    keys = _items(done, f"{WORK}kms-keys.json", "Keys", "KeyId")
    acls = _items(done, f"{WORK}web-acls.json", "WebACLs", "Name", "Id", "ARN")
    plans = _items(done, f"{WORK}backup-plans.json", "BackupPlansList", "BackupPlanId")
    sso = next(iter(_items(done, f"{WORK}sso-instances.json", "Instances", "InstanceArn")), (None,))[0]
    return (
        *((p, c) for arn, name in lbs for p, c in (
            (f"listeners-{_last(arn)}.json", _aws(m, "elbv2", "describe-listeners", "--load-balancer-arn", arn)),
            (f"lb-tags-{_last(arn)}.json", _aws(m, "elbv2", "describe-tags", "--resource-arns", arn)),
            (f"lb-attributes/{name}.json",
             _aws(m, "elbv2", "describe-load-balancer-attributes", "--load-balancer-arn", arn)))),
        *((p, c) for arn, name in tgs for p, c in (
            (f"target-health/{_target_group_name(arn)}.json",
             _aws(m, "elbv2", "describe-target-health", "--target-group-arn", arn)),
            (f"tg-attributes/{name}.json",
             _aws(m, "elbv2", "describe-target-group-attributes", "--target-group-arn", arn)))),
        *((f"route53/{_last(z)}.json", _aws(m, "route53", "list-resource-record-sets", "--hosted-zone-id", _last(z)))
          for (z,) in _items(done, "hosted-zones.json", "HostedZones", "Id")),
        *((p, c) for (k,) in keys for p, c in (
            (f"kms/key-{k}.json", _aws(m, "kms", "describe-key", "--key-id", k)),
            (f"kms/rotation-{k}.json", _aws(m, "kms", "get-key-rotation-status", "--key-id", k,
                                             absent=("UnsupportedOperationException", "KMSInvalidStateException"))),
            (f"key-policy/{k}.json", _aws(m, "kms", "get-key-policy", "--key-id", k, "--policy-name", "default")))),
        *((f"lambda-tags/{name}.json", _aws(m, "lambda", "list-tags", "--resource", arn))
          for arn, name in _items(done, "functions.json", "Functions", "FunctionArn", "FunctionName")),
        *((f"event-targets/{name}.json",
           _aws(m, "events", "list-targets-by-rule", "--rule", name, query=PROJECTIONS["targets"]))
          for (name,) in _items(done, "rules.json", "Rules", "Name")),
        *((f"schedule-{name}.json", _aws(m, "scheduler", "get-schedule", "--name", name, "--group-name",
                                         group or "default", query=PROJECTIONS["schedule"]))
          for name, group in _items(done, f"{WORK}schedules.json", "Schedules", "Name", "GroupName")),
        *((f"pipeline-{name}.json", _aws(m, "codepipeline", "get-pipeline", "--name", name,
                                         query=PROJECTIONS["pipeline"]))
          for (name,) in _items(done, f"{WORK}pipelines.json", "pipelines", "name")),
        *((("build-projects.json", _aws(m, "codebuild", "batch-get-projects", "--names", *names,
                                        query=PROJECTIONS["projects"])),)
          for names in (tuple(_doc(done, f"{WORK}build-projects.json").get("projects") or ()),) if names),
        *((p, c) for name, i, arn in acls for p, c in (
            (f"web-acl-{name}.json", _aws(m, "wafv2", "get-web-acl", "--scope", "REGIONAL", "--name", name, "--id", i)),
            (f"waf-resources/{name}.json", _aws(m, "wafv2", "list-resources-for-web-acl", "--web-acl-arn", arn)))),
        *((f"ip-set-{name}.json", _aws(m, "wafv2", "get-ip-set", "--scope", "REGIONAL", "--name", name, "--id", i))
          for name, i in _items(done, f"{WORK}ip-sets.json", "IPSets", "Name", "Id")),
        *((f"service-permissions/{s}.json",
           _aws(m, "ec2", "describe-vpc-endpoint-service-permissions", "--service-id", s))
          for (s,) in _items(done, "endpoint-services.json", "ServiceConfigurations", "ServiceId")),
        *((f"rule-group-{_last(a)}.json", _aws(m, "network-firewall", "describe-rule-group", "--rule-group-arn", a))
          for (a,) in _items(done, f"{WORK}rule-groups.json", "RuleGroups", "Arn")),
        *((f"firewall-policy-{_last(a)}.json",
           _aws(m, "network-firewall", "describe-firewall-policy", "--firewall-policy-arn", a))
          for (a,) in _items(done, f"{WORK}firewall-policies.json", "FirewallPolicies", "Arn")),
        *((f"firewall-{_last(a)}.json", _aws(m, "network-firewall", "describe-firewall", "--firewall-arn", a))
          for (a,) in _items(done, f"{WORK}firewalls.json", "Firewalls", "FirewallArn")),
        *((f"user-pools/{i}.json", _aws(m, "cognito-idp", "describe-user-pool", "--user-pool-id", i,
                                        query=POOL_QUERY))
          for (i,) in _items(done, f"{WORK}user-pools.json", "UserPools", "Id") if i),
        *((f"{TAGS_FOLDER}/{i}.json", _aws(m, "ds", "list-tags-for-resource", "--resource-id", i))
          for i, kind in _items(done, "directories.json", "DirectoryDescriptions", "DirectoryId", "Type")
          if i and kind == "MicrosoftAD"),
        *((f"db-parameters/{g}.json", _aws(m, "rds", "describe-db-parameters", "--db-parameter-group-name", g,
                                           "--source", "user"))
          for (g,) in _items(done, f"{WORK}db-parameter-groups.json", "DBParameterGroups", "DBParameterGroupName")
          if g and not g.startswith("default.")),
        *((f"db-cluster-parameters/{g}.json", _aws(m, "rds", "describe-db-cluster-parameters",
                                                   "--db-cluster-parameter-group-name", g, "--source", "user"))
          for (g,) in _items(done, f"{WORK}db-cluster-parameter-groups.json", "DBClusterParameterGroups",
                             "DBClusterParameterGroupName") if g and not g.startswith("default.")),
        *((f"dlm-policies/{p}.json", _aws(m, "dlm", "get-lifecycle-policy", "--policy-id", p))
          for (p,) in _items(done, f"{WORK}dlm-policies.json", "Policies", "PolicyId")),
        *((p, c) for v, arn in _items(done, "backup-vaults.json", "BackupVaultList", "BackupVaultName",
                                      "BackupVaultArn") for p, c in (
            (f"backup-tags/{v}.json", _aws(m, "backup", "list-tags", "--resource-arn", arn)),)),
        *((p, c) for (pid,) in plans for p, c in (
            (f"backup-plans/{pid}.json", _aws(m, "backup", "get-backup-plan", "--backup-plan-id", pid)),
            (f"{WORK}backup-selections-{pid}.json",
             _aws(m, "backup", "list-backup-selections", "--backup-plan-id", pid)))),
        *((p, c) for (pid,) in plans for doc in (_doc(done, f"backup-plans/{pid}.json"),) if doc
          for p, c in ((f"backup-tags/{(doc.get('BackupPlan') or {}).get('BackupPlanName')}.json",
                        _aws(m, "backup", "list-tags", "--resource-arn", doc.get("BackupPlanArn"))),)
          if doc.get("BackupPlanArn")),
        *((f"backup-plans/{pid}-{s}.json",
           _aws(m, "backup", "get-backup-selection", "--backup-plan-id", pid, "--selection-id", s))
          for (pid,) in plans for (s,) in _items(done, f"{WORK}backup-selections-{pid}.json", "BackupSelectionsList",
                                                  "SelectionId")),
        *((p, c) for (arn,) in _items(done, "trails.json", "trailList", "TrailARN") for p, c in (
            (f"cloudtrail/{_last(arn)}-selectors.json", _aws(m, "cloudtrail", "get-event-selectors", "--trail-name",
                                                             arn)),
            (f"cloudtrail/{_last(arn)}-tags.json", _aws(m, "cloudtrail", "list-tags", "--resource-id-list", arn)))),
        *_compute_details(m, done),
        *((p, c) for d in _doc(done, f"{WORK}guardduty-detectors.json").get("DetectorIds") or () if isinstance(d, str)
          for p, c in ((f"guardduty/{d}.json", _aws(m, "guardduty", "get-detector", "--detector-id", d)),
                       (f"organization-configuration/guardduty-{d}.json",
                        _aws(m, "guardduty", "describe-organization-configuration", "--detector-id", d,
                             absent=NOT_ADMIN["guardduty"])))),
        *_monitor_details(m, done),
        *_messaging_details(m, done),
        *(((f"{WORK}permission-sets.json", _aws(m, "sso-admin", "list-permission-sets", "--instance-arn", sso)),)
          if sso else ()),
        *((p, c) for ps in (_doc(done, f"{WORK}permission-sets.json").get("PermissionSets") or ()) if sso
          for p, c in _permission_set(m, done, sso, ps)))


def _compute_details(m, done):
    """(path, call) of the launch template versions the autoscaling groups use, and each EKS cluster with its node
    groups and add-ons. User data is never fetched (projected out)."""
    refs = dict.fromkeys((ref["id"], ref["name"], ref["version"] or "$Default")
                         for g in _doc(done, "autoscaling-groups.json").get("AutoScalingGroups") or ()
                         if isinstance(g, dict) for ref in (launch_template_ref(g),) if ref["id"] or ref["name"])
    clusters = [c for c in _doc(done, f"{WORK}eks-clusters.json").get("clusters") or () if isinstance(c, str)]

    def listed(path, key):
        return [x for x in _doc(done, path).get(key) or () if isinstance(x, str)]
    return (
        *((f"launch-templates/{file_name(i or n)}-{file_name(v)}.json",
           _aws(m, "ec2", "describe-launch-template-versions",
                *(("--launch-template-id", i) if i else ("--launch-template-name", n)), "--versions", v,
                query=PROJECTIONS["launch-template-versions"]))
          for i, n, v in refs),
        *((p, c) for name in clusters for p, c in (
            (f"eks/{name}.json", _aws(m, "eks", "describe-cluster", "--name", name)),
            (f"{WORK}eks-nodegroups-{name}.json", _aws(m, "eks", "list-nodegroups", "--cluster-name", name)),
            (f"{WORK}eks-addons-{name}.json", _aws(m, "eks", "list-addons", "--cluster-name", name)))),
        *((f"eks/{name}-nodegroup-{g}.json",
           _aws(m, "eks", "describe-nodegroup", "--cluster-name", name, "--nodegroup-name", g))
          for name in clusters for g in listed(f"{WORK}eks-nodegroups-{name}.json", "nodegroups")),
        *((f"eks/{name}-addon-{a}.json", _aws(m, "eks", "describe-addon", "--cluster-name", name, "--addon-name", a))
          for name in clusters for a in listed(f"{WORK}eks-addons-{name}.json", "addons")))


def _monitor_details(m, done):
    """(path, call) of the tags of each metric alarm, log group and SNS topic, saved by name."""
    return (
        *((tags_path("alarm-tags", name), _aws(m, "cloudwatch", "list-tags-for-resource", "--resource-arn", arn))
          for arn, name in _items(done, "alarms.json", "MetricAlarms", "AlarmArn", "AlarmName") if arn and name),
        *((tags_path("log-group-tags", name), _aws(m, "logs", "list-tags-for-resource", "--resource-arn",
                                                   arn or (star or "").removesuffix(":*")))
          for name, arn, star in _items(done, "log-groups.json", "logGroups", "logGroupName", "logGroupArn", "arn")
          if name and (arn or star)),
        *((tags_path("topic-tags", _last(arn)), _aws(m, "sns", "list-tags-for-resource", "--resource-arn", arn))
          for (arn,) in _items(done, "topics.json", "Topics", "TopicArn") if arn))


def _messaging_details(m, done):
    """(path, call) of each queue's ARN and tags (named by the queue), each event bus's and stream's tags (the default
    bus, which the record leaves out, has none asked), and each SES domain identity (addresses aren't read)."""
    queues = [(url, url.rsplit("/", 1)[-1]) for url in _doc(done, f"{WORK}queues.json").get("QueueUrls") or ()
              if isinstance(url, str)]
    return (
        *((p, c) for url, name in queues for p, c in (
            (f"queues/{file_name(name)}.json", _aws(m, "sqs", "get-queue-attributes", "--queue-url", url,
                                                    "--attribute-names", "QueueArn", query=PROJECTIONS["queue-arn"])),
            (tags_path("queue-tags", name), _aws(m, "sqs", "list-queue-tags", "--queue-url", url,
                                                 query=PROJECTIONS["queue-tags"])))),
        *((tags_path("event-bus-tags", name), _aws(m, "events", "list-tags-for-resource", "--resource-arn", arn))
          for name, arn in _items(done, "event-buses.json", "EventBuses", "Name", "Arn") if arn and name != "default"),
        *((tags_path("stream-tags", name), _aws(m, "kinesis", "list-tags-for-resource", "--resource-arn", arn))
          for name, arn, status in _items(done, "streams.json", "StreamSummaries", "StreamName", "StreamARN",
                                          "StreamStatus") if arn and status != "DELETING"),
        *((f"email-identities/{file_name(name)}.json",
           _aws(m, "sesv2", "get-email-identity", "--email-identity", name, query=PROJECTIONS["email-identity"]))
          for name, kind in _items(done, f"{WORK}email-identities.json", "EmailIdentities", "IdentityName",
                                   "IdentityType") if name and kind == "DOMAIN"))


def _permission_set(m, done, sso, ps):
    """A permission set's description first, then (named by it) its policies and assignments in the account."""
    described = f"{WORK}sso-{_last(ps)}.json"
    name = (_doc(done, described).get("PermissionSet") or {}).get("Name")
    common = ("--instance-arn", sso, "--permission-set-arn", ps)
    return ((described, _aws(m, "sso-admin", "describe-permission-set", *common)),
            *(((f"sso-{name}.json", _aws(m, "sso-admin", "describe-permission-set", *common)),
               (f"sso-inline/{name}.json", _aws(m, "sso-admin", "get-inline-policy-for-permission-set", *common)),
               (f"sso-managed/{name}.json",
                _aws(m, "sso-admin", "list-managed-policies-in-permission-set", *common)),
               (f"sso-assignments-{name}.json", _aws(m, "sso-admin", "list-account-assignments", *common,
                                                     "--account-id", account_id(m))))
              if name else ()))


def _vpc(m):
    network = one_role(m, "network")
    return one(network, "ciamProviderRef") if network is not None else None


def _in_env(m, pairs):
    """The pairs with their paths under the environment's folder (<cloud>/<env>/), work files left as they are."""
    return tuple((p if p.startswith(WORK) else f"{m.label}/{p}", c) for p, c in pairs)


def org_profiles(m):
    """The AWS CLI profiles environment m's aws/cli-inventory collection sources name (aws-profile://<profile>): one for
    the organization's policies, and in GovCloud one for the budgets in the standard account; which is which is told
    by the account each is signed in to (profile_purposes)."""
    return tuple(loc[len("aws-profile://"):] for s in collection_sources(m, "aws/cli-inventory") for loc in s.locations
                 if loc.startswith("aws-profile://"))


def profile_purposes(m, local):
    """{profile: "billing" (signed in to a GovCloud cloud's standard account, ciamBillingAccountRef), "organization"
    (any other account: checked against ciamOrganizationRef), or None (its identity not read yet)}."""
    billing = standard_account(m) if govcloud(m) else None
    return {p: None if f"{WORK}profile-{p}.json" not in local else
            "billing" if billing and _doc(local, f"{WORK}profile-{p}.json").get("Account") == billing
            else "organization" for p in org_profiles(m)}


def organization_id(m):
    """The AWS organization (o-…) the cloud's ciamOrganizationRef names (the ID, or an ARN holding it), or None."""
    found = ORGANIZATION.search(one(m.cloud, "ciamOrganizationRef") or "")
    return found.group(0) if found else None


def inventory_problems(d, m, options):
    """Collector.problems of aws/cli-inventory: profile sources that can't be used safely (more than the organization's
    and, in GovCloud, the standard account's; a name not passed to the AWS CLI; nothing recorded to check them
    against)."""
    profiles = org_profiles(m)
    if not profiles:
        return ()
    billing = govcloud(m) and standard_account(m)
    most = 2 if billing else 1
    return (*(("more than two aws-profile:// collection sources: name one profile for the organization's policies "
               "and one for the standard account's budgets" if billing else
               "more than one aws-profile:// collection source: name one profile for the organization's policies",)
              if len(profiles) > most else ()),
            *(f"aws-profile://{p}: not a profile name opsdir passes to the AWS CLI" for p in profiles
              if not PROFILE.match(p)),
            *(("the cloud records no AWS organization (ciamOrganizationRef o-…) to check the profile against",)
              if organization_id(m) is None and not billing else ()),
            *(("the cloud records no account (ciamAccountRef) whose policies to read",) if not account_id(m) else ()))


def _chain(local, account):
    """The account and its parents up to the root, as far as the listings collected so far go: ((id, is root), ...)."""
    found, at = [(account, False)], account
    while f"{WORK}org-parents-{at}.json" in local:
        parent = next(iter(_items(local, f"{WORK}org-parents-{at}.json", "Parents", "Id", "Type")), (None, None))
        if not (parent[0] and TARGET.match(parent[0])) or parent[0] in [t for t, _ in found]:
            break
        found.append((parent[0], parent[1] == "ROOT"))
        if parent[1] == "ROOT":
            break
        at = parent[0]
    return tuple(found)


def _org_steps(m, local, profile):
    """(path, call or problem) of the organization's policies, read with profile: its identity and organization first;
    then, when that is the cloud's organization, the account's parents, the policies attached to each, each policy."""
    org = lambda *args, absent=(): _aws(m, "organizations", *args, "--profile", profile, absent=absent)
    first = ((f"{WORK}organization.json", org("describe-organization")),)
    if f"{WORK}organization.json" not in local:
        return first
    found, want = (_doc(local, f"{WORK}organization.json").get("Organization") or {}).get("Id"), organization_id(m)
    if found != want:
        return (*first, (f"{WORK}org-check", f"profile {profile} is signed in to organization {found}, the cloud "
                                             f"records {want}: its policies are not read"))
    chain = _chain(local, account_id(m))
    listings = tuple((f"{WORK}org-policies-{t}-{kind}.json", t, kind) for t, _ in chain for kind in POLICY_TYPES)
    policies = dict.fromkeys(p for path, _, _ in listings for (p,) in _items(local, path, "Policies", "Id")
                             if p and POLICY.match(p))
    return (*first,
            *((f"{WORK}org-parents-{t}.json", org("list-parents", "--child-id", t)) for t, root in chain if not root),
            *((path, org("list-policies-for-target", "--target-id", t, "--filter", kind,
                         absent=("PolicyTypeNotEnabledException",))) for path, t, kind in listings),
            *((f"org/{p}.json", org("describe-policy", "--policy-id", p)) for p in policies))


def _budget_steps(m, local, account, profile=None):
    """(path, call) of an account's budgets, each one's notifications, their SNS subscribers and its tags: with the
    environment's login for its own account, or with profile for a GovCloud cloud's standard account. AWS Budgets'
    endpoint is global, listed under us-east-1, with no FIPS endpoint (AWS General Reference): its calls name us-east-1
    and never ask for FIPS endpoints."""
    if not account:
        return ()
    login = ("--profile", profile) if profile else ()
    budgets = lambda *args, query=None: _aws(m, "budgets", *args, *login, query=query, region="us-east-1", fips=False)
    listing, arn_partition = f"budgets/{account}.json", "aws" if profile else partition(m)
    names = [n for (n,) in _items(local, listing, "Budgets", "BudgetName") if n]
    return ((listing, budgets("describe-budgets", "--account-id", account)),
            *((p, c) for n in names for folder in (budget_folder(account, n),) for p, c in (
                (f"{folder}/notifications.json", budgets("describe-notifications-for-budget", "--account-id", account,
                                                         "--budget-name", n)),
                (f"{folder}/tags.json", budgets("list-tags-for-resource", "--resource-arn",
                                                f"arn:{arn_partition}:budgets::{account}:budget/{n}")))),
            *((f"{folder}/subscribers-{i}.json",
               budgets("describe-subscribers-for-notification", "--account-id", account, "--budget-name", n,
                       "--notification", json.dumps({k: note[k] for k in NOTIFICATION_KEYS if k in note}),
                       query=PROJECTIONS["subscribers"]))
              for n in names for folder in (budget_folder(account, n),)
              for i, note in enumerate(x for x in _doc(local, f"{folder}/notifications.json").get("Notifications")
                                       or () if isinstance(x, dict))))


def _profile_steps(m, local):
    """(path, call or problem) of the profile sources: each one's identity first; then the organization's policies with
    the one signed in elsewhere than the standard account, and the standard account's budgets with the one signed in
    there (a GovCloud cloud's billing)."""
    purposes = profile_purposes(m, local)
    orgs = [p for p, purpose in purposes.items() if purpose == "organization"]
    billing = [p for p, purpose in purposes.items() if purpose == "billing"]
    return (*((f"{WORK}profile-{p}.json", _aws(m, "sts", "get-caller-identity", "--profile", p)) for p in purposes),
            *(_org_steps(m, local, orgs[0]) if orgs else ()),
            *((f"{WORK}profile-check-{p}", f"profile {p} is a second profile for the organization's policies (the "
                                           f"standard account is {standard_account(m) or 'not recorded'}): not used")
              for p in orgs[1:]),
            *(_budget_steps(m, local, standard_account(m), billing[0]) if billing else ()),
            *((f"{WORK}profile-check-{p}", f"profile {p} is a second profile for the standard account's budgets: not "
                                           f"used") for p in billing[1:]))


def inventory_steps(d, m, done, options):
    """The cli-inventory calls still to make (core.contract Collector.steps): the listings, then their items; the
    account's budgets (in GovCloud, the standard account's through its profile source); with profile sources, the
    organization's policies that apply to the account."""
    vpc = _vpc(m)
    if vpc is None:
        return ()
    local = env_relative(m, done)
    return _in_env(m, (*_listings(m, vpc), *_details(m, local),
                       *(() if govcloud(m) else _budget_steps(m, local, account_id(m))),
                       *_profile_steps(m, local)))


def state_steps(d, m, done, options):
    """The terraform-state calls (opsdir_format_terraform.state.state_steps): `terraform state pull` in
    --terraform-dir, else each collection source's object."""
    return terraform_state_steps(m, "aws/terraform-state", "s3://", lambda loc: _aws(m, "s3", "cp", loc, "-"), options)


def stack_of(ref):
    """(stack name, the --stack-name to give, region, account) a CloudFormation collection source's ref names
    (cfn://<name>: the cloud's region and account, both None; or a stack ARN), or None when it names no stack."""
    found = STACK_ARN.match(ref or "")
    if found:
        region, account, name = found.groups()
        return name, ref, region, account
    name = (ref or "")[len("cfn://"):] if (ref or "").startswith("cfn://") else None
    return (name, name, None, None) if name and STACK_NAME.match(name) else None


def _stack_calls(m, folder, stack, region):
    """The three calls saving one stack under folder, as the README's script does."""
    given = ("--stack-name", stack)
    return ((f"{folder}/stack.json", _aws(m, "cloudformation", "describe-stacks", *given, query=PROJECTIONS["stack"],
                                          region=region)),
            (f"{folder}/resources.json", _aws(m, "cloudformation", "list-stack-resources", *given, region=region)),
            (f"{folder}/template.json", _aws(m, "cloudformation", "get-template", *given, "--template-stage",
                                             "Processed", region=region)))


def _nested(local, folder):
    """(folder, stack ARN, region) of each nested stack a stack's resources name as created."""
    rows = _items(local, f"{folder}/resources.json", "StackResourceSummaries", "ResourceType", "PhysicalResourceId",
                  "ResourceStatus")
    arns = (STACK_ARN.match(arn or "") for kind, arn, status in rows if kind == NESTED and status not in NOT_CREATED)
    return tuple((f.group(3), f.group(0), f.group(1)) for f in arns if f)


def _with_nested(local, stacks, seen=()):
    """stacks ((folder, --stack-name, region), ...) and, from what was collected, the nested stacks under them."""
    found = tuple(x for x in stacks if x[0] not in seen)
    if not found:
        return ()
    names = (*seen, *(f for f, _, _ in found))
    return (*found, *_with_nested(local, tuple(n for f, _, _ in found for n in _nested(local, f)), names))


def _named_stacks(m):
    """(folder, --stack-name, region) of each stack the environment's aws/cloudformation sources name in its account."""
    want = account_id(m)
    named = (stack_of(loc) for s in collection_sources(m, "aws/cloudformation") for loc in s.locations)
    return tuple((name, stack, region) for name, stack, region, account in (x for x in named if x)
                 if account is None or account == want)


def stack_steps(d, m, done, options):
    """The cloudformation calls still to make: each named stack's three, then each nested stack's."""
    local = env_relative(m, done)
    return _in_env(m, tuple(c for folder, stack, region in _with_nested(local, _named_stacks(m))
                            for c in _stack_calls(m, folder, stack, region)))


def stack_problems(d, m, options):
    """Collector.problems: an aws/cloudformation source naming no stack, or a stack in another account."""
    want = account_id(m)
    return tuple(
        f"collection source `{s.name}`: {loc} " + ("isn't a stack (cfn://<stack name>, or the stack's ARN)"
                                                   if stack_of(loc) is None else
                                                   f"is a stack in account {stack_of(loc)[3]}, "
                                                   f"the cloud records {want}")
        for s in collection_sources(m, "aws/cloudformation") for loc in s.locations
        if stack_of(loc) is None or (stack_of(loc)[3] and stack_of(loc)[3] != want))


def identity_check(d, m):
    """`aws sts get-caller-identity`, and whether its Account is the one the cloud records."""
    want = account_id(m)

    def check(out):
        found = _doc({"out": out}, "out").get("Account")
        return (None if want and found == want else
                "the cloud records no account (ciamAccountRef) to check the login against" if not want else
                f"signed in to account {found}, the record names {want}")
    region = one(m.cloud, "ciamRegion")
    return Command(("aws", "sts", "get-caller-identity", "--output", "json",
                    *(("--region", region) if region else ())),
                   env=(("AWS_USE_FIPS_ENDPOINT", "true"),) if fips_endpoints(m) else ()), check


COLLECTORS = (Collector("cli-inventory", "environment", inventory_steps, identity_check, inventory_problems),
              Collector("terraform-state", "environment", state_steps, identity_check, options=(TERRAFORM_DIR,)),
              Collector("cloudformation", "environment", stack_steps, identity_check, stack_problems))
