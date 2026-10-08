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
custom headers). Nothing reads secret values (no get-secret-value, no SSM parameters, no user data). Calls that answer
"nothing there" for a resource without that setting (a bucket without a policy, Shield without a subscription, a key
without rotation support) leave their file out. Organization control policies need the management account and are
not collected here (import them as before).

Terraform state: (a) by default the state object a collection source names (ciamCollectionSource, importer
aws/terraform-state, ciamSourceRef s3://bucket/key, the workspace prefix included) read with `aws s3 cp URI -`: no
init, no lock, read access to one object; (b) with --terraform-dir, `terraform state pull` in that initialized
working directory (the backend as configured there)."""
import json
import re

from opsdir.core.contract import Collector, Command
from opsdir.core.directory import one, values
from opsdir.core.environment import of_class, one_role
from opsdir.domains.estate.residency import fips_endpoints
from opsdir.domains.governance.collection import collection_sources
from .account import account_id
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
}
BUCKET_SETTINGS = (("bucket-versioning", "get-bucket-versioning", ()),
                   ("bucket-object-lock", "get-object-lock-configuration", ("ObjectLockConfigurationNotFoundError",)),
                   ("bucket-encryption", "get-bucket-encryption", ("ServerSideEncryptionConfigurationNotFoundError",)),
                   ("bucket-public-access", "get-public-access-block", ("NoSuchPublicAccessBlockConfiguration",)),
                   ("bucket-lifecycle", "get-bucket-lifecycle-configuration", ("NoSuchLifecycleConfiguration",)),
                   ("bucket-replication", "get-bucket-replication", ("ReplicationConfigurationNotFoundError",)),
                   ("bucket-policy", "get-bucket-policy", ("NoSuchBucketPolicy",)))


def _aws(m, *args, query=None, absent=()):
    """An AWS CLI call for environment m: JSON output, the cloud's region, FIPS endpoints when it records them."""
    region = one(m.cloud, "ciamRegion")
    return Command(("aws", *args, *(("--query", query) if query else ()), "--output", "json",
                    *(("--region", region) if region else ())),
                   env=(("AWS_USE_FIPS_ENDPOINT", "true"),) if fips_endpoints(m) else (), absent=tuple(absent))


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
        *(((f"{WORK}permission-sets.json", _aws(m, "sso-admin", "list-permission-sets", "--instance-arn", sso)),)
          if sso else ()),
        *((p, c) for ps in (_doc(done, f"{WORK}permission-sets.json").get("PermissionSets") or ()) if sso
          for p, c in _permission_set(m, done, sso, ps)))


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


def _local(m, done):
    """done with the environment's folder taken off its paths (what the steps name)."""
    base = f"{m.label}/"
    return {(p[len(base):] if p.startswith(base) else p): t for p, t in done.items()}


def inventory_steps(d, m, done, options):
    """The cli-inventory calls still to make (core.contract Collector.steps): the listings, then their items."""
    vpc = _vpc(m)
    if vpc is None:
        return ()
    local = _local(m, done)
    return _in_env(m, (*_listings(m, vpc), *_details(m, local)))


def state_steps(d, m, done, options):
    """The terraform-state calls: `terraform state pull` in --terraform-dir, else each collection source's object."""
    if options.get("terraform_dir"):
        return ((f"{m.label}/terraform.tfstate",
                 Command(("terraform", f"-chdir={options['terraform_dir']}", "state", "pull"))),)
    return tuple((f"{m.label}/{loc.rsplit('/', 1)[-1] or 'terraform.tfstate'}", _aws(m, "s3", "cp", loc, "-"))
                 for s in collection_sources(m, "aws/terraform-state") for loc in s.locations
                 if loc.startswith("s3://"))


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


COLLECTORS = (Collector("cli-inventory", "environment", inventory_steps, identity_check),
              Collector("terraform-state", "environment", state_steps, identity_check))
