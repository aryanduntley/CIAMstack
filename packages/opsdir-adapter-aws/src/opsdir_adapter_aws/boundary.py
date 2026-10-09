"""The AWS services an environment uses, as AWS's FedRAMP Certification Package Overviews name them (the certified
services lists of AWS US East/West and AWS GovCloud, 2026-08), so the planner can check them against the in-scope list
of the authorization the environment relies on (opsdir.domains.estate.authorizations). Neither list names Elastic Load
Balancing, EC2 Auto Scaling, Data Lifecycle Manager, Site-to-Site VPN, Transit Gateway or CloudWatch Synthetics (nor
does AWS's FedRAMP services-in-scope page, 2026-10-08). Two are covered by a listed service on AWS's own word (COVERED):
the EBS guide says Data Lifecycle Manager "is assessed as a service capability of Amazon Elastic Block Store (Amazon
EBS)" and that any program listing EBS applies to it; Site-to-Site VPN is a feature of Amazon VPC in the EC2 API (the
SDK the scope page gives for VPC), and the scope page counts "generally available features of each of the services" in
scope "unless specifically excluded". Elastic Load Balancing, EC2 Auto Scaling and CloudWatch Synthetics have APIs of
their own and no row: an environment using them is told so. Budgets and quotas are named nowhere: they hold no
customer data. Pure."""
from opsdir.core.directory import one
from opsdir.domains.edge.records import is_hosted
from opsdir.domains.estate.authorizations import boundary_findings, services_used

VPC, EC2 = "Amazon Virtual Private Cloud (VPC)", "Amazon Elastic Compute Cloud (EC2)"
EBS = "Amazon Elastic Block Store (EBS)"
FEATURES = ("AWS counts generally available features of a listed service in scope unless specifically excluded "
            "(services in scope, FedRAMP)")
# a service AWS documents as covered by a listed one -> (that service, AWS's basis)
COVERED = {
    "Amazon Data Lifecycle Manager": (EBS, "AWS assesses it as a service capability of Amazon EBS: a program listing "
                                           "EBS applies to it (EBS user guide)"),
    "AWS Site-to-Site VPN": (VPC, f"a feature of Amazon VPC in the EC2 API; {FEATURES}"),
}
S3 = "Amazon Simple Storage Service (S3)"
SNS = "Amazon Simple Notification Service (SNS)"
ENGINES = {"postgresql": "Amazon RDS for Postgres", "mysql": "Amazon RDS for MySQL",
           "mariadb": "Amazon RDS for MariaDB", "sqlserver": "Amazon RDS for SQL Server",
           "oracle": "Amazon RDS for Oracle"}
SECURITY = {"threat-detection": "Amazon GuardDuty", "vulnerability-scanning": "Amazon Inspector",
            "config-recording": "AWS Config", "posture": "AWS Security Hub CSPM"}
STREAMS = {"topic": SNS, "queue": "Amazon Simple Queue Service (SQS)", "bus": "Amazon EventBridge",
           "log-stream": "Amazon Kinesis Data Streams"}
EDGE = {"waf": "AWS Web Application Firewall (WAF)", "cdn": "Amazon CloudFront",
        "ddos": "AWS Shield (Standard and Advanced)", "api-gateway": "Amazon API Gateway"}
# object class -> the service a binding of it uses (or a function of the binding)
NAMES = {
    "ciamDatabase": lambda b: ENGINES.get(one(b, "ciamDbEngine")),
    "ciamObjectStore": S3, "ciamVolume": EBS,
    "ciamSnapshotPolicy": "Amazon Data Lifecycle Manager",
    "ciamBackupVault": "AWS Backup", "ciamBackupPlan": "AWS Backup",
    "ciamKeyRef": "AWS Key Management Service (KMS)", "ciamSecretRef": "AWS Secrets Manager",
    "ciamCertificateRef": "AWS Certificate Manager (ACM)",
    "ciamAlertChannel": lambda b: SNS if one(b, "ciamChannelKind") == "topic" else None,
    "ciamLogDestination": lambda b: {"log-group": "Amazon Cloudwatch Logs", "bucket": S3}.get(
        one(b, "ciamDestinationKind")),
    "ciamAlarmBinding": "Amazon Cloudwatch", "ciamCanaryBinding": "Amazon CloudWatch Synthetics",
    "ciamAuditTrail": "AWS CloudTrail",
    "ciamSecurityService": lambda b: SECURITY.get(one(b, "ciamSecurityKind")), "ciamDataDiscovery": "Amazon Macie",
    "ciamComputeGroup": "Amazon EC2 Auto Scaling", "ciamCluster": "Amazon Elastic Kubernetes Service (EKS)",
    "ciamSendingIdentity": "Amazon Simple Email Service (SES)",
    "ciamStreamBinding": lambda b: STREAMS.get(one(b, "ciamStreamKind")),
    "ciamEdgeService": lambda b: EDGE.get(one(b, "ciamEdgeKind")),
    "ciamServiceName": "Elastic Load Balancing (ELB)",
    "ciamDnsZoneBinding": "Amazon Route 53", "ciamDnsRecord": "Amazon Route 53",
    "ciamDnsForwarder": lambda b: EC2 if is_hosted(b) else "Amazon Route 53",
    "ciamIdentityBinding": "AWS Identity and Access Management (IAM)", "ciamGuardrail": "AWS Organizations",
    "ciamFirewallPolicy": "AWS Network Firewall",
    "ciamInterconnect": lambda b: "AWS Direct Connect" if "direct" in (one(b, "ciamInterconnectKind") or "").lower()
    else "AWS Site-to-Site VPN",
    **{oc: VPC for oc in ("ciamNetwork", "ciamSubnetBinding", "ciamRouteTable", "ciamNetworkAcl", "ciamFirewallRule",
                          "ciamFlowLog", "ciamPrivateEndpoint", "ciamEndpointService", "ciamEgress")},
}


def aws_services(m):
    """The AWS services environment m's servers and bindings use."""
    return services_used(m, NAMES, EC2)


def check_boundary(ctx):
    """The target's services outside the authorization it relies on."""
    return boundary_findings(ctx, aws_services(ctx.dst), COVERED)
