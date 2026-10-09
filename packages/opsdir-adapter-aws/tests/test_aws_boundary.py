"""The AWS services an environment uses, named as AWS's FedRAMP package overviews name them, and the planner's check
against the in-scope list of the authorization the target relies on (a load balancer: not on AWS's lists; snapshot
policies: Data Lifecycle Manager, covered by EBS on AWS's word)."""
from opsdir.core.interchange.ldif import LdifRecord
from opsdir_adapter_aws.boundary import aws_services, check_boundary
from network_fixtures import BETA, context, entry, model

AUTH = "cn=F1603047866,ou=authorizations,dc=ciam-ops"
TREE = ("dn: ou=authorizations,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: authorizations\n",
        f"dn: {AUTH}\nobjectClass: top\nobjectClass: ciamCloudAuthorization\ncn: F1603047866\n"
        "ciamPackageId: F1603047866\nciamAuthorizationLevel: fedramp-high\nciamAuthorizationStatus: certified\n"
        "ciamScopeAsOf: 20260826000000Z\nciamInScopeService: Amazon Elastic Compute Cloud (EC2)\n"
        "ciamInScopeService: Amazon RDS for Postgres\nciamInScopeService: Amazon Simple Storage Service (S3)\n"
        "ciamInScopeService: Amazon Virtual Private Cloud (VPC)\n"
        "ciamInScopeService: Amazon Elastic Block Store (EBS)\n")
BINDINGS = (entry(BETA, "grants", "ciamDatabase", ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql"),
            entry(BETA, "backups", "ciamObjectStore", ciamBindingRole="backup-target", ciamStorageRef="s3://b"),
            entry(BETA, "ldaps", "ciamServiceName", ciamBindingRole="ds-ldaps-service", ciamFqdn="ldap.example.test",
                  ciamTargetRole="ds", ciamPort="1636"),
            entry(BETA, "snaps", "ciamSnapshotPolicy", ciamBindingRole="ds-snapshots"))


def test_the_services_an_environment_uses_and_those_outside_its_authorization():
    held = LdifRecord(BETA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                           ("replace", "ciamAuthorizationRef", (AUTH,)),
                                           ("replace", "ciamRequiredAuthorization", ("fedramp-high",))))
    d, a, b = model(beta=BINDINGS, tree=TREE, changes=(held,))
    used = dict(aws_services(b))
    assert {"Amazon Elastic Compute Cloud (EC2)", "Amazon RDS for Postgres", "Amazon Simple Storage Service (S3)",
            "Elastic Load Balancing (ELB)"} <= set(used) and used["Amazon RDS for Postgres"] == "pf-grants-db"
    f = check_boundary(context(d, a, b, cutover="2026-12-01"))
    assert [x[1].split(", which")[0] for x in f.blockers] == [
        "beta/prod uses Elastic Load Balancing (ELB) (ds-ldaps-service, sso-service)"]
    assert f.ok == ("beta/prod uses Amazon Data Lifecycle Manager (ds-snapshots), which `F1603047866` covers as "
                    "part of Amazon Elastic Block Store (EBS): AWS assesses it as a service capability of Amazon EBS: "
                    "a program listing EBS applies to it (EBS user guide).",)
