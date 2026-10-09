"""What the tools should find: every problem planted in the estate, and how the migration planner reports it.
The demo checks the planner against this list, so "NOT READY" reads as "found what was planted", not as a failure.
A finding is (id, area, match, planted, cleared_by, raised_by): cleared_by, the approved change that fixes it;
raised_by, the approved change whose record brings it (expected only once that change is applied).
"""
from types import MappingProxyType


EXPECTED = MappingProxyType({
    "blockers": [
        ("B1", "Contract", "`ds-ldaps-service` changes name", "the target environment binds a new LDAPS name (landing-zone DNS default)", "CHG-2003"),
        ("B2", "Binding", "Role `backup-target`", "the target environment has no backup target", "CHG-2017"),
        ("B3", "Binding", "Consumer `legacy-rptuser`", "no target firewall rule for the unowned legacy account", None),
        ("B4", "Binding", "Consumer `mro-batch-export`", "no target firewall rule for the MRO export", "CHG-2001"),
        ("B5", "Consumer", "Consumer `legacy-rptuser`", "legacy account: unknown status, no owner, no TLS", None),
        ("B6", "Consumer", "Consumer `mro-batch-export`", "MRO export only 'identified', not tested", None),
        ("B7", "Consumer", "Consumer `supplier-portal-svc`", "supplier portal only 'contacted', not tested", None),
        ("B8", "Key", "`disk-encryption` must be kept in an HSM", "the target's disk key is software-protected", None),
        ("B9", "IDM", "Connector `hrdb` has withheld credentials but no credential role",
         "imported HR database connector names no secret", "CHG-2005"),
        ("B10", "IDM", "Connector `ldap` has withheld credentials but no credential role",
         "imported directory connector names no secret", "CHG-2005"),
        ("B11", "PingFederate", "Data store `grant-store` has withheld credentials but no credential role",
         "imported grant database store names no secret", "CHG-2005"),
        ("B12", "PingFederate", "Data store `user-directory` has withheld credentials but no credential role",
         "imported directory data store names no secret", "CHG-2005"),
        ("B13", "Binding", "Role `pf-cluster-discovery`",
         "the target binds no PingFederate cluster discovery: the nodes' tcp.xml uses S3 on AWS; on AKS the "
         "chart's DNS_PING through the cluster service is what to record", None),
        ("B14", "PingFederate", "Notification publisher `smtp` has withheld credentials but no credential role",
         "imported SMTP publisher names no secret", "CHG-2005"),
        ("B15", "PingFederate", "CAPTCHA provider `recaptcha` has withheld credentials but no credential role",
         "imported CAPTCHA provider names no secret", "CHG-2005"),
        ("B16", "Mail", "Sender `noreply@example-aero.test`: target/prod's sending identity for example-aero.test isn't "
         "DKIM-verified", "the target's Communication Services domain isn't DKIM-verified yet: reset mail lands in spam",
         None),
        ("B17", "Binding", "Role `audit-events` is bound in source/prod but not in target/prod",
         "no bus carries the identity audit stream in the target", None),
        ("B18", "Binding", "Role `alarm-disk-free` is bound in source/prod but not in target/prod",
         "the target doesn't run the disk-space alarm CloudWatch runs (nobody described it: A36)", None),
        ("B19", "Logs", "Log route `audit-logs` must keep logs 400 days; target/prod's `audit-logs` keeps them 90",
         "the target's audit workspace keeps logs 90 days, short of the 400-day obligation", None),
        ("B20", "Binding", "Role `identity-idm` is bound in source/prod but not in target/prod",
         "the target doesn't bind the IDM role the source runs (nobody records what acts as it: A39)", None),
        ("B21", "Binding", "Role `forwarder-corp.example-aero.internal` is bound in source/prod but not in target/prod",
         "the source forwards the AD domain to the domain controllers; nothing in the target does", "CHG-2015"),
        ("B22", "Binding", "Role `acl-ds` is bound in source/prod but not in target/prod",
         "the source's network ACL on the directory subnet has no counterpart in the target (Azure has none: its "
         "NSGs do that work); decide, and record why", None),
        ("B23", "PingFederate", "Data store `corp-directory` has withheld credentials but no credential role",
         "imported corporate directory store names no secret", "CHG-2005"),
        ("B24", "Volumes", "Volume `volume-ds-data` is 500 GB in source/prod but 256 GB in target/prod",
         "the target's directory data volume came from a sandbox template: what PingDS keeps doesn't fit", "CHG-2018"),
        ("B25", "Binding", "Role `snapshots-daily` is bound in source/prod but not in target/prod",
         "the target binds no snapshot policy (the volume check says what it loses: A72)", "CHG-2019"),
        ("B26", "Binding", "Role `backup-daily` is bound in source/prod but not in target/prod",
         "the target runs no AWS Backup-like plan for the directory's data (its cost is the platform team's to "
         "approve)", None),
        ("B27", "Binding", "Role `backup-vault` is bound in source/prod but not in target/prod",
         "the target has no backup vault", "CHG-2019"),
        ("B28", "Binding", "Role `config-history` is bound in source/prod but not in target/prod",
         "the source's AWS Config history bucket has no counterpart: the target keeps Azure's own change history "
         "(CHG-2024) and exports none (A88)", None),
        ("B29", "Binding", "Role `config-recording` is bound in source/prod but not in target/prod",
         "the target records no configuration history", "CHG-2024"),
        ("B30", "Security",
         "source/prod runs config-recording (config, exporting its history) and target/prod runs none",
         "the source records every resource change with AWS Config and exports the history; the target records none "
         "(Azure keeps its own for 14 days: CHG-2024 records it)", "CHG-2024"),
        ("B31", "Binding", "Role `budget` is bound in source/prod but not in target/prod",
         "the target has no budget", "CHG-2028"),
        ("B32", "Binding", "Role `security-incidents` is bound in source/prod but not in target/prod",
         "the target has no incident channel: GuardDuty pages the source's", "CHG-2029"),
        ("B34", "Exceptions", "Exception `EXC-2026-02` for target/prod is approved with no expiry",
         "the target's risk acceptance (no container scanning until PingGateway moves) was approved without an expiry",
         "CHG-2030"),
        ("B35", "Authorization", "nist-800-53-r5:SC-12 is the customer's under `F1209051525` and was covered by "
         "`AGENCYAMAZONEW`", "AWS covers key management (SC-12) for production; on Azure it is the customer's and "
         "nothing records how it is met", "CHG-2032"),
        ("B36", "Authorization", "target/prod uses Azure Communication Services (mail-sending), which `F1209051525` "
         "doesn't list in its boundary", "the target sends mail through Azure Communication Services, which Microsoft's "
         "compliance-scope tables don't list; a blocker once the target must rely on FedRAMP Moderate (DFARS) (accepted "
         "by EXC-2026-04 once CHG-2033 approves it: shown as accepted, not counted)", "CHG-2033", "CHG-2029"),
        ("B37", "Authorization", "target/prod uses DNS Private Resolver", "the target's forwarder to the corporate AD "
         "(CHG-2015) runs on the DNS Private Resolver, which Microsoft's compliance-scope tables don't list (CHG-2033 "
         "moves it to the landing zone's DNS servers, virtual machines)", "CHG-2033", "CHG-2015"),
        ("B38", "Data discovery", "source/prod runs data discovery (macie-backups, over backup-target) and target/prod "
         "runs none", "production's Macie examines the directory backups for sensitive data (CUI markings, employee "
         "numbers); the target runs no data discovery, a blocker once it is held to FedRAMP Moderate (DFARS)",
         "CHG-2034", "CHG-2029"),
        ("B39", "Binding", "Role `data-discovery` is bound in source/prod but not in target/prod",
         "the target has no data discovery binding: Macie examines the source's backups", "CHG-2034"),
        ("B33", "Incident reporting", "source/prod is held to reporting obligation `dfars-7012` and target/prod isn't",
         "production is held to DFARS 252.204-7012 (72-hour reporting on DIBNet); the target to no reporting "
         "obligation", "CHG-2029"),
        # the target runs AM, IDM, PingGateway and PingFederate on AKS (compute)
        ("B40", "Job", "Job `pf-engine-pf-audit-ship` runs on servers of role `pf-engine`, which target/prod runs on "
         "Kubernetes", "the audit shipping cron runs on the engines' servers; on AKS it must become a CronJob", None),
        ("B41", "Ports", "target/prod: `ds` listens on tcp 1636 (PingIDM connector ldap) for `idm`",
         "IDM moves to AKS: no firewall rule admits the cluster's nodes to the directory (a fix admits them)", None),
    ],
    "actions": [
        ("A1", "Certificate", "`skyline-air-idp-signing`", "partner cert expires 2026-11-02", None),
        ("A2", "Certificate", "`supplier-portal-sp-signing`", "SP cert expires 2026-11-30", None),
        ("A3", "Certificate", "`ds-ldaps-2026`", "LDAPS cert expires 2026-12-20", None),
        ("A4", "Certificate", "`sso-tls-2026`", "SSO TLS cert expires within 30 days after cutover", None),
        ("A5", "Allowlist", "`skyline-air-ingress`", "partner allowlist pins our old egress IP", None),
        ("A6", "Allowlist", "`mro-dc-egress-to-ldaps`", "consumer firewall pins our old LDAPS IP", None),
        ("A7", "Allowlist", "`supplier-portal-egress-sg`", "consumer security group pins our old LDAPS IP", None),
        ("A8", "Drift", "ds-2: missing on server: `cn=mail", "mail index missing on ds-2 (INC-2231)", None),
        ("A9", "Drift", "ds-3: not declared (unrecorded change): `cn=description", "unrecorded index on ds-3", None),
        ("A10", "Drift", "ds-3: differs: `cn=customers", "lockout threshold changed on ds-3", None),
        ("A11", "Access", "ACI `aci-legacy-all`", "ACI with no owner or justification", None),
        ("A12", "Key", "Copy `pf-signing-key`", "signing key must be carried over, not recorded as carried over", None),
        ("A13", "Key", "`pf-admin-password` loses automatic rotation", "target secret has no rotation function", None),
        ("A14", "Key", "`disk-encryption` loses automatic rotation and replicas",
         "target disk key neither rotates nor replicates", None),
        ("A15", "IDM", "Connector `hrdb` reaches a fixed host", "HR database reached at the same host everywhere", None),
        ("A16", "Gateway", "Route `partner-portal` sends requests to a fixed backend",
         "the partner portal application is reached at the same host everywhere", None),
        ("A17", "Hard-coded", "`opt/scripts/nightly-export.sh` on ds-2 holds source/prod values",
         "the MRO export script names ds-1 by hostname and address", None),
        ("A18", "Hard-coded", "`etc/hosts` on pf-engine-1 holds source/prod values",
         "PingFederate's engine pins ds-1's address in /etc/hosts", None),
        ("A19", "Hard-coded", "`apps/customer-portal/application.properties` holds source/prod values",
         "the portal names the LDAPS service, which the target renames (B1)", "CHG-2003"),
        ("A20", "Databases", "Database `pf-grants-db` has high availability in source/prod but not",
         "the target's grant database has no zone-redundant standby: it fails with its zone", None),
        ("A21", "PingFederate", "Data store `user-directory` reaches a fixed host",
         "PingFederate's LDAP data store lists ds-1 by hostname next to the LDAPS service", None),
        ("A22", "Job", "Job `ds-nightly-export` has no owner", "the MRO nightly export on ds-2's cron nobody owns",
         "CHG-2011"),
        ("A23", "Job", "Job `github-actions-ciam-ops-directory-backup` has no owner",
         "the nightly directory backup pipeline nobody owns", "CHG-2011"),
        ("A24", "Job", "Job `pf-engine-pf-audit-ship` has no owner",
         "the PingFederate engines' audit shipping timer nobody owns", "CHG-2011"),
        ("A25", "Host", "Servers of role `ds` pin 1 name(s) in /etc/hosts",
         "ds-2 pins the legacy reports host to its address", None),
        ("A26", "Host", "Servers of role `pf-engine` trust 1 certificate(s)",
         "the engines' truststore adds the corporate root CA, which the record lacks", "CHG-2013"),
        ("A27", "Host", "Servers of role `pf-admin` trust 1 certificate(s)",
         "the admin node's truststore adds it too", "CHG-2013"),
        ("A28", "Workload", "Role `pf-engine` moves from servers in source/prod to Kubernetes in target/prod",
         "the target runs PingFederate's engines on AKS: what their host baseline adds goes into the image", None),
        ("A29", "Mail", "Sender `noreply@example-aero.test`: target/prod's DMARC policy for example-aero.test is "
         "quarantine", "the target's DMARC policy is weaker than the source's reject", None),
        ("A30", "Data", "24 password value(s) in source/prod are hashed with SSHA512",
         "customers migrated from the old portal, and the legacy reports account, still hold salted SHA-512 hashes; "
         "every declared policy stores PBKDF2", None),
        ("A31", "Data", "attribute(s) in source/prod's user data have no ou=user-schema record",
         "a CRM integration nobody recorded writes crmContactId on suppliers; cn has no PII class either", None),
        ("A32", "Data", "1 member DN(s) of source/prod's groups name entries that don't exist",
         "the supplier approvers group still lists a supplier deleted last year", None),
        ("A33", "Data", "37 entries in source/prod hold challenge questions (KBA)",
         "customers registered before 2022 still hold challenge answers", None),
        ("A34", "Alert", "Alert rule `login-failures` names no runbook",
         "the login-failures rule pages without saying what to do", None),
        ("A35", "Logs", "Log route `audit-logs` is under legal hold",
         "the audit logs are under legal hold: the source's log group must outlive decommissioning", None),
        ("A36", "Monitoring", "source/prod runs alarm `ds-disk-free`",
         "CloudWatch runs a disk-space alarm no recorded rule describes", None),
        ("A37", "Access", "Principal `break-glass-root`: break-glass: last tested 2025-11-03",
         "the break-glass procedure was last exercised over 180 days ago", None),
        ("A38", "Access", "Principal `ciam-admins`: review overdue",
         "the platform admins' access review is over a year old", None),
        ("A39", "Access", "source/prod runs identity `identity-idm`",
         "the source runs an IDM role nobody records as acting as it", None),
        ("A40", "Access", "Operators come into source/prod by session",
         "operators reach the target's servers by a bastion; nothing records a session manager there", None),
        ("A41", "Access", "identity `identity-ds` is granted `s3:* on *`",
         "the source's directory role may do anything in S3, wider than writing its backups", None),
        ("A42", "Access", "whether identity `identity-admins` may `manage pf-admin-password` can't be told",
         "the target's admins hold Key Vault Administrator only as PIM-eligible", None),
        ("A43", "Access", "whether identity `identity-admins` may `manage-key disk-encryption` can't be told",
         "the same eligible assignment covers the disk key", None),
        ("A44", "Guardrail", "guardrail `org-guardrails` prevents `audit-log-disable`",
         "the target's policy assignments don't stop audit logs being disabled (a request to the landing zone team)",
         None),
        ("A45", "Edge", "source/prod runs `stickiness source-ip` in front of `ig-service`",
         "the gateway's source load balancer keeps clients on one server by source address, which no policy states",
         None),
        ("A46", "Edge", "Clients can send header `X-Partner-User` themselves",
         "the gateway doesn't strip the partner user header from incoming requests", None),
        ("A47", "Edge", "`am-service` changes from TLS passthrough",
         "login moves to a TLS-terminating gateway: PingAM must trust its X-Forwarded-For", None),
        ("A48", "Edge", "`pf-sso-service` changes from TLS passthrough",
         "sso moves to a TLS-terminating gateway: PingFederate must trust its X-Forwarded-For", None),
        ("A49", "DNS", "Lower the TTL of `apps.example-aero.test`", "the corporate DNS team's 3600 s TTL", None),
        ("A50", "DNS", "Lower the TTL of `login.example-aero.test`", "the corporate DNS team's 3600 s TTL", None),
        ("A51", "DNS", "Lower the TTL of `sso.example-aero.test`", "the corporate DNS team's 3600 s TTL", None),
        ("A52", "DNS", "corporate-dns runs zone `example-aero.test`: ask them to point `apps.example-aero.test`",
         "the public zone is on the corporate DNS team's Infoblox (a request drafted to them)", None),
        ("A53", "DNS", "corporate-dns runs zone `example-aero.test`: ask them to point `login.example-aero.test`",
         "the same zone", None),
        ("A54", "DNS", "corporate-dns runs zone `example-aero.test`: ask them to point `sso.example-aero.test`",
         "the same zone", None),
        ("A55", "DNS", "source/prod has private zone `id.example-aero.test`",
         "the target publishes LDAPS in the landing zone's default private zone (B1)", "CHG-2003"),
        ("A56", "Edge", "sets no rate limit on password-reset",
         "PingFederate's self-service password reset has no rate limit; the policy limits sign-in and tokens", None),
        ("A57", "Endpoint services", "Consumer `supplier-portal-svc` connects to `ldaps-link` privately",
         "the supplier portal reaches LDAPS through the source's endpoint service; the target's has another name",
         None),
        ("A58", "Endpoint services", "source/prod allows `arn:aws:iam::444455556666:root` to connect to `ldaps-link`",
         "the target's Private Link Service allows the portal's Azure subscription, not its AWS account", None),
        ("A59", "Egress", "doesn't allow `email-smtp.us-east-1.amazonaws.com`",
         "the hub firewall in the target doesn't allow the mail relay the platform sends through", None),
        *((f"A{60 + i}", "Egress proxy", f"so `{role}` must be told",
           f"the target's outside traffic goes through the hub's forward proxy; {what}", None)
          for i, (role, what) in enumerate((
              ("am", "PingAM's HTTP client and JVM options don't name it"),
              ("pf-engine", "the engines' captured run.properties lacks the proxy keys (a fix links them)"),
              ("pf-admin", "the admin node's run.properties and revocation checking don't name it"),
              ("ig", "PingGateway's ProxyOptions and JVM options don't name it"),
              ("idm", "PingIDM's boot.properties and JVM options don't name it")))),
        ("A65", "Flow logs", "`flow-vnet` keeps flow logs 14 days in target/prod",
         "the target's flow log (still to be built by the network team) keeps 14 days; the source keeps 30", None),
        ("A66", "Egress", "no route sends internet egress through `egress-firewall`",
         "the target's route table sends internet traffic straight to the NAT gateway, around the hub firewall whose "
         "domain rules the stack relies on", None),
        ("A67", "PingFederate", "Data store `corp-directory` reaches a fixed host",
         "PingFederate's corporate directory store lists two domain controllers, the same from every environment "
         "(its fix records both, in order, as one role's hosts)", None),
        ("A68", "Databases", "Database `pf-grants-db` keeps backups 14 days in source/prod but 7",
         "the target's grant database keeps backups 7 days where the source keeps 14", "CHG-2016"),
        ("A69", "Databases", "Database `pf-grants-db` has deletion protection in source/prod but not",
         "nothing stops the target's grant database being deleted by mistake (no lock)", "CHG-2016"),
        ("A70", "Object stores", "Object store `backup-target` locks objects (compliance 35 days) in source/prod",
         "the target's backup container (CHG-2017) has no immutability policy: a backup can be deleted early", None,
         "CHG-2017"),
        ("A71", "Object stores", "Object store `backup-target` is copied to",
         "nothing copies the target's backups to another region; the source replicates to us-west-2", None,
         "CHG-2017"),
        ("A73", "Restore tests", "Before cutover, restore `volume-ds-data`'s data in target/prod",
         "nothing shows the target can recover the directory's data: it has no restore test (the source's passed in "
         "August)", None),
        ("A72", "Volumes", "Volume `volume-ds-data` is snapshotted by `snapshots-daily`",
         "the target snapshots nothing of the directory's data volume (on Azure that is a disk backup plan in a "
         "Backup vault)", "CHG-2019"),
        ("A74", "Backups", "Role `volume-ds-data` is backed up by `backup-daily`",
         "nothing backs the target's directory data volume up", "CHG-2019"),
        ("A75", "Volumes", "Snapshot policy `snapshots-daily` copies each snapshot to us-west-2 in source/prod",
         "the target's disk backup (CHG-2019) keeps snapshots in its own region: Azure disk backup can't copy them",
         None, "CHG-2019"),
        ("A76", "Disaster recovery", "Recovery objective `directory-data` allows `volume-ds-data` to lose 60 minutes "
         "of changes; in target/prod", "nothing keeps the target's directory data outside its region: no standby "
         "replicates from it, and its disk backup (CHG-2019) stays in eastus2 (Azure disk backup can't copy)", None),
        ("A77", "Disaster recovery", "standby/prod stands by for source/prod",
         "the warm standby on Google Cloud still stands by for production on AWS: after cutover nothing stands by "
         "for the target (the fix re-points it)", None),
        ("A78", "Disaster recovery", "Recovery objective `directory-data` wants `volume-ds-data` back within 120 "
         "minutes; in target/prod", "nothing shows how fast the target recovers the directory's data (once CHG-2019 "
         "backs it up, the restore-test check asks for the test instead: A73)", "CHG-2019"),
        ("A79", "Tags", "Tag `DataClassification` (tag rule data-classification) has no value in target/prod",
         "the target environment records no data classification, so its resources would go without the tag policy's "
         "DataClassification tag", None),
        ("A80", "Regions", "The region catalog holds no aws regions, so source/prod's region us-east-1",
         "the record holds no region list from AWS yet (a provider prerequisite: `opsdir prerequisites`), so the "
         "source's region can't be checked against the provider's list", "CHG-2020"),
        ("A81", "Regions", "The region catalog holds no azure regions, so target/prod's region eastus2",
         "the record holds no region list from Azure yet, so the target's region can't be checked against the "
         "provider's list", "CHG-2021"),
        ("A82", "Audit", "source/prod's audit trails record data-write activity and target/prod's don't",
         "the source's CloudTrail logs S3 data writes; the target's Activity Log export records control-plane activity "
         "only (Azure logs data access per resource, in each resource's own diagnostic settings)", None),
        ("A83", "Audit", "target/prod's only by an immutable store whose policy a privileged user can lift",
         "the source's CloudTrail log files are validated (signed digests) and kept under Object Lock; the target's "
         "Activity Log container has an unlocked immutability policy, which a privileged user can lift: lock it",
         None),
        ("A84", "Object stores", "Object store `audit-archive` locks objects (compliance 400 days) in source/prod",
         "the same unlocked policy, seen as an object store: the fix locks the target's container (compliance)",
         None),
        ("A85", "Databases", "Database `pf-grants-db` copies its backups to us-west-2 in source/prod",
         "the source replicates the grant database's automated backups to us-west-2; the target's Flexible Server "
         "has no geo-redundant backup, so losing its region loses the backups (the fix asks for the region; Azure "
         "copies to the region's pair)", None),
        ("A86", "Security", "source/prod's threat-detection watches containers and target/prod's doesn't",
         "GuardDuty's EKS protection watches the source's containers; the target's Defender for Cloud runs no "
         "Defender for Containers plan", None),
        ("A90", "Security", "source/prod's vulnerability-scanning watches containers and target/prod's doesn't",
         "Inspector scans the source's container images; without Defender for Containers nothing scans the target's "
         "registry (accepted by EXC-2026-02 once CHG-2030 gives it an expiry: shown as accepted, not counted)",
         "CHG-2030"),
        ("A87", "Security", "source/prod is assessed against nist-800-171-r2 and target/prod isn't",
         "Security Hub assesses the source against NIST SP 800-171 Rev. 2 (CUI); the target's Defender CSPM against "
         "NIST SP 800-53 Rev. 5 only", None),
        ("A88", "Security",
         "source/prod exports its configuration history and target/prod keeps it in the service only",
         "AWS Config delivers the source's history to a bucket; Azure's change history (CHG-2024) stays in Resource "
         "Graph", None, "CHG-2024"),
        ("A89", "Security", "source/prod keeps its config-recording records 2557 days and target/prod 14 days",
         "the source keeps seven years of configuration history; Azure keeps 14 days (CHG-2024)", None, "CHG-2024"),
        ("A91", "Budgets", "source/prod has a budget (monthly-spend: 25000 USD monthly) and target/prod none",
         "the source's spending is held to an AWS Budgets budget; the target was set up without one", "CHG-2028"),
        ("A92", "Quotas", "target/prod's quota limits (azure account 00000000-0000-0000-0000-000000000000 in eastus2) "
         "aren't fetched", "the record holds no quota limits from Azure yet (a provider prerequisite: `opsdir "
         "prerequisites`), so the target's needs can't be checked against them", "CHG-2026"),
        ("A93", "Quotas", "`vcpus` on azure account 00000000-0000-0000-0000-000000000000 in eastus2 is limited to 50 "
         "and its environments need 96: decide",
         "the target's region grants 50 vCPUs where its servers need 96; the fix offers the operator's decision "
         "(request 96, a value of their own, or deny)", "CHG-2028", "CHG-2026"),
        ("A94", "Quotas", "has no `database-instances` quota, which target/prod needs 2 of",
         "Azure reports no usage limit on database servers (raised by a support request): confirm it with Microsoft",
         None, "CHG-2026"),
        ("A95", "Quotas", "96 is requested (rendered where the cloud takes requests)",
         "the operator approved the vCPU increase (CHG-2028); the planner waits for the quotas to be fetched again "
         "once Microsoft grants it", None, "CHG-2028"),
        ("A96", "Incident reporting", "source/prod's threat-detection sends high and worse findings to the incident "
         "process and target/prod's sends none",
         "GuardDuty pages the source's incident process on high findings; Defender pages no one (an action while the "
         "target is held to no obligation)", "CHG-2029"),
        ("A97", "Exceptions", "source/prod's exception `EXC-2026-01` (false-positive: aws:securityhub:IAM.6) doesn't "
         "carry to target/prod", "production's Security Hub IAM.6 false positive is the source's exception: the target "
         "decides for itself", None),
        ("A98", "POA&M", "POA&M item `POAM-2026-001` is open against cmmc-l2, which target/prod is assessed against",
         "PingDS's LDAPS isn't on a FIPS-validated provider yet (SC.L2-3.13.11, allowed on the POA&M at 3 points)", None),
        ("A99", "POA&M", "Close out `CMMC-2026`'s POA&M by 2027-02-11",
         "the CMMC Level 2 assessment is Conditional since 2026-08-15: its POA&M closes out within 180 days", None),
        ("A100", "Authorization", "target/prod uses Azure Communication Services (mail-sending), which `F1209051525` "
         "doesn't list in its boundary", "an action while nothing requires the target to rely on an authorization (it "
         "becomes B36 once CHG-2029 holds the target to DFARS)", "CHG-2029"),
        ("A101", "Authorization", "source/prod is inside system boundary `SSP-CIAM-2026` and target/prod in none",
         "the system security plan covers production and the standby, not the target", "CHG-2032"),
        ("A102", "Data discovery", "source/prod runs data discovery (macie-backups, over backup-target) and target/prod "
         "runs none", "an action while nothing requires the target to rely on an authorization (it becomes B38 once "
         "CHG-2029 holds the target to DFARS)", "CHG-2029"),
        ("A103", "Key", "Copy `pf-signing-key-password`", "the password protecting the carried-over signing key's PKCS#12 "
         "file must be carried over with it (PingFederate imports the file with it)", None),
        # the target runs AM, IDM, PingGateway and PingFederate on AKS (compute)
        ("A104", "Workload", "Role `am` moves from servers in source/prod to Kubernetes in target/prod",
         "the target runs AM on AKS: what its host baseline adds goes into the image", None),
        ("A105", "Workload", "Role `idm` moves from servers in source/prod to Kubernetes in target/prod",
         "the target runs IDM on AKS: what its host baseline adds goes into the image", None),
        ("A106", "Workload", "Role `ig` moves from servers in source/prod to Kubernetes in target/prod",
         "the target runs PingGateway on AKS: what its host baseline adds goes into the image", None),
        ("A107", "Workload", "Role `pf-admin` moves from servers in source/prod to Kubernetes in target/prod",
         "the target runs PingFederate's admin console on AKS: what its host baseline adds goes into the image", None),
        ("A108", "ForgeOps", "ForgeOps in target/prod (namespace `ciam`) reads Secret `am-env-secrets`",
         "AM's own secrets (encryption, session and OIDC keys) are recorded for none", None),
        ("A109", "ForgeOps", "ForgeOps in target/prod (namespace `ciam`) reads Secret `ds-env-secrets`",
         "AM's CTS and application store passwords aren't recorded", None),
        ("A110", "ForgeOps", "ForgeOps in target/prod (namespace `ciam`) reads Secret `amster-env-secrets`",
         "the IDM clients AM registers have no recorded secrets", None),
        ("A111", "ForgeOps", "ForgeOps in target/prod (namespace `ciam`) reads Secret `ds-passwords`",
         "the DS monitor password isn't recorded", None),
        ("A112", "ForgeOps", "ForgeOps in target/prod (namespace `ciam`) reads Secret `keystore-create`",
         "the AM/IDM keystore password isn't recorded", None),
        ("A113", "ForgeOps", "ForgeOps in target/prod (namespace `ciam`) reads Secret `amster`",
         "amster's SSH key pair (made by Helm, not by Kustomize) isn't recorded", None),
        ("A114", "ForgeOps", "ForgeOps in target/prod (namespace `ciam`) reads Secret `ds-ssl-keypair`",
         "the CA that signed the DS servers' certificates isn't recorded: AM and IDM can't trust them", None),
        ("A115", "PingFederate on Kubernetes",
         "PingFederate workload `pf-admin` in target/prod (namespace `ciam`) has no license",
         "no PingFederate license is recorded for the admin console on AKS", None),
        ("A116", "PingFederate on Kubernetes",
         "PingFederate workload `pf-engine` in target/prod (namespace `ciam`) has no license",
         "no PingFederate license is recorded for the engines on AKS", None),
        ("A117", "Ports", "target/prod: firewall rules open ports no installed product listens on: `fw-pf-cluster`",
         "PingFederate's cluster rules stay behind for servers that moved to AKS (a fix closes them)", None),
    ],
})

KEYS = ("id", "area", "match", "planted", "cleared_by", "raised_by")


def expected_findings():
    """The data/expected-findings.json document."""
    return {"_comment": "Generated by scripts/gen-synthetic.py: the problems planted in the synthetic data.",
            **{kind: [dict(zip(KEYS, row)) for row in rows] for kind, rows in EXPECTED.items()}}
