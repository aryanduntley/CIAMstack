#!/usr/bin/env python3
"""Generate schema/ciam-ops.schema.ldif — the opsdir standard as RFC 4512 LDAP schema.

Edit the tables below, re-run, and commit the LDIF (the LDIF is the published artifact;
it can be loaded by opsdir or, with the X- extensions ignored, by an LDAP server).
"""
import pathlib
ARC = "1.3.6.1.4.1.32473.1"   # RFC 5612 documentation PEN; replace with a real arc
SYN = {"string": ".15", "int": ".27", "bool": ".7", "time": ".24", "dn": ".12", "extdn": ".12",
       "cidr": ".15", "ip": ".15", "fqdn": ".26", "url": ".26", "port": ".27", "ref-uri": ".26", "json": ".15"}
def syn(vt): return "1.3.6.1.4.1.1466.115.121.1" + SYN["string" if vt.startswith("enum:") else vt]
def eq(vt):
    return {"int": "integerMatch", "port": "integerMatch", "bool": "booleanMatch", "time": "generalizedTimeMatch",
            "dn": "distinguishedNameMatch", "extdn": "distinguishedNameMatch"}.get(vt, "caseIgnoreMatch")

STD = [  # standard attributes (real OIDs), portability assigned by this standard
 ("2.5.4.0", "objectClass", "string", "meta", False, "LDAP object classes"),
 ("2.5.4.3", "cn", "string", "meta", False, "Common name / RDN"),
 ("2.5.4.11", "ou", "string", "meta", False, "Organizational unit / RDN"),
 ("0.9.2342.19200300.100.1.25", "dc", "string", "meta", True, "Domain component / RDN"),
 ("2.5.4.13", "description", "string", "meta", False, "Free text"),
 ("0.9.2342.19200300.100.1.3", "mail", "string", "meta", False, "Contact email"),
]
# name, value-type, portability, single, desc
ATTRS = [
 # naming
 ("cloud", "string", "meta", True, "RDN of a cloud hosting environment"),
 ("env", "string", "meta", True, "RDN of a deployment stage within a cloud (prod/stage)"),
 ("snap", "string", "observed", True, "RDN of an observed configuration snapshot"),
 # governance / meta
 ("ciamOwner", "dn", "meta", False, "Owning party (team, partner, vendor)"),
 ("ciamLastChanged", "time", "meta", True, "Last change before this directory tracked history"),
 ("ciamChangeRef", "dn", "meta", False, "Change record(s) that justify this entry"),
 # environments
 ("ciamCloudProvider", "enum:aws|azure|onprem", "binding", True, "Cloud provider; selects the renderer"),
 ("ciamRegion", "string", "binding", True, "Provider region"),
 ("ciamCloudEnvironment", "enum:public|usgovernment", "binding", True, "Provider cloud (commercial vs government)"),
 ("ciamLifecycle", "enum:active|building|retiring|retired", "meta", True, "Lifecycle state"),
 ("ciamPlannedCutover", "time", "meta", True, "Planned cutover date for an environment being built"),
 ("ciamJoinsDeploymentOf", "dn", "intent", True, "DS replicas here join the replication deployment of that environment"),
 # servers
 ("ciamServerRole", "enum:ds|pf-engine|pf-admin", "intent", True, "What the server runs"),
 ("ciamProductVersion", "string", "intent", True, "Product and version"),
 ("ciamHostname", "fqdn", "binding", True, "Server hostname (never used by consumers)"),
 ("ciamPrivateIp", "ip", "binding", True, "Private IP address"),
 ("ciamZone", "string", "binding", True, "Availability zone"),
 ("ciamInstanceSize", "string", "binding", True, "Instance / VM size"),
 ("ciamImageRef", "string", "binding", True, "Machine image reference"),
 ("ciamSubnet", "dn", "binding", True, "Subnet binding the server is placed in"),
 # bindings
 ("ciamBindingRole", "string", "meta", True, "Abstract role this binding fulfils; migrations match roles across environments"),
 ("ciamProviderRef", "string", "binding", True, "Provider resource identifier (VPC id, vnet/subnet name, zone id, DES id)"),
 ("ciamResourceGroup", "string", "binding", True, "Azure resource group"),
 ("ciamCidr", "cidr", "binding", False, "Address range"),
 ("ciamFqdn", "fqdn", "contract", True, "Service DNS name consumers and partners use. Must stay stable across migrations"),
 ("ciamDnsZone", "fqdn", "binding", True, "DNS zone the service name is published in"),
 ("ciamDnsZoneRef", "string", "binding", True, "Provider id of the DNS zone"),
 ("ciamTargetRole", "enum:ds|pf-engine|pf-admin", "intent", True, "Server role a service or rule targets"),
 ("ciamPort", "port", "intent", False, "TCP/UDP port"),
 ("ciamFrontendIp", "ip", "binding", True, "Load balancer frontend IP"),
 ("ciamSourceCidr", "cidr", "binding", False, "Allowed source range"),
 ("ciamProtocol", "enum:tcp|udp", "intent", True, "Transport protocol"),
 ("ciamAllowsConsumer", "dn", "binding", False, "Consumer this firewall rule exists for"),
 ("ciamRulePriority", "int", "binding", True, "Provider rule priority (e.g. Azure NSG). Pinned so adding a rule never renumbers others"),
 ("ciamRefUri", "ref-uri", "secret-ref", True, "Reference to a secret or key in the environment's store. Never the value"),
 ("ciamInterconnectKind", "string", "binding", True, "Cross-environment link type (VPN, ExpressRoute, peering)"),
 ("ciamPeerEnvironment", "dn", "binding", True, "Environment at the other end of an interconnect"),
 ("ciamStorageRef", "string", "binding", True, "Backup storage location"),
 ("ciamRetentionDays", "int", "intent", True, "Retention period in days"),
 # external allowlists (held in consumer / partner systems)
 ("ciamManagedBy", "dn", "meta", True, "Party that operates the external allowlist"),
 ("ciamExternalSystem", "string", "meta", True, "Where the allowlist lives (partner firewall, app egress policy, SaaS IP list)"),
 ("ciamAllowlistDirection", "enum:consumer-egress|partner-ingress|partner-egress", "meta", True, "consumer-egress: their outbound rule to our service; partner-ingress: they allow our egress in; partner-egress: they send to us"),
 ("ciamRefersToRole", "string", "meta", True, "Binding role of OUR address this allowlist contains (resolved per environment)"),
 ("ciamRecordedCidr", "cidr", "observed", False, "Addresses the external allowlist contains today"),
 ("ciamLeadTimeDays", "int", "meta", True, "Typical lead time for the owner to change it"),
 ("ciamRequestStatus", "enum:not-needed|to-request|requested|done", "meta", True, "Status of the change request to the owner"),
 # directory config
 ("ciamBackendType", "string", "intent", True, "DS backend type"),
 ("ciamBaseDn", "extdn", "intent", True, "Base DN in the user directory"),
 ("ciamIndexedAttribute", "dn", "intent", True, "User-directory attribute record being indexed"),
 ("ciamIndexType", "enum:equality|presence|substring|ordering|approximate", "intent", False, "DS index type"),
 ("ciamStorageScheme", "string", "intent", True, "Password storage scheme"),
 ("ciamLockoutFailureCount", "int", "intent", True, "Failed binds before lockout"),
 ("ciamLockoutDuration", "string", "intent", True, "Lockout duration (DS duration syntax)"),
 ("ciamPasswordHistoryCount", "int", "intent", True, "Passwords remembered"),
 ("ciamMaxPasswordAge", "string", "intent", True, "Maximum password age (DS duration syntax)"),
 ("ciamEnabled", "bool", "intent", True, "Enabled flag"),
 ("ciamListenPort", "port", "intent", True, "Listener port"),
 ("ciamReplicaCount", "int", "intent", True, "DS replicas per environment"),
 ("ciamReplicationPurgeDelay", "string", "intent", True, "Replication changelog purge delay"),
 ("ciamServerRef", "dn", "observed", True, "Server a snapshot was captured from"),
 ("ciamCapturedAt", "time", "observed", True, "Snapshot capture time"),
 # user-directory attribute records
 ("ciamLdapName", "string", "intent", True, "Attribute name in the user directory"),
 ("ciamPiiClass", "enum:none|low|moderate|high", "intent", True, "Privacy classification"),
 ("ciamExportControlled", "bool", "intent", True, "Export-control relevant"),
 ("ciamPurpose", "string", "intent", True, "Why the attribute is stored"),
 ("ciamRetentionRule", "string", "intent", True, "Retention rule"),
 # consumers
 ("ciamBindDn", "extdn", "intent", True, "Bind DN in the user directory"),
 ("ciamObservedSource", "cidr", "observed", False, "Source addresses seen in access logs"),
 ("ciamOperationMix", "string", "observed", True, "Operation mix seen in access logs"),
 ("ciamSubtreeRead", "extdn", "observed", False, "Subtrees searched"),
 ("ciamAttrRead", "dn", "observed", False, "User-directory attribute records read"),
 ("ciamUnindexedSearchesPerDay", "int", "observed", True, "Unindexed searches per day"),
 ("ciamTlsOnly", "bool", "observed", True, "Only TLS connections seen"),
 ("ciamPeakOpsPerSec", "int", "observed", True, "Peak operations per second"),
 ("ciamFirstSeen", "time", "observed", True, "First seen in logs"),
 ("ciamLastSeen", "time", "observed", True, "Last seen in logs"),
 ("ciamCriticality", "enum:critical|high|medium|low", "meta", True, "Business criticality"),
 ("ciamMigrationStatus", "enum:unknown|identified|contacted|tested|cutover", "meta", True, "Migration readiness of a consumer"),
 # ACIs
 ("ciamAciTargetDn", "extdn", "intent", True, "Subtree the ACI is placed on"),
 ("ciamAciTargetAttr", "dn", "intent", False, "User-directory attribute records the ACI covers"),
 ("ciamAciAllAttributes", "bool", "intent", True, "ACI covers all attributes (targetattr=*)"),
 ("ciamAciRight", "enum:read|search|compare|write|add|delete|selfwrite|all", "intent", False, "Granted rights"),
 ("ciamAciGrantee", "dn", "intent", False, "Consumer(s) the ACI grants to"),
 ("ciamJustification", "string", "meta", True, "Why the access exists"),
 ("ciamReviewedOn", "time", "meta", True, "Last access review"),
 # integrations and claims
 ("ciamProtocolType", "enum:saml2-sp|oidc-client|saml2-idp|ldap", "intent", True, "Integration type"),
 ("ciamEntityId", "url", "contract", True, "SAML entity ID"),
 ("ciamAcsUrl", "url", "contract", True, "SAML assertion consumer service URL"),
 ("ciamRedirectUri", "url", "contract", False, "OIDC redirect URI"),
 ("ciamClientId", "string", "contract", True, "OIDC client id"),
 ("ciamGrantType", "enum:authorization_code|client_credentials|refresh_token", "intent", False, "OIDC grant types"),
 ("ciamPkceRequired", "bool", "intent", True, "PKCE required"),
 ("ciamPopulation", "enum:customers|suppliers|partners|individuals", "intent", False, "Identity populations served"),
 ("ciamMfaRequired", "bool", "intent", True, "MFA required"),
 ("ciamUsesCertificate", "dn", "intent", False, "Certificates this integration depends on"),
 ("ciamJitBaseDn", "extdn", "intent", True, "Where just-in-time provisioned partner users are created"),
 ("ciamClaimName", "string", "contract", True, "Claim / SAML attribute name the application receives"),
 ("ciamSourceAttribute", "dn", "intent", True, "User-directory attribute record the claim comes from"),
 ("ciamTransform", "string", "intent", True, "Transformation applied to the value"),
 # certificates
 ("ciamFingerprint", "string", "meta", True, "SHA-256 fingerprint"),
 ("ciamSubject", "string", "meta", True, "Certificate subject"),
 ("ciamIssuer", "string", "meta", True, "Certificate issuer"),
 ("ciamNotBefore", "time", "meta", True, "Valid from"),
 ("ciamNotAfter", "time", "meta", True, "Expires"),
 ("ciamCertPurpose", "enum:tls-server|saml-signing|saml-encryption|jwt-signing|partner-signing", "intent", True, "What the certificate is for"),
 ("ciamSubjectAltName", "fqdn", "contract", False, "DNS names the certificate is valid for"),
 ("ciamKeyRole", "string", "meta", True, "Binding role of the secret holding the private key (per environment)"),
 ("ciamPartnerContact", "dn", "meta", True, "Partner to coordinate rotation with"),
 ("ciamRotationRunbook", "dn", "meta", True, "Work instruction for rotation"),
 # runbooks, changes, incidents, parties
 ("ciamTitle", "string", "meta", True, "Title"),
 ("ciamVersion", "string", "meta", True, "Document version"),
 ("ciamAppliesTo", "dn", "meta", False, "Entries this work instruction depends on"),
 ("ciamLastValidated", "time", "meta", True, "When the work instruction was last validated against config"),
 ("ciamDocUrl", "url", "meta", True, "Document location"),
 ("ciamChangeStatus", "enum:proposed|approved|applied|rejected", "meta", True, "Change record status"),
 ("ciamApprovedBy", "string", "meta", True, "Approver (CAB)"),
 ("ciamPlannedAt", "time", "meta", True, "Planned implementation time"),
 ("ciamOpenedAt", "time", "meta", True, "Incident opened"),
 ("ciamSeverity", "enum:sev1|sev2|sev3|sev4", "meta", True, "Incident severity"),
 ("ciamInvolved", "dn", "meta", False, "Entries involved in the incident"),
 ("ciamRootCause", "string", "meta", True, "Root cause"),
 ("ciamOwnerKind", "enum:team|partner|vendor", "meta", True, "Kind of party"),
 ("ciamContactUrl", "url", "meta", True, "Contact / escalation link"),
]
CLASSES = [
 # name, sup, kind, must, may, desc
 ("ciamObject", "top", "ABSTRACT", [], ["description", "ciamOwner", "ciamLastChanged", "ciamChangeRef"], "Base of every operations-directory entry"),
 ("ciamCloud", "ciamObject", "STRUCTURAL", ["cloud", "ciamCloudProvider", "ciamRegion"], ["ciamCloudEnvironment", "ciamLifecycle"], "A cloud hosting environment"),
 ("ciamEnvironment", "ciamObject", "STRUCTURAL", ["env"], ["ciamLifecycle", "ciamPlannedCutover", "ciamJoinsDeploymentOf"], "A deployment stage within a cloud"),
 ("ciamServer", "ciamObject", "STRUCTURAL", ["cn", "ciamServerRole", "ciamHostname", "ciamSubnet"], ["ciamProductVersion", "ciamPrivateIp", "ciamZone", "ciamInstanceSize", "ciamImageRef"], "A server instance"),
 ("ciamBinding", "ciamObject", "ABSTRACT", ["cn", "ciamBindingRole"], ["ciamProviderRef"], "Environment-specific binding of an abstract role"),
 ("ciamNetwork", "ciamBinding", "STRUCTURAL", ["ciamCidr"], ["ciamResourceGroup"], "Network (VPC / VNet)"),
 ("ciamSubnetBinding", "ciamBinding", "STRUCTURAL", ["ciamCidr"], ["ciamZone"], "Subnet"),
 ("ciamServiceName", "ciamBinding", "STRUCTURAL", ["ciamFqdn", "ciamTargetRole", "ciamPort"], ["ciamDnsZone", "ciamDnsZoneRef", "ciamFrontendIp"], "Stable service name + load balancer"),
 ("ciamFirewallRule", "ciamBinding", "STRUCTURAL", ["ciamSourceCidr", "ciamPort", "ciamTargetRole"], ["ciamProtocol", "ciamAllowsConsumer", "ciamRulePriority"], "Inbound allow rule"),
 ("ciamSecretRef", "ciamBinding", "STRUCTURAL", ["ciamRefUri"], [], "Reference to a secret"),
 ("ciamKeyRef", "ciamBinding", "STRUCTURAL", ["ciamRefUri"], [], "Reference to an encryption key"),
 ("ciamEgress", "ciamBinding", "STRUCTURAL", ["ciamCidr"], [], "Outbound (NAT) addresses our services send from"),
 ("ciamExternalAllowlist", "ciamObject", "STRUCTURAL", ["cn", "ciamManagedBy", "ciamRefersToRole", "ciamRecordedCidr", "ciamAllowlistDirection"], ["ciamExternalSystem", "ciamLeadTimeDays", "ciamRequestStatus", "ciamAllowsConsumer"], "An allowlist in someone else's system that contains our addresses"),
 ("ciamBackupTarget", "ciamBinding", "STRUCTURAL", ["ciamStorageRef"], ["ciamRetentionDays"], "Backup destination"),
 ("ciamInterconnect", "ciamBinding", "STRUCTURAL", ["ciamInterconnectKind", "ciamPeerEnvironment", "ciamSourceCidr"], ["ciamPort"], "Link to another environment"),
 ("ciamBackend", "ciamObject", "STRUCTURAL", ["cn", "ciamBackendType", "ciamBaseDn"], [], "DS backend"),
 ("ciamIndex", "ciamObject", "STRUCTURAL", ["cn", "ciamIndexedAttribute", "ciamIndexType"], [], "DS backend index"),
 ("ciamPasswordPolicy", "ciamObject", "STRUCTURAL", ["cn", "ciamStorageScheme"], ["ciamLockoutFailureCount", "ciamLockoutDuration", "ciamPasswordHistoryCount", "ciamMaxPasswordAge", "ciamPopulation"], "Password policy"),
 ("ciamConnectionHandler", "ciamObject", "STRUCTURAL", ["cn", "ciamEnabled"], ["ciamListenPort"], "DS connection handler"),
 ("ciamLogPublisher", "ciamObject", "STRUCTURAL", ["cn", "ciamEnabled"], [], "DS log publisher"),
 ("ciamReplicationTopology", "ciamObject", "STRUCTURAL", ["cn", "ciamReplicaCount"], ["ciamReplicationPurgeDelay"], "Replication topology shape"),
 ("ciamSnapshot", "ciamObject", "STRUCTURAL", ["snap", "ciamServerRef", "ciamCapturedAt"], [], "Observed config snapshot of one server"),
 ("ciamUserAttribute", "ciamObject", "STRUCTURAL", ["cn", "ciamLdapName", "ciamPiiClass"], ["ciamExportControlled", "ciamPurpose", "ciamRetentionRule"], "Record describing a user-directory attribute"),
 ("ciamConsumer", "ciamObject", "STRUCTURAL", ["cn", "ciamBindDn"], ["ciamObservedSource", "ciamOperationMix", "ciamSubtreeRead", "ciamAttrRead", "ciamUnindexedSearchesPerDay", "ciamTlsOnly", "ciamPeakOpsPerSec", "ciamFirstSeen", "ciamLastSeen", "ciamCriticality", "ciamMigrationStatus"], "A client of the user directory"),
 ("ciamAci", "ciamObject", "STRUCTURAL", ["cn", "ciamAciTargetDn", "ciamAciRight", "ciamAciGrantee"], ["ciamAciTargetAttr", "ciamAciAllAttributes", "ciamJustification", "ciamReviewedOn"], "Access control instruction"),
 ("ciamIntegration", "ciamObject", "STRUCTURAL", ["cn", "ciamProtocolType"], ["ciamEntityId", "ciamAcsUrl", "ciamRedirectUri", "ciamClientId", "ciamGrantType", "ciamPkceRequired", "ciamPopulation", "ciamMfaRequired", "ciamUsesCertificate", "ciamJitBaseDn", "ciamCriticality"], "Application or partner integration"),
 ("ciamClaimMap", "ciamObject", "STRUCTURAL", ["cn", "ciamClaimName", "ciamSourceAttribute"], ["ciamTransform"], "One claim / SAML attribute mapping"),
 ("ciamCertificate", "ciamObject", "STRUCTURAL", ["cn", "ciamFingerprint", "ciamNotAfter", "ciamCertPurpose"], ["ciamSubject", "ciamIssuer", "ciamNotBefore", "ciamSubjectAltName", "ciamKeyRole", "ciamPartnerContact", "ciamRotationRunbook"], "Certificate (public facts only)"),
 ("ciamRunbook", "ciamObject", "STRUCTURAL", ["cn", "ciamTitle", "ciamLastValidated"], ["ciamVersion", "ciamAppliesTo", "ciamDocUrl"], "Work instruction"),
 ("ciamChange", "ciamObject", "STRUCTURAL", ["cn", "ciamTitle", "ciamChangeStatus"], ["ciamApprovedBy", "ciamPlannedAt"], "Change record (mirrored from ITSM)"),
 ("ciamIncident", "ciamObject", "STRUCTURAL", ["cn", "ciamTitle", "ciamOpenedAt"], ["ciamSeverity", "ciamInvolved", "ciamRootCause"], "Incident / postmortem"),
 ("ciamParty", "ciamObject", "STRUCTURAL", ["cn", "ciamOwnerKind"], ["mail", "ciamContactUrl"], "Team, partner or vendor"),
]
STD_CLASSES = [
 ("2.5.6.0", "top", None, "ABSTRACT", ["objectClass"], [], "Top of the class hierarchy"),
 ("2.5.6.5", "organizationalUnit", "top", "STRUCTURAL", ["ou"], ["description"], "Organizational unit"),
 ("0.9.2342.19200300.100.4.13", "domain", "top", "STRUCTURAL", ["dc"], ["description"], "Domain"),
]
def q(d): return d.replace('\\', '\\5C').replace("'", '\\27')
def lst(xs): return xs[0] if len(xs) == 1 else "( " + " $ ".join(xs) + " )"
def wrap(line, width=76):
    out, first = [], True
    while len(line) > width:
        out.append(line[:width]); line = " " + line[width:]
    out.append(line); return "\n".join(out)

lines = ["# Operations Directory schema (opsdir) — LDAP schema extended for platform configuration.",
         "# Standard RFC 4512 definitions. Extensions (legal per RFC 4512 §4.2):",
         "#   X-PORTABILITY  intent | contract | binding | secret-ref | observed | meta",
         "#   X-VALUE-TYPE   stricter value type enforced by the store (string, int, bool, time, dn, extdn,",
         "#                  cidr, ip, fqdn, url, port, ref-uri, json, enum:a|b|c)",
         "# OIDs use the RFC 5612 documentation arc 1.3.6.1.4.1.32473 as a placeholder.",
         "dn: cn=schema", "objectClass: top", "objectClass: ldapSubentry", "objectClass: subschema", "cn: schema"]
for oid, n, vt, port, sv, d in STD:
    lines.append(wrap(f"attributeTypes: ( {oid} NAME '{n}' DESC '{q(d)}' EQUALITY {eq(vt)} SYNTAX {syn(vt)}{' SINGLE-VALUE' if sv else ''} X-PORTABILITY '{port}' X-VALUE-TYPE '{vt}' X-ORIGIN 'RFC 4519' )"))
for i, (n, vt, port, sv, d) in enumerate(ATTRS, 1):
    lines.append(wrap(f"attributeTypes: ( {ARC}.1.{i} NAME '{n}' DESC '{q(d)}' EQUALITY {eq(vt)} SYNTAX {syn(vt)}{' SINGLE-VALUE' if sv else ''} X-PORTABILITY '{port}' X-VALUE-TYPE '{vt}' X-ORIGIN 'opsdir' )"))
for oid, n, sup, kind, must, may, d in STD_CLASSES:
    s = f"objectClasses: ( {oid} NAME '{n}' DESC '{q(d)}'" + (f" SUP {sup}" if sup else "") + f" {kind}"
    if must: s += f" MUST {lst(must)}"
    if may: s += f" MAY {lst(may)}"
    lines.append(wrap(s + " X-ORIGIN 'RFC 4519' )"))
for i, (n, sup, kind, must, may, d) in enumerate(CLASSES, 1):
    s = f"objectClasses: ( {ARC}.2.{i} NAME '{n}' DESC '{q(d)}' SUP {sup} {kind}"
    if must: s += f" MUST {lst(must)}"
    if may: s += f" MAY {lst(may)}"
    lines.append(wrap(s + " X-ORIGIN 'opsdir' )"))
open(pathlib.Path(__file__).resolve().parent.parent / "schema" / "ciam-ops.schema.ldif", "w").write("\n".join(lines) + "\n")
print(len(ATTRS), "attrs", len(CLASSES), "classes")
