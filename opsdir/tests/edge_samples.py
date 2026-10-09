"""An estate whose service name sso terminates TLS (cookie stickiness, an HTTP health check, an idle timeout) with
a certificate the record holds as PEM, for the tests of the load-balancer add-ons."""
from opsdir.core.interchange.ldif import parse
from network_fixtures import ALPHA, entry, model
from pki_samples import CERTIFICATES, ca_records

POLICIES = "ou=edge-policies,dc=ciam-ops"
TERMINATE = (f"dn: {POLICIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: edge-policies\n",
             f"dn: cn=sso,{POLICIES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamTrafficPolicy\n"
             "cn: sso\nciamServiceRole: sso-service\nciamTlsMode: terminate\nciamStickiness: cookie\n"
             "ciamHealthProtocol: http\nciamHealthPath: /health\nciamIdleTimeoutSeconds: 120\n")
TLS = (f"dn: cn=svc-sso,ou=bindings,{ALPHA}\nchangetype: modify\nadd: ciamTlsCertificate\n"
       f"ciamTlsCertificate: cn=internal-ca,{CERTIFICATES}\n-\nadd: ciamFrontendIp\nciamFrontendIp: 10.1.9.10\n-\n",
       f"dn: cn=internal-ca,{CERTIFICATES}\nchangetype: modify\nadd: ciamKeyRole\nciamKeyRole: sso-tls-key\n-\n")
KEY = entry(ALPHA, "sso-key", "ciamSecretRef", ciamBindingRole="sso-tls-key", ciamRefUri="aws-sm://ciam/sso-tls-key")


def alpha_with_policy(*extra):
    """The alpha model of that estate with extra records."""
    _, alpha, _ = model(alpha=extra, tree=(*ca_records(), *TERMINATE), changes=tuple(r for t in TLS for r in parse(t)))
    return alpha

# The estate's DNS: a zone the platform runs (with the service name sso and two other records) and one a partner runs
DNS = (entry(ALPHA, "zone-example", "ciamDnsZoneBinding", ciamBindingRole="zone-example", ciamDnsZone="example.test",
             ciamZoneVisibility="private"),
       entry(ALPHA, "zone-partner", "ciamDnsZoneBinding", ciamBindingRole="zone-partner",
             ciamDnsZone="partner.example", ciamZoneVisibility="public",
             ciamManagedBy="cn=site-infra,ou=parties,dc=ciam-ops"),
       entry(ALPHA, "rec-verify", "ciamDnsRecord", ciamBindingRole="rec-verify", ciamRecordName="example.test",
             ciamRecordType="TXT", ciamRecordValue="v=opsdir1"),
       entry(ALPHA, "rec-mail", "ciamDnsRecord", ciamBindingRole="rec-mail", ciamRecordName="example.test",
             ciamRecordType="MX", ciamRecordValue="10 mail.example.test", ciamTtlSeconds="3600"),
       entry(ALPHA, "rec-partner", "ciamDnsRecord", ciamBindingRole="rec-partner", ciamRecordName="sso.partner.example",
             ciamRecordType="CNAME", ciamRecordValue="sso.example.test"))
PARTY = ("dn: ou=parties,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: parties\n",
         "dn: cn=site-infra,ou=parties,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: site-infra\n"
         "ciamOwnerKind: team\n")


def appliance(cn, stack_role, address, scope=None):
    """A ciamAppliance in alpha filling a stack role, its login secret (vault://secret/ciam/<cn>) bound beside it."""
    return (entry(ALPHA, cn, "ciamAppliance", ciamBindingRole=f"appliance-{cn}", ciamStackRole=stack_role,
                  ciamManagementAddress=address, ciamLoginName="opsdir", ciamLoginSecretRole=f"{cn}-login",
                  **({"ciamApplianceScope": scope} if scope else {})),
            entry(ALPHA, f"{cn}-login", "ciamSecretRef", ciamBindingRole=f"{cn}-login",
                  ciamRefUri=f"vault://secret/ciam/{cn}"))


def alpha_with_dns(*extra):
    """The alpha model of the policy estate with its DNS (zones, records) and extra records."""
    _, alpha, _ = model(alpha=(*DNS, *extra), tree=(*ca_records(), *TERMINATE, *PARTY),
                        changes=tuple(r for t in TLS for r in parse(t)))
    return alpha
