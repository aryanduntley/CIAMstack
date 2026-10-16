"""The template collector (`opsdir collect`, core.contract Collector): what adcs/inventory reads of the forest's
certificate templates (templates.ldif), from a domain controller over LDAPS, read-only. Pure: the core runs the search.

Where to read is the environment's collection source for adcs/inventory (ciamCollectionSource: ciamSourceRef
ldaps://<domain controller>:<port>/<forest root DN>, the bind DN or user principal name in ciamLoginName, the role of
the binding referencing its password in ciamCredentialRole). Any authenticated account is enough: templates are
readable by Authenticated Users, with Read Control on their security descriptor, by default (their actual ACLs
govern). One search with OpenLDAP's ldapsearch (core.ldap_source: a simple bind, the password only on standard input,
the CA certificate from --ldap-ca) of CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,
<forest root DN>, one level, unwrapped, the attributes the template reader reads (templates.py) and
nTSecurityDescriptor, asked for its owner, group and DACL only with the SD flags control (1.2.840.113556.1.4.801,
flags 7, critical): without it the directory asks for the SACL too, which an ordinary account can't read, and leaves
the descriptor out. The CAs' exports (ca/<name>.json) are the exporter's (scripts/Export-AdcsInventory.ps1): a
collection holds the templates only, and its import replaces the record's templates alone."""
from opsdir.core.contract import Collector
from opsdir.core.ldap_source import LDAP_CA, ldaps_parts, ldaps_source, ldaps_source_problems, ldapsearch_command
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "adcs/inventory"
TEMPLATES_BASE = "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{forest}"
# the SD flags control asking for the owner, group and DACL (BER SEQUENCE { INTEGER 7 }, base64), critical
SD_FLAGS = "!1.2.840.113556.1.4.801=::MAMCAQc="
ATTRIBUTES = ("objectClass", "cn", "displayName", "msPKI-Cert-Template-OID", "msPKI-Template-Schema-Version",
              "pKIExtendedKeyUsage", "msPKI-Certificate-Application-Policy", "pKIExpirationPeriod",
              "msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag", "msPKI-RA-Signature", "nTSecurityDescriptor")


def templates_steps(d, m, done, options):
    """The search of the first readable collection source's forest for its certificate templates, into
    templates.ldif."""
    s = ldaps_source(collection_sources(m, IMPORTER))
    if s is None:
        return ()
    base = TEMPLATES_BASE.format(forest=ldaps_parts(s.locations[0])[2])
    return (("templates.ldif",
             ldapsearch_command(s, base, ("-s", "one", "-o", "ldif-wrap=no", "-E", SD_FLAGS,
                                          "(objectClass=pKICertificateTemplate)", *ATTRIBUTES), options)),)


def problems(d, m, options):
    """Why the forest's templates can't be collected: a source's problems, no bind DN, credential or forest DN."""
    return ldaps_source_problems(collection_sources(m, IMPORTER))


COLLECTORS = (Collector("inventory", "environment", templates_steps, problems=problems, options=(LDAP_CA,)),)
