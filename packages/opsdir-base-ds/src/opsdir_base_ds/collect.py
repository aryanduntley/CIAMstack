"""Collectors of DS-lineage servers' configuration (`opsdir collect`, core.contract Collector), registered by each
product of the lineage with its own ldapsearch's option names: what the config and declared importers read, over
LDAP, read-only. Pure: the core runs the tool.

Where to read is the environment's collection sources for <product>/config (and <product>/declared):
ciamCollectionSource naming the directory servers' role and the administration connector's port (4444), or an
ldaps://host:port URL, with the bind DN (ciamLoginName) and the role of the binding referencing its password
(ciamCredentialRole). Each server's cn=config is searched with the product's own ldapsearch over LDAPS (`--useSsl`),
"(objectClass=*)" with all user and operational attributes, unwrapped; the password reaches the tool only on its
standard input (its password-file option reads /dev/stdin). The output becomes <host>/config/config.ldif, the layout
the config importer reads (one folder per server, named by its host); declared takes the first server's as
config.ldif.
Only the configuration in effect is read: the archived configurations are on disk only.

Before anything sees the output (the export, the evidence's hash, --save), the attributes that hold credentials are
dropped (holds_credential): password values (userPassword, authPassword, settings ending -password other than the
password policies' ds-cfg-password-* settings), key and trust store PINs (-pin) and secrets (-secret). The ldapsearch
to run and the truststore its server certificate is checked against are the operator's, given when collecting
(--ldapsearch PATH, --ldap-truststore PATH; else `ldapsearch` on the path and the JVM's trust store); neither is
stored."""
from functools import reduce
from urllib.parse import urlparse

from opsdir.core.contract import Collector, Command
from opsdir.domains.governance.collection import collection_sources

# the DS-lineage ldapsearch option names that differ between products
PINGDS_FLAGS = {"bind_dn": "--bindDn", "password_file": "--bindPassword:file", "ssl": "--useSsl",
                "base_dn": "--baseDn"}
OPENDJ_FLAGS = {"bind_dn": "--bindDN", "password_file": "--bindPasswordFile", "ssl": "--useSSL",
                "base_dn": "--baseDN"}
VALUES = ("userpassword", "authpassword")          # attributes whose values are passwords


def holds_credential(attribute):
    """Whether a configuration attribute's value is a credential: a password value (userPassword, authPassword, a
    setting ending -password other than the ds-cfg-password-* policy settings), a key or trust store PIN (-pin) or a
    secret (-secret)."""
    name = attribute.split(";", 1)[0].lower()
    return (name in VALUES or name.endswith(("-pin", "-secret"))
            or (name.endswith("-password") and not name.startswith("ds-cfg-password-")))


def without_credentials(ldif):
    """LDIF with every attribute that holds a credential left out (with its continuation lines)."""
    def keep(state, line):
        kept, dropping = state
        if line.startswith(" ") and dropping:
            return kept, True
        drop = ":" in line and not line.startswith(("#", " ")) and holds_credential(line.split(":", 1)[0])
        return (kept if drop else (*kept, line)), drop
    kept, _ = reduce(keep, ldif.splitlines(), ((), False))
    return "\n".join(kept) + ("\n" if ldif.endswith("\n") else "")


def _host_port(location):
    parsed = urlparse(location if "://" in location else f"ldaps://{location}")
    return parsed.hostname, str(parsed.port or 4444)


def _search(flags, host, port, source, options):
    tool = options.get("ldapsearch") or "ldapsearch"
    trust = options.get("ldap_truststore")
    return Command((tool, "--hostname", host, "--port", port, flags["ssl"],
                    *(("--trustStorePath", trust) if trust else ()),
                    flags["bind_dn"], source.login, flags["password_file"], "/dev/stdin",
                    flags["base_dn"], "cn=config", "--searchScope", "sub", "--wrapColumn", "0",
                    "(objectClass=*)", "*", "+"),
                   (source.credential,), lambda s: s[source.credential], keep=without_credentials)


def _sources(m, importer):
    return [s for s in collection_sources(m, importer) if s.locations and s.credential and s.login and not s.problems]


def _problems(importer):
    def problems(d, m, options):
        return tuple(p for s in collection_sources(m, importer) for p in (
            *s.problems, *(("collection source `{}`: no bind DN (ciamLoginName)".format(s.name),) if not s.login
                           else ()),
            *(("collection source `{}`: no credential (ciamCredentialRole)".format(s.name),)
              if not s.credential and not s.problems else ())))
    return problems


def config_collectors(product_name, flags):
    """The config and declared collectors of a product of the lineage, its ldapsearch's option names flags."""
    def config_steps(d, m, done, options):
        return tuple((f"{host}/config/config.ldif", _search(flags, host, port, s, options))
                     for s in _sources(m, f"{product_name}/config")
                     for host, port in (_host_port(loc) for loc in s.locations) if host)

    def declared_steps(d, m, done, options):
        first = next(iter(_sources(m, f"{product_name}/declared")), None)
        host, port = _host_port(first.locations[0]) if first else (None, None)
        return (("config.ldif", _search(flags, host, port, first, options)),) if host else ()
    return (Collector("config", "environment", config_steps, problems=_problems(f"{product_name}/config")),
            Collector("declared", "environment", declared_steps, problems=_problems(f"{product_name}/declared")))
