"""Linux servers' own files read as host baselines: one per server role, from every server of the role; what the
servers' Java truststore adds is linked to the certificates the record holds and named otherwise; values only some
servers have, and values that differ, are named; names pinned in /etc/hosts are kept; a fact no server gave is never
cleared; a re-import changes nothing and keeps what the record adds."""
from opsdir.connectors.importing import preview_import
from opsdir.core.directory import get, one, values
from opsdir.core.interchange.ldif import parse
from opsdir.domains.compute.naming import baseline_dn
from opsdir_adapter_linux.adapter import ADAPTER
from opsdir_adapter_linux.host import agents, jdk, kernel, pinned, truststore, units
import mini_estate
from support import REGISTRY, build_directory

ALPHA, BETA = ("env=prod,cloud=alpha,ou=environments,dc=ciam-ops", "env=prod,cloud=beta,ou=environments,dc=ciam-ops")
CA_FP = "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF"
NEW_FP = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"


def _server(env, cn, host):
    return (f"dn: cn={cn},{env}\nobjectClass: top\nobjectClass: ciamServer\ncn: {cn}\nciamServerRole: ds\n"
            f"ciamHostname: {host}\nciamSubnet: cn=net,ou=bindings,{env}\n")


RECORDS = "\n".join((
    _server(ALPHA, "ds-1", "ds-1.alpha.example.test"), _server(ALPHA, "ds-2", "ds-2.alpha.example.test"),
    _server(BETA, "ds-b1", "ds-b1.beta.example.test"),
    "dn: ou=certificates,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: certificates\n",
    "dn: cn=partner-root-ca,ou=certificates,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCertificate\n"
    f"cn: partner-root-ca\nciamFingerprint: {CA_FP.replace(':', '').lower()}\nciamNotAfter: 20300101000000Z\n"
    "ciamCertPurpose: ca\n",
    "dn: ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: organizationalUnit\nou: owners\n",
    "dn: cn=ops,ou=owners,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamParty\ncn: ops\nciamOwnerKind: team\n"))
CACERTS = ("Keystore type: JKS\nKeystore provider: SUN\n\nYour keystore contains 3 entries\n\n"
           "digicertglobalrootg2 [jdk], Aug 25, 2016, trustedCertEntry,\n"
           "Certificate fingerprint (SHA-256): CB:3C:CB:B7:60:31:E5:E0:13:8F:8D:D3:9A:23:F9:DE:47:FF:C3:5E:43:C1:14:4C\n"
           f"partner-root-ca, Jan 2, 2026, trustedCertEntry,\nCertificate fingerprint (SHA-256): {CA_FP}\n")
JAVA = ('openjdk version "17.0.11" 2024-04-16\nOpenJDK Runtime Environment Temurin-17.0.11+9 (build 17.0.11+9)\n'
        "OpenJDK 64-Bit Server VM Temurin-17.0.11+9 (build 17.0.11+9, mixed mode)\n")


def server(host, extra=None):
    base = {"etc/os-release": 'NAME="Red Hat Enterprise Linux"\nID="rhel"\nVERSION_ID="9.4"\n',
            "java/version.txt": JAVA, "java/cacerts.txt": CACERTS,
            "etc/security/limits.conf": "# limits\nds soft nofile 65536\nds hard nofile 65536\n",
            "etc/sysctl.conf": "net.core.somaxconn = 4096\n", "etc/sysctl.d/10-ds.conf": "net.ipv4.tcp_keepalive_time=600\n",
            "sys/kernel/mm/transparent_hugepage/enabled": "always madvise [never]\n",
            "proc/sys/crypto/fips_enabled": "0\n", "etc/selinux/config": "SELINUX=enforcing\nSELINUXTYPE=targeted\n",
            "packages.txt": "falcon-sensor-7.10.0-16303.el9.x86_64\nopenssl-3.0.7-27.el9.x86_64\n"
                            "splunkforwarder-9.2.1-78803f08aabb.x86_64\n",
            "etc/systemd/system/opendj.service": "[Service]\nUser=ds\nRestart=always\nExecStart=/opt/ds/bin/start-ds\n",
            "etc/systemd/system/backup.timer": "[Timer]\nOnCalendar=daily\n",
            "etc/systemd/system/backup.service": "[Service]\nExecStart=/opt/scripts/backup.sh\n",
            "etc/hosts": f"127.0.0.1 localhost\n::1 localhost\n10.1.2.10 {host} {host.split('.')[0]}\n",
            "etc/resolv.conf": "search alpha.example.test example.test\nnameserver 10.1.0.2\n"}
    return {f"{host}/{p}": t for p, t in {**base, **(extra or {})}.items()}


FILES = {**server("ds-1.alpha.example.test"),
         **server("ds-2.alpha.example.test", {
             "java/cacerts.txt": CACERTS + f"legacy-ca, Jan 2, 2020, trustedCertEntry,\n"
                                           f"Certificate fingerprint (SHA-256): {NEW_FP}\n",
             "etc/sysctl.conf": "net.core.somaxconn = 1024\n",
             "etc/hosts": "127.0.0.1 localhost\n10.9.9.9 legacy-db.internal legacy-db\n"}),
         **server("ds-b1.beta.example.test", {"java/version.txt": JAVA.replace("17.0.11", "17.0.12")}),
         "unknown.example.test/etc/os-release": "ID=rhel\n"}


def records():
    return tuple(parse(mini_estate.LDIF + "\n" + RECORDS))


def imported(changes=(), files=None):
    base = build_directory(REGISTRY, records(), changes)
    import_changes, notices = preview_import(base, "linux/baseline", files or FILES, (ADAPTER,))
    return build_directory(REGISTRY, records(), (*changes, *import_changes)), import_changes, notices


def test_one_baseline_per_role_from_its_servers():
    d, _, _ = imported()
    b = get(d, baseline_dn("ds"))
    assert (one(b, "ciamTargetRole"), one(b, "ciamOs"), one(b, "ciamJdk"), one(b, "ciamHugePages"),
            one(b, "ciamFipsMode"), one(b, "ciamSelinuxMode")) == \
        ("ds", "rhel 9.4", "temurin 17.0.11", "never", "FALSE", "enforcing")
    assert values(b, "ciamOsLimit") == ("ds soft nofile 65536", "ds hard nofile 65536")
    assert values(b, "ciamKernelSetting") == ("net.core.somaxconn=4096", "net.ipv4.tcp_keepalive_time=600")
    assert values(b, "ciamHostAgent") == ("falcon-sensor 7.10.0", "splunkforwarder 9.2.1")
    assert values(b, "ciamServiceUnit") == ("opendj.service: user ds, restart always",)    # backup is a timer's: a job
    assert values(b, "ciamFoundOn") == tuple(sorted((f"cn=ds-1,{ALPHA}", f"cn=ds-2,{ALPHA}", f"cn=ds-b1,{BETA}")))


def test_the_truststore_links_what_the_record_holds_and_names_the_rest():
    d, _, notices = imported()
    b = get(d, baseline_dn("ds"))
    assert values(b, "ciamTrustsCertificate") == ("cn=partner-root-ca,ou=certificates,dc=ciam-ops",)
    assert values(b, "ciamTrustedFingerprint") == (NEW_FP,)
    assert any("adds 1 certificate(s) the record holds no certificate for" in n for n in notices)
    assert any("truststore addition" in n and "is on ds-2 but not ds-1, ds-b1" in n for n in notices)


def test_differences_and_drift_are_named_and_pins_kept():
    d, _, notices = imported()
    b = get(d, baseline_dn("ds"))
    assert values(b, "ciamPinnedHost") == ("10.9.9.9 legacy-db.internal legacy-db",)
    assert values(b, "ciamSearchDomain") == ("alpha.example.test", "example.test")
    assert any("Java runtime differs between servers (ds-1: temurin 17.0.11; ds-b1: temurin 17.0.12)" in n
               for n in notices)
    assert "role ds: kernel setting 'net.core.somaxconn' differs between servers (ds-1: net.core.somaxconn=4096; " \
        "ds-2: net.core.somaxconn=1024; ds-b1: net.core.somaxconn=4096); recorded 'net.core.somaxconn=4096'" in notices
    assert any(n.startswith("unknown.example.test: no server") for n in notices)


def test_a_reimport_changes_nothing_and_keeps_the_owner_and_what_no_file_gave():
    owner = tuple(parse(f"dn: {baseline_dn('ds')}\nchangetype: modify\nadd: ciamOwner\n"
                        "ciamOwner: cn=ops,ou=owners,dc=ciam-ops\n-\n"))
    d, first, _ = imported()
    again, changes, _ = imported((*first, *owner))
    assert not changes
    partial = {p: t for p, t in FILES.items() if not p.endswith("java/version.txt")}
    d2, changes, _ = imported((*first, *owner), partial)
    b = get(d2, baseline_dn("ds"))
    assert one(b, "ciamJdk") == "temurin 17.0.11" and one(b, "ciamOwner") == "cn=ops,ou=owners,dc=ciam-ops"
    assert not changes


def test_the_parsers():
    assert jdk('java version "1.8.0_401"\nJava(TM) SE Runtime Environment') == "oracle 1.8.0_401"
    assert jdk('openjdk version "21.0.3" 2024-04-16 LTS\nOpenJDK Runtime Environment Corretto-21.0.3.9.1') == \
        "corretto 21.0.3"
    assert kernel(("a.b = 1\n", "a/b=2\nc.d=3\n")) == ("a.b=2", "c.d=3")
    assert agents("amazon-ssm-agent\t3.3.40.0\nbash 5.1\nWALinuxAgent-2.9.1.1-1.el9.noarch\n") == \
        ("WALinuxAgent 2.9.1.1", "amazon-ssm-agent 3.3.40.0")
    assert pinned("10.0.0.5 web-1.example.test web-1\n10.0.0.6 db\n", ("web-1.example.test",)) == ("10.0.0.6 db",)
    assert units({"etc/systemd/system/x.service": "[Service]\nUser=x\n",
                  "etc/systemd/system/x.service.d/override.conf": "[Service]\n"}) == ("x.service: user x",)
    verbose = "Alias name: mine\nCreation date: Jan 1, 2026\nSHA256: 01:02\n\nAlias name: theirs [jdk]\nSHA256: 03:04\n"
    assert truststore(verbose) == (("01:02",), 2, True)
    assert truststore("mine, Jan 1, 2026, trustedCertEntry,\nCertificate fingerprint (SHA-256): 0a:0b\n") == \
        (("0A:0B",), 1, False)
