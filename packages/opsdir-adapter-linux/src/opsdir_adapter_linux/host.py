"""A Linux server's own files read as host facts: what it runs beyond its product. Pure.

  etc/os-release                         the OS: ID and VERSION_ID (rhel 9.4)
  java/version.txt                       `java -version` output: the runtime's vendor and version
  java/cacerts.txt                       `keytool -list -cacerts` output (or -v): the truststore's entries. Entries
                                         whose alias carries [jdk] are the runtime's own (JDK 9+); the rest are added
  etc/security/limits.conf, limits.d/    resource limits: domain type item value
  etc/sysctl.d/*.conf, etc/sysctl.conf   kernel settings: name=value (later files win)
  sys/kernel/mm/transparent_hugepage/    transparent huge pages (always madvise [never])
    enabled
  proc/sys/crypto/fips_enabled           FIPS mode (1)
  etc/selinux/config                     SELINUX=
  packages.txt                           installed packages (`rpm -qa`, `rpm -qa --qf '%{NAME} %{VERSION}\\n'` or
                                         `dpkg-query -W`): the host agents among them
  etc/systemd/system/*.service           service units (not the ones timers start: those are jobs): user, restart
  etc/hosts                              names pinned to addresses (loopback and the server's own name left out)
  etc/resolv.conf                        search domains

A fact whose files aren't there is None (or not seen), so an import never clears what it wasn't given.
"""
import re
from functools import reduce
from types import MappingProxyType
from typing import NamedTuple, Optional

from opsdir.core.directory import fingerprint
from .cron import TIMERS, timer_services, unit_settings

HostFacts = NamedTuple("HostFacts", [("os", Optional[str]), ("jdk", Optional[str]), ("trusted", Optional[tuple]),
                                     ("limits", Optional[tuple]), ("kernel", Optional[tuple]),
                                     ("huge_pages", Optional[str]), ("fips", Optional[str]),
                                     ("selinux", Optional[str]), ("agents", Optional[tuple]),
                                     ("units", Optional[tuple]), ("pinned", Optional[tuple]),
                                     ("search", Optional[tuple]), ("notes", tuple)])

# package name -> what the agent is: the host agents opsdir recognizes among installed packages (names lowercased)
AGENTS = MappingProxyType({"falcon-sensor": "CrowdStrike Falcon", "nessusagent": "Tenable Nessus agent",
          "nessus-agent": "Tenable Nessus agent", "qualys-cloud-agent": "Qualys Cloud Agent",
          "splunkforwarder": "Splunk universal forwarder", "amazon-cloudwatch-agent": "Amazon CloudWatch agent",
          "amazon-ssm-agent": "AWS Systems Manager agent", "azuremonitoragent": "Azure Monitor agent",
          "walinuxagent": "Azure Linux agent", "google-guest-agent": "Google guest agent",
          "datadog-agent": "Datadog agent", "newrelic-infra": "New Relic infrastructure agent",
          "elastic-agent": "Elastic agent", "filebeat": "Filebeat", "fluent-bit": "Fluent Bit",
          "td-agent-bit": "Fluent Bit", "wazuh-agent": "Wazuh agent", "mdatp": "Microsoft Defender for Endpoint",
          "sentinelagent": "SentinelOne agent", "cortex-agent": "Cortex XDR agent", "osquery": "osquery"})
_NEVRA = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*)-(?P<release>[^-]+?)(?:\.(?:x86_64|aarch64|noarch|i686))?$")
_JDK_VENDORS = (("temurin", "temurin"), ("corretto", "corretto"), ("zulu", "zulu"), ("red_hat", "red hat"),
                ("redhat", "red hat"), ("microsoft", "microsoft"), ("semeru", "semeru"), ("graalvm", "graalvm"))
_LOOPBACK = re.compile(r"^(127\.|::1$|0\.0\.0\.0$|fe00::|ff0[0-2]::)")


def _lines(text):
    return [line.split("#", 1)[0].strip() for line in (text or "").splitlines() if line.split("#", 1)[0].strip()]


def os_name(text):
    """'ID VERSION_ID' of an os-release file (rhel 9.4), or None."""
    pairs = dict(line.split("=", 1) for line in _lines(text) if "=" in line)
    found = [pairs.get(k, "").strip('"') for k in ("ID", "VERSION_ID")]
    return " ".join(x for x in found if x) or None


def jdk(text):
    """'vendor version' of `java -version` output (temurin 17.0.11), or None."""
    version = re.search(r'version "([^"]+)"', text or "")
    if version is None:
        return None
    low = text.lower()
    vendor = next((v for marker, v in _JDK_VENDORS if marker in low),
                  "oracle" if low.startswith("java version") else "openjdk")
    return f"{vendor} {version.group(1)}"


def truststore(text):
    """(fingerprints of the entries the runtime doesn't ship, how many entries in all, whether any carry [jdk]) of
    keytool -list output (with or without -v)."""
    lines = [line.strip() for line in (text or "").splitlines()]
    alias = re.compile(r"^(?:Alias name:\s*)?(?P<alias>.+?)(?:,\s.*(?:trustedCertEntry|PrivateKeyEntry),?)?$")
    fp = re.compile(r"^(?:Certificate fingerprint \(SHA-256\)|SHA256):\s*(?P<fp>[0-9A-Fa-f:]+)$")

    def entries(acc, line):
        found, current = acc
        m = fp.match(line)
        if m:
            return (*found, (current, fingerprint(m.group("fp")))), None
        if line.startswith("Alias name:") or re.search(r"(trustedCertEntry|PrivateKeyEntry),?$", line):
            return found, alias.match(line).group("alias").strip()
        return acc
    pairs = reduce(entries, lines, ((), None))[0]
    shipped = [a for a, _ in pairs if a and a.endswith("[jdk]")]
    return tuple(f for a, f in pairs if not (a and a.endswith("[jdk]"))), len(pairs), bool(shipped)


def limits(texts):
    """'domain type item value' of every limit the files set, in file order."""
    return tuple(" ".join(parts) for t in texts for line in _lines(t) for parts in (line.split(),) if len(parts) == 4)


def kernel(texts):
    """'name=value' of every kernel setting, later files winning, sorted by name."""
    pairs = [(k.strip().replace("/", "."), v.strip()) for t in texts for line in _lines(t) if "=" in line
             for k, v in (line.split("=", 1),)]
    return tuple(f"{k}={v}" for k, v in sorted(dict(pairs).items()))


def huge_pages(text):
    m = re.search(r"\[(always|madvise|never)\]", text or "")
    return m.group(1) if m else None


def selinux(text):
    pairs = dict(line.split("=", 1) for line in _lines(text) if "=" in line)
    mode = pairs.get("SELINUX", "").strip().lower()
    return mode if mode in ("enforcing", "permissive", "disabled") else None


def _package(line):
    parts = line.split()
    if len(parts) >= 2:
        return parts[0], parts[1]
    m = _NEVRA.match(line)
    return (m.group("name"), m.group("version")) if m else (line, None)


def agents(text):
    """'name version' of every recognized host agent among the installed packages, sorted."""
    found = [_package(line) for line in _lines(text)]
    return tuple(sorted({f"{n} {v}" if v else n for n, v in found if n.lower() in AGENTS}))


def units(files):
    """'name: user U, restart R' of every service unit a timer doesn't start, sorted."""
    timed = timer_services(files)

    def unit(path, text):
        service = unit_settings(text).get("Service", {})
        facts = [f"user {service['User'][0]}" if service.get("User") else "user root",
                 *((f"restart {service['Restart'][0]}",) if service.get("Restart") else ())]
        return f"{path[len(TIMERS):]}: {', '.join(facts)}"
    return tuple(unit(p, t) for p, t in sorted(files.items())
                 if p.startswith(TIMERS) and p.endswith(".service") and "/" not in p[len(TIMERS):]
                 and p[len(TIMERS):] not in timed)


def pinned(text, own_names):
    """'address name ...' of each /etc/hosts line that pins a name other than loopback and the server's own."""
    own = {n.lower() for n in own_names if n}
    rows = [line.split() for line in _lines(text)]
    return tuple(" ".join(parts) for parts in rows if len(parts) >= 2 and not _LOOPBACK.match(parts[0])
                 and not {p.lower() for p in parts[1:]} <= own | {p.split(".", 1)[0] for p in own})


def search_domains(text):
    return tuple(d for line in _lines(text) for parts in (line.split(),) if parts[0] in ("search", "domain")
                 for d in parts[1:])


def _seen(files, *paths, prefix=None):
    return any(p in files for p in paths) or (prefix is not None and any(p.startswith(prefix) for p in files))


def host_facts(files, own_names=()):
    """HostFacts of one server's files ({path under /: text}); own_names: its hostname and record name."""
    limit_files = [files[p] for p in sorted(files) if p == "etc/security/limits.conf"
                   or (p.startswith("etc/security/limits.d/") and p.endswith(".conf"))]
    sysctl_files = [*(files[p] for p in sorted(files) if p.startswith("etc/sysctl.d/") and p.endswith(".conf")),
                    *((files["etc/sysctl.conf"],) if "etc/sysctl.conf" in files else ())]
    trusted, total, shipped = truststore(files["java/cacerts.txt"]) if "java/cacerts.txt" in files else ((), 0, True)
    fips = (files.get("proc/sys/crypto/fips_enabled") or "").strip()
    return HostFacts(
        os=os_name(files.get("etc/os-release")), jdk=jdk(files.get("java/version.txt")),
        trusted=(trusted if shipped else None) if "java/cacerts.txt" in files else None,
        limits=limits(limit_files) if limit_files else None, kernel=kernel(sysctl_files) if sysctl_files else None,
        huge_pages=huge_pages(files.get("sys/kernel/mm/transparent_hugepage/enabled")),
        fips={"1": "TRUE", "0": "FALSE"}.get(fips), selinux=selinux(files.get("etc/selinux/config")),
        agents=agents(files["packages.txt"]) if "packages.txt" in files else None,
        units=units(files) if _seen(files, prefix=TIMERS) else None,
        pinned=pinned(files["etc/hosts"], own_names) if "etc/hosts" in files else None,
        search=search_domains(files["etc/resolv.conf"]) if "etc/resolv.conf" in files else None,
        notes=(() if shipped else (f"java/cacerts.txt: none of its {total} entries carries [jdk], so what the "
                                   "truststore adds to the runtime's own can't be told (JDK 9+ marks its own); "
                                   "truststore not recorded",)))
