"""A server role's host baseline in an environment (the core compute domain's ciamHostBaseline: those that
apply in the environment, merged) as the variables the host-config playbook reads: what the record states as intent
(kernel settings, limits, transparent huge pages, FIPS and SELinux modes, the certificates the truststore adds, the
hardening profile) to apply, and what comes with installing the servers (OS, Java runtime, agents, service units) to
verify. What the record only observed (names pinned in /etc/hosts, search domains) is never applied: those are the
source's addresses. Pure."""
from opsdir.core.directory import get, one, rdn_of, values
from opsdir.domains.compute.hosts import baseline_for
from opsdir.domains.pki.pem import certificate_pem

HARDENING_PROFILES = ("disa-stig",)       # ciamHardeningProfile values this adapter applies


def _setting(v):
    name, _, value = v.partition("=")
    return {"name": name.strip(), "value": value.strip()}


def _limit(v):
    parts = v.split()
    return dict(zip(("domain", "type", "item", "value"), parts)) if len(parts) == 4 else None


def _unit(v):
    return v.split(":", 1)[0].strip()


def _trusted(d, b):
    """([{name, pem}], [names with no PEM recorded]) of the certificates a baseline's truststore adds."""
    certs = tuple((rdn_of(dn), certificate_pem(get(d, dn))) for dn in values(b, "ciamTrustsCertificate"))
    return ([{"name": n, "pem": pem} for n, pem in certs if pem],
            [*(n for n, pem in certs if not pem), *values(b, "ciamTrustedFingerprint")])


def baseline_vars(m, role):
    """The variables of a role's host baseline in environment m (those it records), or {} when none applies there."""
    d, b = m.d, baseline_for(m.d, role, m)
    if b is None:
        return {}
    trusted, unrecorded = _trusted(d, b)
    fips = one(b, "ciamFipsMode")
    found = {
        "ciam_os": one(b, "ciamOs"), "ciam_jdk": one(b, "ciamJdk"),
        "ciam_kernel_settings": [_setting(v) for v in values(b, "ciamKernelSetting") if "=" in v],
        "ciam_limits": [x for x in map(_limit, values(b, "ciamOsLimit")) if x],
        "ciam_transparent_hugepages": one(b, "ciamHugePages"),
        "ciam_fips_mode": None if fips is None else fips == "TRUE",
        "ciam_selinux_mode": one(b, "ciamSelinuxMode"),
        "ciam_trusted_certificates": trusted, "ciam_trusted_unrecorded": unrecorded,
        "ciam_host_agents": [{"package": v.split()[0], "recorded": v} for v in values(b, "ciamHostAgent")],
        "ciam_service_units": [_unit(v) for v in values(b, "ciamServiceUnit")],
        "ciam_hardening_profile": one(b, "ciamHardeningProfile")}
    return {k: v for k, v in found.items() if v not in (None, [], "")}
