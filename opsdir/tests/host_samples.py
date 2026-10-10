"""A server role's host baseline using every attribute (intent, installation, observed) in the network fixtures'
estate, for the tests of what renders host configuration."""
from network_fixtures import model
from pki_samples import CERTIFICATES, ca_records

BASELINES = "ou=baselines,dc=ciam-ops"
DS = (f"dn: {BASELINES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: baselines\n",
      f"dn: cn=ds,{BASELINES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamHostBaseline\ncn: ds\n"
      "ciamTargetRole: ds\nciamOs: rhel 9.4\nciamJdk: temurin 17.0.11\nciamKernelSetting: net.core.somaxconn=4096\n"
      "ciamOsLimit: ds soft nofile 65536\nciamHugePages: never\nciamFipsMode: TRUE\nciamSelinuxMode: enforcing\n"
      f"ciamTrustsCertificate: cn=internal-ca,{CERTIFICATES}\nciamTrustedFingerprint: AB:CD\n"
      "ciamHostAgent: falcon-sensor 7.10.0\nciamServiceUnit: pingds.service: user ds, restart always\n"
      "ciamPinnedHost: 10.9.9.9 ldap.old.example\nciamSearchDomain: old.example\nciamHardeningProfile: disa-stig\n")


def baseline_model():
    """(directory, alpha model) of the network fixtures' estate with the ds role's baseline and its CA."""
    d, alpha, _ = model(tree=(*ca_records(), *DS))
    return d, alpha

JOBS = "ou=jobs,dc=ciam-ops"
DS_JOBS = (f"dn: {JOBS}\nobjectClass: top\nobjectClass: organizationalUnit\nou: jobs\n",
           f"dn: cn=ds-nightly-export,{JOBS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamJob\n"
           "cn: ds-nightly-export\nciamJobKind: cron\nciamSchedule: 30 2 * * *\nciamSchedule: @reboot\n"
           "ciamCommand: /opt/scripts/nightly-export.sh\nciamRunsAs: ds\nciamTargetRole: ds\n",
           f"dn: cn=ds-audit-ship,{JOBS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamJob\n"
           "cn: ds-audit-ship\nciamJobKind: timer\nciamSchedule: OnCalendar=*:0/15\n"
           "ciamCommand: /opt/scripts/ship-audit.sh --stamp '{{.Time}}' --day %F\nciamRunsAs: ds\nciamTargetRole: ds\n",
           f"dn: cn=ds-rotate,{JOBS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamJob\n"
           "cn: ds-rotate\nciamJobKind: cron\nciamSchedule: 0 3 * * 0\nciamTargetRole: ds\n")


def host_config_model():
    """(directory, alpha model): baseline_model's estate with the ds role's jobs and a firewall rule for it."""
    from network_fixtures import ALPHA, rule
    d, alpha, _ = model(alpha=(rule(ALPHA, "fw-ldaps", ("10.1.2.0/24", "fd00::/64"), "1636", "ds"),),
                        tree=(*ca_records(), *DS, *DS_JOBS))
    return d, alpha
