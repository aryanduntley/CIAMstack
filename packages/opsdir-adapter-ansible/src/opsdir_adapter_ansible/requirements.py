"""What an Ansible run of the rendered files needs from Ansible Galaxy, pinned: each collection a rendered file names
(by its namespace.name prefix: a module, a lookup), and the hardening roles a baseline names. The same pins are what
opsdir/scripts/fetch-tools.sh installs for validation, so what is checked is what is rendered. Each version was
released at least two weeks before it was pinned (2026-10-09). Pure."""
COLLECTIONS = (                            # (name, version)
    ("ansible.posix", "2.2.2"),            # sysctl, selinux, firewalld
    ("community.general", "13.4.0"),       # pam_limits
    ("amazon.aws", "11.4.0"),              # secretsmanager_secret lookup
    ("azure.azcollection", "4.0.0"),       # azure_keyvault_secret lookup
    ("community.hashi_vault", "7.1.0"),    # vault_kv1_get / vault_kv2_get lookups
    ("kubernetes.core", "6.6.0"),          # k8s lookup
    ("ansible.netcommon", "8.7.1"),        # httpapi connection (appliances)
    ("f5networks.f5_bigip", "3.14.0"),     # bigip_as3_deploy (F5 add-on)
    ("ansible.windows", "3.8.0"),          # win_dns_record (Windows DNS add-on)
    ("infoblox.nios_modules", "1.10.0"),   # nios_*_record (Infoblox add-on)
    ("paloaltonetworks.panos", "3.4.2"))   # panos_* objects, rules, commits (Palo Alto add-on)
ROLES = tuple((f"RedHatOfficial.rhel{n}_stig", "0.1.82") for n in (8, 9, 10))   # the disa-stig profile


def requirements(texts, stig):
    """ansible/requirements.yml's content for rendered texts: the pinned collections they name, and the STIG roles
    when a baseline names the disa-stig profile (stig)."""
    text = "\n".join(texts)
    return {"collections": [{"name": n, "version": v} for n, v in COLLECTIONS if f"{n}." in text],
            **({"roles": [{"name": n, "version": v} for n, v in ROLES]} if stig else {})}


def all_requirements():
    """Every pinned collection and role (what validation installs)."""
    return {"collections": [{"name": n, "version": v} for n, v in COLLECTIONS],
            "roles": [{"name": n, "version": v} for n, v in ROLES]}
