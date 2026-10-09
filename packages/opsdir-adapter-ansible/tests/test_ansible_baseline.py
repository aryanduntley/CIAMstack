"""A server role's host baseline as the variables the host-config playbook reads (intent applied, installation
verified, observed facts never applied), and the playbook itself."""
import yaml

from opsdir.connectors.registry import services
from opsdir_adapter_ansible.baseline import baseline_vars
from opsdir_adapter_ansible.render import render
from host_samples import baseline_model as _d
from pki_samples import CA_PEM


def test_the_baselines_intent_and_installation_checks():
    d, _ = _d()
    assert baseline_vars(d, "ds") == {
        "ciam_os": "rhel 9.4", "ciam_jdk": "temurin 17.0.11",
        "ciam_kernel_settings": [{"name": "net.core.somaxconn", "value": "4096"}],
        "ciam_limits": [{"domain": "ds", "type": "soft", "item": "nofile", "value": "65536"}],
        "ciam_transparent_hugepages": "never", "ciam_fips_mode": True, "ciam_selinux_mode": "enforcing",
        "ciam_trusted_certificates": [{"name": "internal-ca", "pem": CA_PEM}],
        "ciam_trusted_unrecorded": ["AB:CD"],
        "ciam_host_agents": [{"package": "falcon-sensor", "recorded": "falcon-sensor 7.10.0"}],
        "ciam_service_units": ["pingds.service"], "ciam_hardening_profile": "disa-stig"}
    assert baseline_vars(d, "web") == {}


def test_observed_facts_are_never_applied():
    d, alpha = _d()
    text = "".join(render(alpha, services()).values())
    assert "10.9.9.9" not in text and "old.example" not in text


def test_the_role_group_vars_carry_the_baseline():
    _, alpha = _d()
    files = render(alpha, services())
    ds = yaml.safe_load(files["ansible/inventory/group_vars/ds.yml"])
    assert ds["ciam_role"] == "ds" and ds["ciam_selinux_mode"] == "enforcing"
    assert yaml.safe_load(files["ansible/inventory/group_vars/web.yml"]) == {"ciam_role": "web"}


def test_the_host_config_playbook():
    _, alpha = _d()
    (play,) = yaml.safe_load(render(alpha, services())["ansible/host-config.yml"])
    assert (play["hosts"], play["become"]) == ("all", True)
    by_name = {t["name"]: t for t in play["tasks"]}
    assert by_name["Kernel settings"]["ansible.posix.sysctl"]["sysctl_file"] == "/etc/sysctl.d/90-ciam.conf"
    assert by_name["Resource limits"]["community.general.pam_limits"]["dest"] == "/etc/security/limits.d/90-ciam.conf"
    assert "fips-mode-setup --enable" == by_name["FIPS mode on (RHEL 8, 9)"]["ansible.builtin.command"]["cmd"]
    assert "ansible_facts.distribution_major_version | int >= 10" in \
        by_name["FIPS mode on (RHEL 10: chosen at installation)"]["when"]
    stig = by_name["DISA STIG (Red Hat's role for this RHEL release)"]
    assert stig["ansible.builtin.include_role"]["name"] == \
        "RedHatOfficial.rhel{{ ansible_facts.distribution_major_version }}_stig" and stig["tags"] == ["stig"]
    assert {t["name"] for t in play["tasks"] if "never" in t["tags"]} == {
        "OS release", "OS as recorded", "Installed packages", "Agents installed", "Services",
        "Service units enabled"}
    assert [h["name"] for h in play["handlers"]] == [
        "Apply transparent huge pages", "Update the system trust store", "FIPS mode needs a reboot"]
    assert by_name["FIPS mode on (RHEL 8, 9)"]["notify"] == "FIPS mode needs a reboot"
