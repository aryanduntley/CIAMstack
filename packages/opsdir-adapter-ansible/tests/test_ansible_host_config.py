"""A role's jobs, host firewall and product configuration files as the host-config playbook applies them."""
import yaml

from opsdir.connectors.registry import services
from opsdir_adapter_ansible.files import template
from opsdir_adapter_ansible.jobs import job_vars
from opsdir_adapter_ansible.render import render
from host_samples import host_config_model

CONFIG = (("ds", "/opt/ds/config/tools.properties", "ds/config/tools.properties",
           "port=4444\nbindPassword=${secret:aws-sm://ciam/ds-admin}\nraw={{ kept }} {% not jinja %}\n"),)


def _services():
    return services()._replace(deployable_config=lambda m: CONFIG)


def test_cron_and_timer_jobs_and_the_ones_not_deployed():
    d, _ = host_config_model()
    assert job_vars(d, "ds") == {
        "ciam_cron_jobs": [
            {"name": "ds-nightly-export (1)", "job": "/opt/scripts/nightly-export.sh", "user": "ds", "minute": "30",
             "hour": "2", "day": "*", "month": "*", "weekday": "*"},
            {"name": "ds-nightly-export (2)", "job": "/opt/scripts/nightly-export.sh", "user": "ds",
             "special_time": "reboot"}],
        "ciam_timer_jobs": [{"unit": "opsdir-ds-audit-ship", "description": "ds-audit-ship (opsdir)",
                             "command": "/opt/scripts/ship-audit.sh", "user": "ds",
                             "schedule": ["OnCalendar=*:0/15"]}],
        "ciam_jobs_not_deployed": ["ds-rotate"]}


def test_the_roles_firewall_rules_and_files_in_its_group_vars():
    _, alpha = host_config_model()
    files = render(alpha, _services())
    ds = yaml.safe_load(files["ansible/inventory/group_vars/ds.yml"])
    assert ds["ciam_firewall_rules"] == [
        'rule family="ipv4" source address="10.1.2.0/24" port port="1636" protocol="tcp" accept',
        'rule family="ipv6" source address="fd00::/64" port port="1636" protocol="tcp" accept']
    assert ds["ciam_config_files"] == [{"src": "ds/config/tools.properties.j2",
                                        "dest": "/opt/ds/config/tools.properties"}]
    assert "ciam_config_files" not in yaml.safe_load(files["ansible/inventory/group_vars/web.yml"])


def test_a_template_keeps_the_text_and_reads_secrets_at_run_time():
    _, alpha = host_config_model()
    text = render(alpha, _services())["ansible/templates/ds/config/tools.properties.j2"]
    assert text == ('{% raw %}port=4444\nbindPassword={% endraw %}'
                    '{{ lookup("amazon.aws.aws_secret", "ciam/ds-admin") }}'
                    '{% raw %}\nraw={{ kept }} {% not jinja %}\n{% endraw %}')
    assert template(alpha, _services(), "") == ""
    assert "amazon.aws" in render(alpha, _services())["ansible/requirements.yml"]


def test_the_playbook_tags():
    _, alpha = host_config_model()
    (play,) = yaml.safe_load(render(alpha, _services())["ansible/host-config.yml"])
    tags = {t["name"]: t["tags"] for t in play["tasks"]}
    assert tags["Cron jobs"] == tags["Timer jobs enabled"] == ["jobs"]
    assert tags["Host firewall rules"] == ["firewall"] and tags["Product configuration files"] == ["files"]
