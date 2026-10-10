"""A role's jobs, host firewall and product configuration files as the host-config playbook applies them: commands run
through /bin/sh with cron's and systemd's escapes, record text never templated, secrets never shown by --diff, files
that can't be deployed named; and the files other adapters render for the servers (agents' configuration), each
reloaded by its own command when it changes."""
from ansible_yaml import load, untagged_strings

from opsdir.connectors.registry import services
from opsdir.core.contract import HostFile
from opsdir_adapter_ansible.files import template
from opsdir_adapter_ansible.jobs import cron_command, exec_start, job_vars
from opsdir_adapter_ansible.render import render
from host_samples import host_config_model

CONFIG = (("ds", "/opt/ds/config/tools.properties", "ds/config/tools.properties",
           "port=4444\nbindPassword=${secret:aws-sm://ciam/ds-admin}\nraw={{ kept }} {% not jinja %}\n"),)


def _services():
    return services()._replace(deployable_config=lambda m: CONFIG)


def test_cron_and_timer_jobs_and_the_ones_not_deployed():
    _, alpha = host_config_model()
    assert job_vars(alpha, "ds") == {
        "ciam_cron_jobs": [
            {"name": "ds-nightly-export (1)", "job": "/opt/scripts/nightly-export.sh", "user": "ds", "minute": "30",
             "hour": "2", "day": "*", "month": "*", "weekday": "*"},
            {"name": "ds-nightly-export (2)", "job": "/opt/scripts/nightly-export.sh", "user": "ds",
             "special_time": "reboot"}],
        "ciam_timer_jobs": [{"unit": "opsdir-ds-audit-ship", "description": "ds-audit-ship (opsdir)",
                             "exec_start": '/bin/sh -c "/opt/scripts/ship-audit.sh --stamp \'{{.Time}}\' --day %%F"',
                             "user": "ds",
                             "schedule": ["OnCalendar=*:0/15"]}],
        "ciam_jobs_not_deployed": ["ds-rotate"]}


def test_the_roles_firewall_rules_and_files_in_its_group_vars():
    _, alpha = host_config_model()
    files = render(alpha, _services())
    ds = load(files["ansible/inventory/group_vars/ds.yml"])
    assert ds["ciam_firewall_rules"] == [
        'rule family="ipv4" source address="10.1.2.0/24" port port="1636" protocol="tcp" accept',
        'rule family="ipv6" source address="fd00::/64" port port="1636" protocol="tcp" accept']
    assert ds["ciam_config_files"] == [{"src": "ds/config/tools.properties.j2",
                                        "dest": "/opt/ds/config/tools.properties"}]
    assert "ciam_config_files" not in load(files["ansible/inventory/group_vars/web.yml"])


def test_a_template_keeps_the_text_and_reads_secrets_at_run_time():
    _, alpha = host_config_model()
    text = render(alpha, _services())["ansible/templates/ds/config/tools.properties.j2"]
    assert text == ('{% raw %}port=4444\nbindPassword={% endraw %}'
                    '{{ lookup("amazon.aws.secretsmanager_secret", "ciam/ds-admin") }}'
                    '{% raw %}\nraw={{ kept }} {% not jinja %}\n{% endraw %}')
    assert template(alpha, _services(), "") == ("", ())
    assert "amazon.aws" in render(alpha, _services())["ansible/requirements.yml"]


def test_the_playbook_tags():
    _, alpha = host_config_model()
    (play,) = load(render(alpha, _services())["ansible/host-config.yml"])
    tags = {t["name"]: t["tags"] for t in play["tasks"]}
    assert tags["Cron jobs"] == tags["Timer jobs enabled"] == ["jobs"]
    assert tags["Host firewall rules"] == ["firewall"] and tags["Product configuration files"] == ["files"]
    assert tags["Files other adapters render for the servers"] == ["host-files"]
    assert tags["Files not deployed"] == ["files", "host-files"]


def test_commands_run_through_the_shell_with_their_schedulers_escapes():
    command = 'tar czf "/backup/$(date +%F).tgz" /data && echo \\done | logger'
    assert cron_command(command) == 'tar czf "/backup/$(date +\\%F).tgz" /data && echo \\done | logger'
    assert exec_start(command) == '/bin/sh -c "tar czf \\"/backup/$$(date +%%F).tgz\\" /data && echo \\\\done | logger"'


def test_record_text_that_looks_like_jinja_is_never_templated():
    _, alpha = host_config_model()
    files = render(alpha, _services())
    assert [s for p, t in files.items() if "/inventory/" in p for s in untagged_strings(t)
            if any(j in s for j in ("{{", "{%", "{#"))] == []
    assert "exec_start: !unsafe " in files["ansible/inventory/group_vars/ds.yml"]
    assert "!unsafe" not in files["ansible/inventory/group_vars/all.yml"]      # plain text stays plain


def test_secrets_in_product_files_are_never_shown_and_what_cant_be_deployed_is_named():
    _, alpha = host_config_model()
    bad = (("ds", "/opt/ds/a.properties", "ds/a.properties", "x=${secret:nowhere://a/b}\n"),
           ("nobody", "/opt/x/b.properties", "x/b.properties", "y=1\n"))
    files = render(alpha, services()._replace(deployable_config=lambda m: CONFIG + bad))
    (play,) = load(files["ansible/host-config.yml"])
    by_name = {t["name"]: t for t in play["tasks"]}
    assert by_name["Product configuration files"]["diff"] is False
    assert load(files["ansible/inventory/group_vars/all.yml"])["ciam_config_files_not_deployed"] == [
        "/opt/ds/a.properties: secret references it can't read: nowhere://a/b",
        "/opt/x/b.properties: role nobody has no servers here"]
    assert "ansible/templates/ds/a.properties.j2" not in files and "ansible/templates/x/b.properties.j2" not in files
    assert play["hosts"] == "ciam_servers"

def test_only_the_jobs_and_agents_that_apply_in_the_environment():
    from host_samples import JOBS
    from network_fixtures import BETA, model
    from opsdir.domains.compute.naming import BASELINES
    scoped = (f"dn: cn=ds-beta-only,{JOBS}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamJob\n"
              f"cn: ds-beta-only\nciamJobKind: cron\nciamSchedule: @daily\nciamCommand: /opt/x.sh\nciamTargetRole: ds\n"
              f"ciamInEnvironment: {BETA}\n",
              f"dn: cn=ds-fake,{BASELINES}\nobjectClass: top\nobjectClass: ciamHostBaseline\ncn: ds-fake\n"
              "ciamTargetRole: ds\nciamOnProvider: fakecloud\nciamHostAgent: cloud-agent 2\n")
    from host_samples import DS, DS_JOBS
    from pki_samples import ca_records
    d, alpha, beta = model(tree=(*ca_records(), *DS, *DS_JOBS, *scoped))
    assert "ds-beta-only" not in str(job_vars(alpha, "ds")) and "ds-beta-only" in str(job_vars(beta, "ds"))
    assert [a["package"] for a in load(render(alpha, _services())["ansible/inventory/group_vars/ds.yml"])[
        "ciam_host_agents"]] == ["falcon-sensor", "cloud-agent"]


def test_the_recorded_time_sources_are_chronys():
    from network_fixtures import ALPHA, entry, model
    time = entry(ALPHA, "time", "ciamTimeSource", ciamBindingRole="time-source",
                 ciamTimeServer=("ntp1.example.test", "ntp2.example.test"), ciamTimeKind="ntp")
    _, alpha, _ = model(alpha=(time,))
    files = render(alpha, _services())
    assert load(files["ansible/inventory/group_vars/all.yml"])["ciam_time_sources"] == [
        "ntp1.example.test", "ntp2.example.test"]
    (play,) = load(files["ansible/host-config.yml"])
    tasks = {t["name"]: t for t in play["tasks"]}
    block = tasks["The recorded time sources"]
    assert block["tags"] == ["time"] and block["notify"] == "Restart time sync"
    assert block["ansible.builtin.blockinfile"]["block"] == (
        "{% for s in ciam_time_sources %}server {{ s }} iburst\n{% endfor %}")
    assert tasks["Only the recorded time sources (the distribution's default pools removed)"][
        "ansible.builtin.lineinfile"]["regexp"] == "^pool "
    _, bare, _ = model()
    assert "ciam_time_sources" not in load(render(bare, _services())["ansible/inventory/group_vars/all.yml"])


AGENT = HostFile("ds", "/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent.json", '{"logs": {"x": "{{ y }}"}}\n',
                 ("/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl", "-a", "fetch-config", "-m",
                  "ec2", "-s", "-c", "file:/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent.json"))


def test_other_adapters_files_are_placed_and_reloaded_when_they_change():
    _, alpha = host_config_model()
    nobody = HostFile("nobody", "/etc/x.yaml", "a: 1\n")
    files = render(alpha, _services()._replace(host_files=lambda m: (AGENT, nobody)))
    template_path = "ansible/templates/host-files/ds/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent.json.j2"
    assert files[template_path] == '{% raw %}{"logs": {"x": "{{ y }}"}}\n{% endraw %}'    # never templated
    assert load(files["ansible/inventory/group_vars/ds.yml"])["ciam_host_files"] == [
        {"src": "host-files/ds/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent.json.j2",
         "dest": "/opt/aws/amazon-cloudwatch-agent/etc/cloudwatch-agent.json", "mode": "0644",
         "reload": list(AGENT.reload)}]
    assert load(files["ansible/inventory/group_vars/all.yml"])["ciam_config_files_not_deployed"] == [
        "/etc/x.yaml: role nobody has no servers here"]
    (play,) = load(files["ansible/host-config.yml"])
    by_name = {t["name"]: t for t in play["tasks"]}
    written, reload = by_name["Files other adapters render for the servers"], by_name[
        "What reads a changed file takes it up"]
    assert written["register"] == "ciam_host_files_written" and written["diff"] is False
    assert reload["ansible.builtin.command"] == {"argv": "{{ item.item.reload }}"}      # no shell
    assert "selectattr('changed')" in reload["loop"]
    assert "ciam_host_files" not in load(render(alpha, _services())["ansible/inventory/group_vars/ds.yml"])


def test_a_file_for_some_of_a_roles_servers_goes_only_to_them():
    _, alpha = host_config_model()
    path = "/opt/aws/amazon-cloudwatch-agent/etc/opsdir-logs.json"
    first, second = (HostFile("ds", path, f'{{"root": "{root}"}}\n', hosts=(host,))
                     for root, host in (("/opt/ds", "ds-1"), ("/srv/ds", "ds-2")))
    files = render(alpha, _services()._replace(host_files=lambda m: (first, second)))
    assert files["ansible/templates/host-files/ds/ds-2/opt/aws/amazon-cloudwatch-agent/etc/opsdir-logs.json.j2"] == (
        '{% raw %}{"root": "/srv/ds"}\n{% endraw %}')
    assert load(files["ansible/inventory/group_vars/ds.yml"])["ciam_host_files"] == [
        {"src": f"host-files/ds/{h}{path}.j2", "dest": path, "mode": "0644", "hosts": [f"{h}.example.test"]}
        for h in ("ds-1", "ds-2")]
    (play,) = load(files["ansible/host-config.yml"])
    written = next(t for t in play["tasks"] if t["name"] == "Files other adapters render for the servers")
    assert written["when"] == "item.hosts is not defined or inventory_hostname in item.hosts"
