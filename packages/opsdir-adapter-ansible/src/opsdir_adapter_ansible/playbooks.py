"""The host-config playbook: the same for every environment, everything environment- or role-specific in the
inventory's variables (baseline.py). One play over the servers (group ciam_servers: never the appliances add-ons
list), by tag:

  baseline  (run by default) kernel settings (ansible.posix.sysctl into /etc/sysctl.d/90-ciam.conf), limits
            (community.general.pam_limits into /etc/security/limits.d/90-ciam.conf), transparent huge pages (a oneshot
            unit setting them at boot), SELinux mode (ansible.posix.selinux, targeted policy), FIPS mode (on Red Hat
            Enterprise Linux and its rebuilds 8 and 9 fips-mode-setup --enable, then a reboot the play names; 10 can't
            switch after installation, so it only checks: reinstall with fips=1; other systems are named, not
            changed), the certificates the truststore adds as system trust anchors (Red Hat
            update-ca-trust, Debian update-ca-certificates); a FIPS mode recorded off is never switched off
  stig      (run by default when the role's baseline names the disa-stig profile) Red Hat's DISA STIG role for the
            host's RHEL major version (RedHatOfficial.rhel<major>_stig, RHEL 8 to 10); other hosts are named
  jobs      (default) the role's cron jobs (ansible.builtin.cron) and timers (a oneshot service running the command
            through /bin/sh and its timer unit, opsdir-<job>, enabled); jobs whose command the record withholds are
            named
  time      (default) the environment's time servers (ciamTimeSource) as chrony's: chrony installed, the servers
            in a managed block of chrony.conf (the distribution's default pool lines removed: only the recorded
            sources), chronyd enabled, restarted when they change
  firewall  (default) the role's firewall rules as firewalld rich rules (ansible.posix.firewalld, permanent and
            immediate), firewalld enabled and running
  files     (default) the product configuration files the role receives, from their templates (secrets read at run
            time; never shown by --diff), to their deploy paths, mode 0640; files not deployed are named
  host-files (default) the files other adapters render for the role's servers (agents' configuration: the
            CloudWatch agent's, the Ops Agent's), from their templates to their paths with their modes (never shown by
            --diff), then each changed file's reload command (argv, no shell) so what reads it takes it up; nothing
            is installed: the agents come with the host's baseline
  verify    (only when asked: --tags verify) what installing the servers brings: the OS (os-release ID VERSION_ID),
            the agents' packages, the service units enabled
Pure."""
from .names import SERVERS

REBOOT = "reboot the host for it to take effect (this play doesn't reboot)"
THP_UNIT = "ciam-transparent-hugepages.service"
EL = "ansible_facts.distribution in ['RedHat', 'Rocky', 'AlmaLinux', 'CentOS', 'OracleLinux']"   # fips-mode-setup
STIG_HOSTS = ("ansible_facts.distribution == 'RedHat' and ansible_facts.distribution_major_version | int in [8, 9, 10]")
TRUST_DIR = ("{{ '/etc/pki/ca-trust/source/anchors' if ansible_facts.os_family == 'RedHat' "
             "else '/usr/local/share/ca-certificates' }}")


def _task(name, module, args, tags=("baseline",), **extra):
    return {"name": name, module: args, **extra, "tags": list(tags)}


def _thp_unit():
    mode = "{{ ciam_transparent_hugepages }}"
    path = "/sys/kernel/mm/transparent_hugepage"
    return (f"[Unit]\nDescription=Transparent huge pages {mode} (opsdir)\n\n[Service]\nType=oneshot\n"
            f"RemainAfterExit=yes\nExecStart=/bin/sh -c 'echo {mode} > {path}/enabled'\n"
            f"ExecStart=/bin/sh -c 'echo {mode} > {path}/defrag'\n\n[Install]\nWantedBy=basic.target\n")


def _baseline():
    has = "{} is defined"
    return [
        _task("Kernel settings", "ansible.posix.sysctl",
              {"name": "{{ item.name }}", "value": "{{ item.value }}", "sysctl_file": "/etc/sysctl.d/90-ciam.conf",
               "reload": True},
              loop="{{ ciam_kernel_settings | default([]) }}", loop_control={"label": "{{ item.name }}"}),
        _task("Resource limits", "community.general.pam_limits",
              {"domain": "{{ item.domain }}", "limit_type": "{{ item.type }}", "limit_item": "{{ item.item }}",
               "value": "{{ item.value }}", "dest": "/etc/security/limits.d/90-ciam.conf"},
              loop="{{ ciam_limits | default([]) }}",
              loop_control={"label": "{{ item.domain }} {{ item.type }} {{ item.item }}"}),
        _task("Transparent huge pages at boot", "ansible.builtin.copy",
              {"dest": f"/etc/systemd/system/{THP_UNIT}", "content": _thp_unit(), "mode": "0644"},
              when=has.format("ciam_transparent_hugepages"), notify="Apply transparent huge pages"),
        _task("Transparent huge pages unit enabled", "ansible.builtin.systemd_service",
              {"name": THP_UNIT, "enabled": True, "state": "started", "daemon_reload": True},
              when=has.format("ciam_transparent_hugepages")),
        _task("SELinux mode", "ansible.posix.selinux",
              {"policy": "targeted", "state": "{{ ciam_selinux_mode }}"},
              when=has.format("ciam_selinux_mode"), register="ciam_selinux"),
        _task("SELinux mode needs a reboot", "ansible.builtin.debug", {"msg": f"SELinux mode changed: {REBOOT}"},
              when="ciam_selinux is changed and (ciam_selinux.reboot_required | default(false))"),
        _task("FIPS mode now", "ansible.builtin.slurp", {"src": "/proc/sys/crypto/fips_enabled"},
              when="ciam_fips_mode | default(false)", register="ciam_fips_now"),
        _task("FIPS mode on (RHEL 8, 9)", "ansible.builtin.command", {"cmd": "fips-mode-setup --enable"},
              when=["ciam_fips_mode | default(false)", EL,
                    "ansible_facts.distribution_major_version | int in [8, 9]",
                    "(ciam_fips_now.content | b64decode | trim) != '1'"],
              changed_when=True, notify="FIPS mode needs a reboot"),
        _task("FIPS mode on (RHEL 10: chosen at installation)", "ansible.builtin.assert",
              {"that": "(ciam_fips_now.content | b64decode | trim) == '1'",
               "fail_msg": "RHEL 10 can't switch to FIPS mode after installation: reinstall with fips=1 on the kernel "
                           "command line"},
              when=["ciam_fips_mode | default(false)", EL,
                    "ansible_facts.distribution_major_version | int >= 10"]),
        _task("FIPS mode not set here", "ansible.builtin.debug",
              {"msg": "FIPS mode is recorded on, but this play sets it only on RHEL 8 and 9 (and their rebuilds); "
                      "{{ ansible_facts.distribution }} {{ ansible_facts.distribution_version }}: set it as its "
                      "vendor documents"},
              when=["ciam_fips_mode | default(false)",
                    f"not ({EL}) or ansible_facts.distribution_major_version | int < 8"]),
        _task("Certificates the truststore adds, as system trust anchors", "ansible.builtin.copy",
              {"dest": "{{ ciam_trust_dir }}/opsdir-{{ item.name }}.crt", "content": "{{ item.pem }}", "mode": "0644"},
              loop="{{ ciam_trusted_certificates | default([]) }}", loop_control={"label": "{{ item.name }}"},
              notify="Update the system trust store"),
        _task("Certificates with no PEM recorded", "ansible.builtin.debug",
              {"msg": "Not added (record their PEM, ciamCertificatePem): {{ ciam_trusted_unrecorded | join(', ') }}"},
              when="ciam_trusted_unrecorded | default([]) | length > 0")]


def _jobs():
    cron_fields = ("minute", "hour", "day", "month", "weekday", "special_time")
    service = ("[Unit]\nDescription={{ item.description }}\n\n[Service]\nType=oneshot\nUser={{ item.user }}\n"
               "ExecStart={{ item.exec_start }}\n")
    timer = ("[Unit]\nDescription={{ item.description }}\n\n[Timer]\n{{ item.schedule | join('\\n') }}\n\n"
             "[Install]\nWantedBy=timers.target\n")
    timers = {"loop": "{{ ciam_timer_jobs | default([]) }}", "loop_control": {"label": "{{ item.unit }}"}}
    return [
        _task("Cron jobs", "ansible.builtin.cron",
              {"name": "{{ item.name }}", "job": "{{ item.job }}", "user": "{{ item.user }}",
               **{f: f"{{{{ item.{f} | default(omit) }}}}" for f in cron_fields}},
              ("jobs",), loop="{{ ciam_cron_jobs | default([]) }}", loop_control={"label": "{{ item.name }}"}),
        _task("Timer jobs' services", "ansible.builtin.copy",
              {"dest": "/etc/systemd/system/{{ item.unit }}.service", "content": service, "mode": "0644"},
              ("jobs",), **timers),
        _task("Timer jobs' timers", "ansible.builtin.copy",
              {"dest": "/etc/systemd/system/{{ item.unit }}.timer", "content": timer, "mode": "0644"},
              ("jobs",), **timers),
        _task("Timer jobs enabled", "ansible.builtin.systemd_service",
              {"name": "{{ item.unit }}.timer", "enabled": True, "state": "started", "daemon_reload": True},
              ("jobs",), **timers),
        _task("Jobs not deployed", "ansible.builtin.debug",
              {"msg": "Their command isn't recorded (it held a secret): {{ ciam_jobs_not_deployed | join(', ') }}"},
              ("jobs",), when="ciam_jobs_not_deployed | default([]) | length > 0")]


CHRONY_CONF = "{{ '/etc/chrony.conf' if ansible_facts.os_family == 'RedHat' else '/etc/chrony/chrony.conf' }}"
CHRONYD = "{{ 'chronyd' if ansible_facts.os_family == 'RedHat' else 'chrony' }}"


def _time():
    tags, has = ("time",), "ciam_time_sources | default([]) | length > 0"
    return [
        _task("Time sync installed", "ansible.builtin.package", {"name": "chrony", "state": "present"}, tags,
              when=has),
        _task("Only the recorded time sources (the distribution's default pools removed)", "ansible.builtin.lineinfile",
              {"path": CHRONY_CONF, "regexp": "^pool ", "state": "absent"}, tags, when=has,
              notify="Restart time sync"),
        _task("The recorded time sources", "ansible.builtin.blockinfile",
              {"path": CHRONY_CONF, "marker": "# {mark} opsdir time sources",
               "block": "{% for s in ciam_time_sources %}server {{ s }} iburst\n{% endfor %}"}, tags, when=has,
              notify="Restart time sync"),
        _task("Time sync running", "ansible.builtin.systemd_service",
              {"name": CHRONYD, "enabled": True, "state": "started"}, tags, when=has)]


def _firewall():
    return [
        _task("Host firewall running", "ansible.builtin.systemd_service",
              {"name": "firewalld", "enabled": True, "state": "started"},
              ("firewall",), when="ciam_firewall_rules | default([]) | length > 0"),
        _task("Host firewall rules", "ansible.posix.firewalld",
              {"rich_rule": "{{ item }}", "permanent": True, "immediate": True, "state": "enabled"},
              ("firewall",), loop="{{ ciam_firewall_rules | default([]) }}")]


def _files():
    return [_task("Product configuration files", "ansible.builtin.template",
                  {"src": "{{ item.src }}", "dest": "{{ item.dest }}", "mode": "0640"},
                  ("files",), loop="{{ ciam_config_files | default([]) }}", loop_control={"label": "{{ item.dest }}"},
                  diff=False),
            _task("Files not deployed", "ansible.builtin.debug",
                  {"msg": "{{ ciam_config_files_not_deployed | join('; ') }}"},
                  ("files", "host-files"), when="ciam_config_files_not_deployed | default([]) | length > 0",
                  run_once=True)]


def _host_files():
    changed = ("{{ ciam_host_files_written.results | selectattr('changed') "
               "| selectattr('item.reload', 'defined') | list }}")
    return [_task("Files other adapters render for the servers", "ansible.builtin.template",
                  {"src": "{{ item.src }}", "dest": "{{ item.dest }}", "mode": "{{ item.mode }}"},
                  ("host-files",), loop="{{ ciam_host_files | default([]) }}",
                  loop_control={"label": "{{ item.dest }}"}, register="ciam_host_files_written", diff=False,
                  when="item.hosts is not defined or inventory_hostname in item.hosts"),
            _task("What reads a changed file takes it up", "ansible.builtin.command",
                  {"argv": "{{ item.item.reload }}"}, ("host-files",), loop=changed,
                  loop_control={"label": "{{ item.item.dest }}"}, changed_when=True)]


def _stig():
    return [_task("DISA STIG (Red Hat's role for this RHEL release)", "ansible.builtin.include_role",
                  {"name": "RedHatOfficial.rhel{{ ansible_facts.distribution_major_version }}_stig",
                   "apply": {"tags": ["stig"]}},
                  tags=("stig",), when=["ciam_hardening_profile | default('') == 'disa-stig'", STIG_HOSTS]),
            _task("DISA STIG not applied here", "ansible.builtin.debug",
                  {"msg": "The disa-stig profile is recorded, but its roles are Red Hat's, for RHEL 8 to 10: "
                          "{{ ansible_facts.distribution }} {{ ansible_facts.distribution_version }} isn't hardened"},
                  tags=("stig",), when=["ciam_hardening_profile | default('') == 'disa-stig'", f"not ({STIG_HOSTS})"])]


def _verify():
    tags = ("verify", "never")
    return [
        _task("OS release", "ansible.builtin.shell", {"cmd": '. /etc/os-release && echo "$ID $VERSION_ID"'}, tags,
              register="ciam_os_now", changed_when=False, check_mode=False, when="ciam_os is defined"),
        _task("OS as recorded", "ansible.builtin.assert",
              {"that": "ciam_os_now.stdout == ciam_os",
               "fail_msg": "runs {{ ciam_os_now.stdout }}; the record says {{ ciam_os }}"},
              tags, when="ciam_os is defined"),
        _task("Installed packages", "ansible.builtin.package_facts", {}, tags),
        _task("Agents installed", "ansible.builtin.assert",
              {"that": "item.package in ansible_facts.packages",
               "fail_msg": "agent {{ item.recorded }} isn't installed"},
              tags, loop="{{ ciam_host_agents | default([]) }}", loop_control={"label": "{{ item.package }}"}),
        _task("Services", "ansible.builtin.service_facts", {}, tags),
        _task("Service units enabled", "ansible.builtin.assert",
              {"that": "item in ansible_facts.services and ansible_facts.services[item].status == 'enabled'",
               "fail_msg": "service unit {{ item }} isn't enabled"},
              tags, loop="{{ ciam_service_units | default([]) }}")]


def host_config():
    """The host-config playbook (a list of plays)."""
    return [{"name": "Host baseline of each server role (opsdir)", "hosts": SERVERS, "become": True,
             "vars": {"ciam_trust_dir": TRUST_DIR},
             "tasks": [*_baseline(), *_stig(), *_jobs(), *_time(), *_firewall(), *_files(), *_host_files(),
                       *_verify()],
             "handlers": [
                 {"name": "Apply transparent huge pages", "ansible.builtin.systemd_service":
                  {"name": THP_UNIT, "state": "restarted", "daemon_reload": True}},
                 {"name": "Update the system trust store", "ansible.builtin.command":
                  {"cmd": "{{ 'update-ca-trust extract' if ansible_facts.os_family == 'RedHat' "
                          "else 'update-ca-certificates' }}"}, "changed_when": True},
                 {"name": "Restart time sync", "ansible.builtin.systemd_service":
                  {"name": CHRONYD, "state": "restarted"}},
                 {"name": "FIPS mode needs a reboot", "ansible.builtin.debug":
                  {"msg": f"FIPS mode enabled: {REBOOT}"}}]}]
