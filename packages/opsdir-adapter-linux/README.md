# opsdir-adapter-linux

opsdir host adapter for Linux servers: what runs on the platform's servers beyond its products, read from the servers' own files. The hidden automation (cron entries and systemd timers) as jobs (the core `automation` domain), and each server role's host baseline (OS, Java runtime and the certificates its truststore adds, limits, kernel settings, huge pages, FIPS and SELinux modes, agents, service units, names pinned in `/etc/hosts`; the core `compute` domain).

**Applies to** environments that declare it in their stack (`kind: host`). It is declaration-only: it renders nothing yet. Its importers work whether or not an environment declares it.

**Depends on** `opsdir` (the automation, compute, configuration and PKI domains).

## What it renders

Nothing yet: jobs and host baselines are intent, rendered by whatever builds and configures the servers (configuration management, milestone 5.3).

## Reading the servers' jobs

```bash
# one folder per server, named by its hostname, with its files at their paths under /
mkdir -p hosts/ds-2.example.test && cd hosts/ds-2.example.test
scp -r ds-2:/etc/crontab ds-2:/etc/cron.d ds-2:/var/spool/cron ds-2:/etc/systemd/system .   # keep the paths
opsdir import --dry-run linux/jobs hosts/
opsdir import --change CHG-… linux/jobs hosts/
```

**Collected over SSH** (`opsdir collect --env CLOUD/ENV --adapter linux`, with the estate setting `collect-from-ssh` on): a collection source per server role, read from every server of that role in the environment by its host name, one folder per server (the layout above):

```ldif
dn: cn=jobs-ds,ou=bindings,env=prod,cloud=source,ou=environments,dc=ciam-ops
objectClass: ciamCollectionSource
ciamBindingRole: collect-jobs-ds
ciamImporter: linux/jobs
ciamTargetRole: ds
ciamLoginName: ops
```

`ciamPort` when SSH isn't on 22. The calls are the core's SSH (`BatchMode=yes`, `StrictHostKeyChecking=yes`: add the hosts to `known_hosts` first; an unknown or changed key fails) running only `cat` of `/etc/crontab`, and `find` then `cat` of the files in `/etc/cron.d` and `/etc/systemd/system`. A file or directory a server lacks is absent, not a failure. Nothing is escalated: users' crontabs (`/var/spool/cron`) are readable by root only and aren't collected; save them by hand if you need them. One host's files can also be read with an `ssh://` configuration source (core README). The showcase's end-to-end tests prove both import like the saved export (`examples/showcase/tests/unit/test_collected_sources.py`).

| File | Read as |
|---|---|
| `etc/crontab`, `etc/cron.d/<file>` | System crontabs: `minute hour day month weekday USER command`, `@daily USER command`, `@reboot USER command` (trigger `boot`) |
| `var/spool/cron/crontabs/<user>`, `var/spool/cron/<user>` | A user's crontab: the same without the user field; runs as `<user>` |
| `etc/systemd/system/<name>.timer` + its service (`Unit=`, else `<name>.service`) | A timer: `OnCalendar`, `OnUnitActiveSec`, `OnUnitInactiveSec`, `OnActiveSec` as schedules; `OnBootSec`, `OnStartupSec` as trigger `boot`; the service's `ExecStart` and `User` |

**One job per role.** The same job (kind, command) on several servers of a role is one `ciamJob` for that role (`ciamTargetRole`), with the servers it was found on (`ciamFoundOn`). Jobs are named `ROLE-NAME`, NAME from the script or program the command runs (or the timer's name), made unique; a re-import finds the record's job of the same kind, role and command (or name) and changes nothing. What the record adds (owner, criticality, the roles a job uses, its realization) is kept.

**Code.** A command that runs from a recorded bundle's deploy path (`ciamDeployPath`, configuration domain) links the bundle (`ciamCodeBundle`).

**Notices:** a job found on some of a role's servers in an environment and not the others (one server runs it, or the others drifted); schedules that differ between servers (the first is recorded); folders that name no server in the record.

**Secrets.** A command that holds secret material, a secret assignment (`--password=…`) or a random-looking token is not recorded (the job is, without its command; named); an environment line in a crontab that gives a secret a value (`DB_PASSWORD=…`) is named and never recorded: move it to a secret store and reference it.

## Reading the servers' host baseline

```bash
# one folder per server, named by its hostname, with its files at their paths under / and three command outputs
H=hosts/ds-2.example.test; mkdir -p $H/java
scp -r ds-2:/etc/os-release ds-2:/etc/security ds-2:/etc/sysctl.conf ds-2:/etc/sysctl.d ds-2:/etc/selinux \
       ds-2:/etc/systemd/system ds-2:/etc/hosts ds-2:/etc/resolv.conf $H/etc/      # keep the paths
ssh ds-2 cat /sys/kernel/mm/transparent_hugepage/enabled > …; ssh ds-2 cat /proc/sys/crypto/fips_enabled > …
ssh ds-2 'java -version' 2> $H/java/version.txt
ssh ds-2 'keytool -list -cacerts -storepass changeit' > $H/java/cacerts.txt     # public certificates only
ssh ds-2 "rpm -qa --qf '%{NAME} %{VERSION}\n'" > $H/packages.txt               # or dpkg-query -W
opsdir import --dry-run linux/baseline hosts/
opsdir import --change CHG-… linux/baseline hosts/
```

**Collected over SSH** the same way (`ciamImporter: linux/baseline`, a role, a login): `cat` of the files in the table below, `find` then `cat` of `limits.d/*.conf`, `sysctl.d/*.conf` and `/etc/systemd/system` (its timers tell the services that are jobs apart), and, after `command -v java keytool rpm dpkg-query` says which tools the server has, only those: `java -version`, `keytool -list -cacerts -storepass changeit` (the JDK's documented default password; a truststore with another one fails, named) and `rpm -qa --qf '%{NAME} %{VERSION}\n'`, or `dpkg-query -W` when `os-release` says Debian or Ubuntu. `java` is the login's `PATH` Java: when the product runs another JDK, read that one by hand. A file or tool a server lacks is absent, not a failure.

| File | Read as |
|---|---|
| `etc/os-release` | `ciamOs`: `ID VERSION_ID` (`rhel 9.4`) |
| `java/version.txt` (`java -version`) | `ciamJdk`: vendor and version (`temurin 17.0.11`; Temurin, Corretto, Zulu, Red Hat, Microsoft, Semeru, GraalVM, Oracle, else `openjdk`) |
| `java/cacerts.txt` (`keytool -list`, with or without `-v`) | The truststore's additions: entries whose alias carries `[jdk]` are the runtime's own (JDK 9+), the rest are added. An addition the record holds a certificate for (by SHA-256 fingerprint) is linked (`ciamTrustsCertificate`); the others are kept by fingerprint (`ciamTrustedFingerprint`) and named. A list with no `[jdk]` entry can't tell additions apart: named, not recorded |
| `etc/security/limits.conf`, `limits.d/*.conf` | `ciamOsLimit`: `domain type item value` |
| `etc/sysctl.d/*.conf`, `etc/sysctl.conf` | `ciamKernelSetting`: `name=value`, later files winning |
| `sys/kernel/mm/transparent_hugepage/enabled` | `ciamHugePages` |
| `proc/sys/crypto/fips_enabled` | `ciamFipsMode` |
| `etc/selinux/config` | `ciamSelinuxMode` |
| `packages.txt` (`rpm -qa`, `rpm -qa --qf '%{NAME} %{VERSION}\n'`, `dpkg-query -W`) | `ciamHostAgent`: the agents among the packages (CrowdStrike Falcon, Tenable Nessus, Qualys, Splunk forwarder, CloudWatch, SSM, Azure Monitor, Azure Linux agent, Google guest agent, Datadog, New Relic, Elastic agent, Filebeat, Fluent Bit, Wazuh, Defender for Endpoint, SentinelOne, Cortex XDR, osquery) |
| `etc/systemd/system/*.service` | `ciamServiceUnit`: `name: user U, restart R` (services a timer starts are jobs, not services) |
| `etc/hosts` | `ciamPinnedHost`: names pinned to addresses (loopback and the server's own names left out) |
| `etc/resolv.conf` | `ciamSearchDomain` |

**One baseline per role.** A host baseline (`ciamHostBaseline`, `cn=<role>,ou=baselines`) is intent: it comes from every server of the role found, in any environment. OS, Java runtime, huge pages, FIPS and SELinux are the first server's (by name); servers that differ are named. Limits, kernel settings, agents, units and truststore additions are every value any server has; values only some servers have are named (drift), and a limit or kernel setting the servers set differently is recorded once (the first server's) and named. Pinned names and search domains are every server's. A fact none of the role's servers' files gave is left as the record has it; what the record adds (owners) is kept; a re-import changes nothing.

The planner (core `compute` domain) then names truststore additions the record doesn't hold (lost silently when a server is rebuilt from a stock image), every pinned name (pinned addresses don't move with the platform), and roles a target runs servers of without a baseline.

## References, vocabulary and schema

None of its own: jobs are the core `automation` domain's (`ciamJob` under `ou=jobs`), baselines the core `compute` domain's (`ciamHostBaseline` under `ou=baselines`). The agents it recognizes are a table in `host.py` (`AGENTS`). Adapter kind `host`.

## Known limits

- Not run against live servers yet; crontab and systemd syntax as documented (cron(5), systemd.timer(5)). The SSH collectors are tested with a stand-in ssh, not real hosts.
- Not read: anacron (`/etc/anacrontab`), `/etc/cron.{hourly,daily,weekly,monthly}/` scripts (run-parts), `at` jobs, user systemd units (`~/.config/systemd/user`), timers under `/usr/lib/systemd/system` (the distribution's).
- A job's schedule is recorded as its system writes it (cron expressions are not normalized).
- Host baseline: not read yet are `java.security` overrides, sudoers and local accounts, auditd rules, logrotate, `/etc/systemd/system/*.service.d/` drop-ins, and units under `/usr/lib/systemd/system`. A truststore listing from a JDK 8 (no `[jdk]` markers) can't tell additions apart.

## Tests

`tests/test_linux_baseline.py`: one baseline per role from its servers, truststore additions linked or named, values that differ and drift named, pins kept, a re-import changing nothing, keeping an owner and not clearing what no file gave; the parsers (JDK vendors, sysctl order, package list forms, pinned names, units, both keytool forms).

`examples/showcase/tests/unit/test_collected_sources.py`: crontabs, timers and host baselines collected over SSH (per host, and per role) give the same import as the saved export; a Debian server without Java gets `dpkg-query` and no Java calls; the SSH setting and roles without servers are named.

`tests/test_linux_jobs.py`: one job per role found on each server, `@reboot` and timers (schedules, boot trigger, the service's command and user), bundle links, secrets never recorded, jobs on some of a role's servers and differing schedules named, unknown folders, a re-import changing nothing and keeping an owner.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `linux`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
