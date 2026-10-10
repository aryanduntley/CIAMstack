# opsdir-adapter-ansible

opsdir configuration-management adapter: an environment's servers as an Ansible inventory with their variables, and the host configuration the record holds for them as playbooks. It works for servers on any cloud or on-prem.

**Applies to** environments whose stack declares it (`ciamStackRole: configuration-management`, `ciamAdapter: ansible`); it is never inferred. **Depends on** `opsdir` (the infrastructure and compute domains; the secret stores' adapters for lookups).

## What it renders

| File | Content |
|---|---|
| `ansible/inventory/hosts.yml` | YAML inventory: `all` → `ciam_servers` → one group per server role (the role's name with other characters as `_`: `pf-engine` → `pf_engine`) → its servers by host name (`ciamHostname`), `ansible_host` their `ciamPrivateIp` when recorded |
| `ansible/inventory/group_vars/all.yml` | `ciam_environment` (`cloud/env`), `ciam_provider`, `ciam_region` (an on-prem environment's site), `ciam_time_sources` (its time servers), `ciam_config_files_not_deployed` (product files that can't be deployed here, with why) |
| `ansible/inventory/group_vars/<role>.yml` | `ciam_role`, and the role's host baseline, jobs, host firewall rules and product files (below) |
| `ansible/templates/<repo path>.j2` | The product configuration files the servers receive, as templates (no header: they are the products' files) |
| `ansible/host-config.yml` | The host-config playbook (below): the same in every environment |
| `ansible/inventory/host_vars/<host>.yml` | `ciam_server` (its name in the record), `ciam_zone`, `ciam_subnet` (its subnet's range), `ciam_product_version` (those recorded) |

Every file carries the do-not-edit header. Add-ons put their appliances in their own files and groups beside `hosts.yml`, so a run reads the whole folder: `ansible-playbook -i ansible/inventory ansible/host-config.yml`; check it with `ansible-inventory -i ansible/inventory --graph`. `host-config.yml` runs on `ciam_servers` only, never on the appliances.

Values come from the record as written. Ansible evaluates any variable holding `{{`, `{%` or `{#` as a template, so those strings are written `!unsafe` (Ansible takes them as is). Only those: Ansible's `!unsafe` re-reads a scalar's type ignoring its quotes (`!unsafe "30"` would be a number). Lines are kept within ansible-lint's 160 characters, longer strings folded (`>-`).

## Host configuration

`group_vars/<role>.yml` carries the role's host baseline in the environment (`ciamHostBaseline`, core compute domain: the role's baselines that apply there merged, one scoped to environments or providers by `ciamInEnvironment` / `ciamOnProvider` over one that applies everywhere; list values combined, single values from the most specific) and its jobs that apply there (the same scoping), and `host-config.yml` applies them, by tag:

| Tag | What | From the baseline |
|---|---|---|
| `baseline` (default) | Kernel settings (`ansible.posix.sysctl` into `/etc/sysctl.d/90-ciam.conf`), limits (`community.general.pam_limits` into `/etc/security/limits.d/90-ciam.conf`), transparent huge pages (a oneshot unit `ciam-transparent-hugepages.service` setting `enabled` and `defrag` at boot), SELinux mode (`ansible.posix.selinux`, targeted), FIPS mode, the certificates the truststore adds as system trust anchors (`update-ca-trust` on Red Hat, `update-ca-certificates` on Debian) | `ciamKernelSetting`, `ciamOsLimit`, `ciamHugePages`, `ciamSelinuxMode`, `ciamFipsMode`, `ciamTrustsCertificate` (their recorded PEMs, `ciamCertificatePem`; the others, and `ciamTrustedFingerprint`s, are named, not added) |
| `stig` (default, when recorded) | Red Hat's DISA STIG role for the host's RHEL major version (`RedHatOfficial.rhel8_stig`, `rhel9_stig`, `rhel10_stig`); a host that isn't RHEL 8 to 10 is named, not hardened | `ciamHardeningProfile: disa-stig` (an environment can differ through an override) |
| `jobs` (default) | The role's cron jobs (`ansible.builtin.cron`: five fields, or `special_time` for `@daily`, `@reboot`, …) and timers (`opsdir-<job>.service` oneshot running the command through `/bin/sh -c`, as cron does, + `opsdir-<job>.timer`, schedule lines as recorded, enabled). The record holds the shell command; cron's `%` and systemd's `\\`, `"`, `%` and `$` are escaped when written. A job whose command the record withholds is named, not deployed | `ciamJob` of kind `cron` or `timer` with the role as `ciamTargetRole` (`ciamSchedule`, `ciamCommand`, `ciamRunsAs`) |
| `time` (default) | chrony installed, the environment's time servers in a managed block of `chrony.conf` (`server <host> iburst`; the distribution's default `pool` lines removed, so only the recorded sources are used), chronyd enabled and restarted when they change | the environment's `ciamTimeSource` bindings (`ciamTimeServer`), as `ciam_time_sources` in `group_vars/all.yml` |
| `firewall` (default) | The role's firewall rules on its servers: firewalld enabled and running, a rich rule per source range and port (`ansible.posix.firewalld`, permanent and immediate) | `ciamFirewallRule` with the role as `ciamTargetRole` (`ciamSourceCidr`, `ciamPort`, `ciamProtocol`) |
| `files` (default) | The product configuration files the role receives, from their templates, to their deploy paths (mode `0640`; `diff: false`, so `--diff` never prints the secrets read into them); files not deployed are named | captured files (`ciamConfigFile`) with the role as `ciamTargetRole` and a `ciamDeployPath`, rebuilt with the environment's bindings (`Services.deployable_config`) |
| `verify` (only with `--tags verify`) | What installing the servers brings: OS (`ID VERSION_ID` of os-release), agents' packages installed, service units enabled | `ciamOs`, `ciamHostAgent`, `ciamServiceUnit` |

FIPS: on RHEL 8 and 9 (and Rocky, AlmaLinux, CentOS Stream, Oracle Linux) the play runs `fips-mode-setup --enable` and names the reboot it needs; RHEL 10 can't switch to FIPS mode after installation (Red Hat's RHEL 10 security hardening guide), so there it only checks `/proc/sys/crypto/fips_enabled` and tells you to reinstall with `fips=1`; on other systems it names what to do, changing nothing. A FIPS mode recorded off is never switched off, and the play never reboots. What the record only observed (names pinned in `/etc/hosts`, search domains) is never applied: those are the source's addresses.

A template keeps the file's text verbatim in `{% raw %}` blocks; each secret placeholder (`${secret:<ref-uri>}`) becomes the lookup below, read when the play runs. A file isn't deployed, and is named in `ciam_config_files_not_deployed`, when a placeholder can't be read (no scheme, or one no installed adapter resolves) or its target role has no servers in the environment.

## Secrets at run time

Nothing secret is written. Where a playbook needs a secret, it reads the reference at run time on the controller, under the operator's own login, with the lookup the adapter owning the reference's scheme declares (`Adapter.ansible_lookup`, `Services.ansible_lookup(m, ref-uri)`):

| Scheme | Lookup |
|---|---|
| `aws-sm://` | `amazon.aws.secretsmanager_secret` (region and credentials from the controller's AWS configuration, as the CLI) |
| `azkv://` | `azure.azcollection.azure_keyvault_secret` with `vault_url` built from the Key Vault store's `ciamStoreEndpoint` (so Azure Government's `vault.usgovcloudapi.net` is kept), as the operator's `az login` (`auth_source=cli`, `use_msi=false`; the CLI's configured cloud, `AzureUSGovernment` in Azure Government); without an endpoint, the pipe below |
| `vault://` | `community.hashi_vault.vault_kv2_get` (or `vault_kv1_get` by the store's `ciamStoreKvVersion`), `.secret.value`; mount = the reference's first segment, `url` from the store's `ciamStoreEndpoint` |
| `k8s-secret://` | `kubernetes.core.k8s` (kind Secret), the key's data base64-decoded |
| any other (`cyberark://`, `gcp-sm://`) | `ansible.builtin.pipe` of the scheme's resolver command (the one `opsdir` itself runs: `clipasswordsdk`, `gcloud`), built by this adapter (`output.secret_lookup`; the core only offers the owner's native lookup). Native lookups for these two wait until they are verified (CyberArk's CCP/Conjur lookups, `google.cloud.gcp_secret_manager`) |

The collections a run needs are those its lookups name (`amazon.aws`, `azure.azcollection`, `community.hashi_vault`, `kubernetes.core`; the pipe needs none, only the resolver's CLI on the controller), pinned in the rendered `requirements.yml`. A reference that can't be read (no scheme, or one no installed adapter resolves) is never written: the file holding it isn't deployed, and is named.

## Validation

`ansible/requirements.yml` pins what a run needs from Galaxy (only the collections the rendered files name; Red Hat's STIG roles when a baseline names `disa-stig`), from the adapter's pin list (`requirements.py`: `ansible.posix` 2.2.2, `community.general` 13.4.0, `amazon.aws` 11.4.0, `azure.azcollection` 4.0.0, `community.hashi_vault` 7.1.0, `kubernetes.core` 6.6.0, `ansible.netcommon` 8.7.1, `f5networks.f5_bigip` 3.14.0, `ansible.windows` 3.8.0, `infoblox.nios_modules` 1.10.0, `paloaltonetworks.panos` 3.4.2, `RedHatOfficial.rhel8/9/10_stig` 0.1.82; each released two weeks or more before it was pinned). The add-ons render their own `requirements-<add-on>.yml` the same way. `opsdir/scripts/fetch-tools.sh` installs the same pins (`--force`, so a changed pin replaces what is installed) with ansible-core 2.21.4 and ansible-lint 26.9.0 into `tools/ansible` (their own Python dependencies are resolved by pip, not hash-pinned), and `opsdir/scripts/validate-ansible.sh` checks every `ansible/` folder: `ansible-inventory --list`, `ansible-playbook --syntax-check`, `ansible-lint --profile production` (the pytest marker `ansible`). The YAML is written with sequences indented under their keys and long strings folded (`output.yaml_text`: core `yaml_text.dump(..., indent_sequences=True, width=160)`), as ansible-lint's yamllint wants. Add-ons write theirs through the same helpers (`output.py`: `yaml_files`, `requirements_file`, `secret_lookup`, `login`, `appliance_inventory`, `LOCAL` for plays run on the controller with its own Python).

## Known limits

- Bundles (`ciamBundle`: scripts, templates, packages) aren't placed: the record holds their digest, not their content.
- File owners aren't recorded: templates are written with mode `0640`, owned by the play's user.
- Per-server product scripts (`ds/setup-ds-<n>.sh`, …) are run by the operators, not by this play (installing the products is out of scope).
- The Java runtime (`ciamJdk`) isn't checked (no version source common to every vendor's runtime).
- Native lookups not yet used: CyberArk's Credential Provider (no verified lookup plugin; the pipe runs the same SDK), Google Secret Manager (`google.cloud.gcp_secret_manager` needs auth parameters the record doesn't hold).

## Tests

`tests/test_ansible_inventory.py`: groups and hosts, variables by scope, headers, group names; native lookups, store-shaped lookups (Azure Government endpoint, Vault KV 1), the pipe fallback. `tests/test_ansible_baseline.py`: baseline variables (intent applied, installation verified, observed facts never applied), the playbook's tasks and tags. `tests/test_ansible_host_config.py`: jobs (cron fields, @-words, timers, withheld commands), firewall rich rules (IPv4 and IPv6), templates (raw text, lookups), tags. `tests/test_ansible_validate.py` (marker `ansible`): a render using every host-config feature passes the real tools.
