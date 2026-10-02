# Servers' own files (synthetic)

Made-up copies of source servers' files (one folder per server, named by its hostname, at their paths under /), read by two importers:

- `opsdir import --change CHG-2010 linux/jobs exports/hosts`: the schedulers. ds-2 runs the MRO nightly export from cron (and ds-1 and ds-3 don't, which the import points out), and both PingFederate engines ship their audit log every 15 minutes from a systemd timer. Both run scripts from the ops-scripts bundle.
- `opsdir import --change CHG-2012 linux/baseline exports/hosts`: each server role's host baseline, from one server or more of every role (ds-1..3, both engines, the admin node, am-1, idm-1, ig-1): `etc/os-release`, `java/version.txt` (`java -version`), `java/cacerts.txt` (`keytool -list -cacerts`), limits, sysctl, huge pages, FIPS and SELinux modes, `packages.txt` (`rpm -qa`), service units, `/etc/hosts`, `resolv.conf`. Planted: ds-3 sets a lower `net.core.somaxconn` and pf-engine-2 runs a newer Java patch (drift the import names), ds-2 pins `rpt-legacy.mro.example-aero.test` in `/etc/hosts`, and the PingFederate servers' truststore adds the corporate root CA, which the record doesn't hold until CHG-2013.
