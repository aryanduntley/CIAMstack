"""PingAM collector (`opsdir collect`, core.contract Collector): the Amster export pingam/amster reads, read-only for
AM. Pure: the core runs Amster.

Where to read is the environment's collection source for pingam/amster (ciamCollectionSource: AM's URL,
https://<host>/am). Amster signs in with a private key whose public key AM trusts (its authorized_keys): the operator's
existing key file, given when collecting (--amster-key PATH, never stored in the record). Amster runs a script in a
private work directory (connect with the key, export-config --failOnError into the directory, exit), and the files it
writes are the export. Encrypted passwords are exported only with a transport key, which this never configures: they
are left out, and the importer withholds what it recognizes as secret anyway."""
from opsdir.core.contract import Collector, Command
from opsdir.domains.governance.collection import collection_sources

IMPORTER = "pingam/amster"


def script(url, key):
    """The Amster script: connect with the key, export the configuration into the work directory, exit."""
    return f"connect {url} -k {key}\nexport-config --path {{dir}}/export --failOnError\n:exit\n"


def amster_steps(d, m, done, options):
    """Amster's export of the first collection source's AM, when the operator gave the key."""
    s = next((x for x in collection_sources(m, IMPORTER) if x.locations and not x.problems), None)
    key = options.get("amster_key")
    if s is None or not key:
        return ()
    return (("", Command(("amster", "{dir}/collect.amster"), workdir=True,
                         inputs=(("collect.amster", script(s.locations[0].rstrip("/"), key)),))),)


def problems(d, m, options):
    """Why AM can't be read: its sources' problems, or no Amster key given."""
    sources = collection_sources(m, IMPORTER)
    return (*(p for s in sources for p in s.problems),
            *(("give --amster-key PATH: the private key AM trusts for Amster",)
              if sources and not options.get("amster_key") else ()))


COLLECTORS = (Collector("amster", "environment", amster_steps, problems=problems),)
