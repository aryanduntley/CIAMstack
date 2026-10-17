"""Vault PKI collector (`opsdir collect`, core.contract Collector): what hashicorp-vault/pki reads of each PKI mount,
from Vault's HTTP API, read-only (GETs only: a listing is a GET with ?list=true) and metadata only. Pure: the core
makes the requests.

Where to read is the environment's collection sources for hashicorp-vault/pki (ciamCollectionSource: ciamSourceRef
https://<vault>:<port>/<mount>, one source per mount; the Vault token its ciamCredentialRole binding references,
resolved when collecting and never stored, sent as X-Vault-Token (ciamCredentialScheme api-key) or Authorization:
Bearer (bearer); the CA certificate its ciamCaRole binding references as the trust anchor). A Vault only resolving
vault:// references records no such source and is never read here.

Per mount, saved as pki.py reads them (each answer trimmed to what the importer reads):
  GET <mount>/issuers?list=true, then issuer/<id>        issuers.json, issuers/<id>.json
  GET <mount>/roles?list=true, then roles/<role>           roles.json, roles/<role>.json
  GET <mount>/certs?list=true, then cert/<serial>          certs.json, certs/<serial, - for :>.json
  GET <mount>/config/{urls,issuers,cluster,crl,auto-tidy}  config/<name>.json
  GET sys/policies/acl?list=true, then sys/policies/acl/<name>   policies.json, policies/<name>.json (optional)
An empty listing (Vault answers 404) and a configuration this Vault doesn't have are nothing to read; the policies,
which the token may not be granted, are nothing to read when refused too (who may request from the roles is then
unknown). The token needs only the policy the README states. One collection makes at most the core's call bound (a
mount keeping more certificates is exported with scripts/export-vault-pki.sh)."""
import json
from urllib.parse import quote, urlsplit

from opsdir.core.contract import Collector, Request
from opsdir.core.sources import json_document
from opsdir.domains.governance.collection import collection_sources, readable_sources, scheme_problems
from .pki import file_name, listing

IMPORTER = "hashicorp-vault/pki"
SCHEMES = ("api-key", "bearer")
TAKES = "Vault takes a token: api-key (sent as X-Vault-Token) or bearer"
TOKEN_HEADER = "X-Vault-Token"
CONFIGS = ("urls", "issuers", "cluster", "crl", "auto-tidy")
NOTHING, REFUSABLE = (404,), (403, 404)
# what the importer reads of each answer's data (the rest is dropped before anything sees it)
LIST_FIELDS = ("keys",)
ISSUER_FIELDS = ("issuer_id", "issuer_name", "key_id", "certificate", "crl_distribution_points",
                 "delta_crl_distribution_points", "issuing_certificates", "ocsp_servers", "enable_aia_url_templating")
ROLE_FIELDS = ("max_ttl", "server_flag", "client_flag", "code_signing_flag", "email_protection_flag",
               "ext_key_usage", "ext_key_usage_oids", "allow_any_name", "allowed_domains", "allowed_domains_template",
               "no_store", "issuer_ref")
CERT_FIELDS = ("certificate", "revocation_time", "revocation_time_rfc3339", "revocation_reason", "issuer_id")
CONFIG_FIELDS = {"urls": ("crl_distribution_points", "delta_crl_distribution_points", "issuing_certificates",
                          "ocsp_servers", "enable_templating"),
                 "issuers": ("default",), "cluster": ("path", "aia_path"),
                 "crl": ("disable", "ocsp_disable", "enable_delta", "expiry"),
                 "auto-tidy": ("enabled", "tidy_cert_store", "tidy_revoked_certs", "safety_buffer")}
POLICY_FIELDS = ("name", "policy")


def trimmed(fields):
    """A Request keep function: a Vault answer reduced to {"data": the fields of its data}; text that isn't one is
    kept as it is (the importer names it)."""
    def keep(text):
        doc = json_document(text or "", dict)
        data = doc.get("data") if doc is not None else None
        return json.dumps({"data": {k: data[k] for k in fields if k in data}}, indent=1, sort_keys=True) \
            if isinstance(data, dict) else text
    return keep


def credential(s):
    """The Request credential sending a source's Vault token: X-Vault-Token (api-key), else Authorization: Bearer."""
    if not s.credential:
        return None
    return ("api-key", s.credential, None, TOKEN_HEADER) if s.scheme == "api-key" else ("bearer", s.credential, None)


def mount_of(location):
    """(Vault's address, the mount) a source's location names (https://<vault>:<port>/<mount>), or None."""
    parts = urlsplit(location or "")
    mount = parts.path.strip("/")
    return (f"{parts.scheme}://{parts.netloc}", mount) if parts.scheme in ("http", "https") and parts.netloc \
        and mount else None


def _get(s, address, path, fields, absent=NOTHING):
    return Request(f"{address}/v1/{path}", (), credential(s), s.ca, absent, trimmed(fields))


def _source_steps(s, done):
    address, mount = mount_of(s.locations[0])
    at = lambda name: f"pki/{mount}/{name}"        # noqa: E731
    keys = lambda name: listing(done.get(at(name))) or ()     # noqa: E731
    return ((at("issuers.json"), _get(s, address, f"{mount}/issuers?list=true", LIST_FIELDS)),
            (at("roles.json"), _get(s, address, f"{mount}/roles?list=true", LIST_FIELDS)),
            (at("certs.json"), _get(s, address, f"{mount}/certs?list=true", LIST_FIELDS)),
            *((at(f"config/{c}.json"), _get(s, address, f"{mount}/config/{c}", CONFIG_FIELDS[c])) for c in CONFIGS),
            (at("policies.json"), _get(s, address, "sys/policies/acl?list=true", LIST_FIELDS, REFUSABLE)),
            *((at(f"issuers/{i}.json"), _get(s, address, f"{mount}/issuer/{quote(i)}", ISSUER_FIELDS))
              for i in keys("issuers.json")),
            *((at(f"roles/{r}.json"), _get(s, address, f"{mount}/roles/{quote(r)}", ROLE_FIELDS))
              for r in keys("roles.json")),
            *((at(f"certs/{file_name(c)}.json"), _get(s, address, f"{mount}/cert/{quote(c)}", CERT_FIELDS))
              for c in keys("certs.json")),
            *((at(f"policies/{p}.json"), _get(s, address, f"sys/policies/acl/{quote(p)}", POLICY_FIELDS, REFUSABLE))
              for p in keys("policies.json")))


def pki_steps(d, m, done, options):
    """Each readable source's mount: its listings and configuration, then each issuer, role, certificate and
    policy its listings name."""
    return tuple({p: c for s in readable_sources(m, IMPORTER, SCHEMES) if mount_of(s.locations[0])
                  for p, c in _source_steps(s, done)}.items())


def source_problems(d, m, options):
    """Why the collection sources can't be read: an unbound credential or trust anchor, no location, a credential
    scheme Vault isn't read with, or a location naming no mount."""
    return (*scheme_problems(m, IMPORTER, SCHEMES, TAKES),
            *(f"collection source `{s.name}`: {s.locations[0]} names no mount (https://<vault>:<port>/<mount>)"
              for s in collection_sources(m, IMPORTER) if s.locations and not mount_of(s.locations[0])))


PKI_COLLECTORS = (Collector("pki", "environment", pki_steps, problems=source_problems),)
