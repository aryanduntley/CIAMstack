"""CyberArk collector (`opsdir collect`, core.contract Collector): the account listings cyberark/accounts reads, from
the PVWA REST API, read-only and metadata only. Pure: the core makes the requests.

Where to read is the environment's collection source for cyberark/accounts (ciamCollectionSource: the PVWA's base
URL, https://<pvwa>, or a Privilege Cloud tenant's; the first location of the first usable source), with the
credential its ciamCredentialRole binding references (resolved when collecting, never stored) and the CA certificate
its ciamCaRole binding references as the trust anchor. The credential is a session token obtained outside opsdir:
ciamCredentialScheme token for a self-hosted PVWA (its logon's token, sent as the whole Authorization header) or
bearer for Privilege Cloud (an Identity OAuth access token); opsdir never logs on itself (a logon is a POST, and
collection makes only GETs).

The safes listed are those the record's cyberark:// references name (in every environment), plus the operator's
--inventory-container ones: GET /PasswordVault/API/Accounts?filter=safeName eq <safe>&limit=1000&offset=<n>, page
after page while the vault's count says more accounts remain, each saved as accounts/<safe>/<offset>.json with only
the metadata the importer reads (inventory.metadata_only: never a value-bearing field). The reader needs the Safe
permission List accounts on each safe, nothing more (README)."""
import json
from urllib.parse import quote

from opsdir.core.contract import Collector, Request
from opsdir.domains.governance.collection import collection_sources
from opsdir.domains.pki.inventory import CONTAINER_OPTION, wanted_containers
from .inventory import SCHEME, locate, metadata_only

IMPORTER = "cyberark/accounts"
SCHEMES = ("token", "bearer")       # a self-hosted PVWA's session token; a Privilege Cloud OAuth access token
PAGE = 1000                         # the API's largest page


def page_path(safe, offset):
    return f"accounts/{safe}/{offset}.json"


def _source(m):
    return next((s for s in collection_sources(m, IMPORTER) if s.locations and not s.problems and s.scheme in SCHEMES),
                None)


def _request(s, safe, offset):
    query = f"filter={quote(f'safeName eq {safe}')}&limit={PAGE}&offset={offset}"
    return Request(f"{s.locations[0].rstrip('/')}/PasswordVault/API/Accounts?{query}", (),
                   (s.scheme, s.credential, s.login), s.ca, keep=metadata_only)


def next_offset(text, offset):
    """The offset of the page after one (its text), or None when the vault's count says nothing remains (or the page
    isn't a listing)."""
    try:
        doc = json.loads(text or "")
    except ValueError:
        return None
    listed = doc.get("value") if isinstance(doc, dict) else None
    count = doc.get("count") if isinstance(doc, dict) else None
    if not isinstance(listed, list) or not listed or not isinstance(count, int):
        return None
    return offset + len(listed) if offset + len(listed) < count else None


def account_steps(d, m, done, options):
    """Each safe's first page, then each next page its last one says remains."""
    s = _source(m)
    if s is None:
        return ()
    def pages(safe):
        offsets = [0]
        while page_path(safe, offsets[-1]) in done:
            following = next_offset(done[page_path(safe, offsets[-1])], offsets[-1])
            if following is None:
                break
            offsets.append(following)
        return offsets
    return tuple((page_path(safe, o), _request(s, safe, o))
                 for safe in wanted_containers(d, SCHEME, locate, options.get("inventory_container"))
                 for o in pages(safe))


def source_problems(d, m, options):
    """Why the collection sources can't be read (an unbound credential or trust anchor, no location, a credential
    scheme the PVWA API doesn't take)."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in (
        *s.problems, *((f"collection source `{s.name}`: credential scheme `{s.scheme}`: the PVWA API takes a session "
                        "token (token) or a Privilege Cloud access token (bearer)",) if s.scheme not in SCHEMES
                       else ())))


COLLECTORS = (Collector("accounts", "environment", account_steps, problems=source_problems,
                        options=(CONTAINER_OPTION,)),)
