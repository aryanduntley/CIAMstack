"""A CA's publication URL registry entries (CRLPublicationURLs, CACertPublicationURLs: REG_MULTI_SZ strings
"<decimal flags>:<path or URL template>", MS-CSRA) as the revocation endpoints the CA writes into the certificates it
issues. Pure.

Flags (CSURL_*, Microsoft's CertSrv.h) are read in the context of the value holding them: in CRLPublicationURLs 0x02
puts the location in issued certificates' CRL distribution points and 0x04 in their freshest CRL (the delta CRL); in
CACertPublicationURLs 0x02 puts it in their authority information access as CA issuers and 0x20 as OCSP. Other flags
(publishing, 0x08 CRL CDP, 0x10 retry, 0x40 delta publishing, 0x80 IDP) put nothing into issued certificates.

Variables are filled only from what the exporter states: %1 the CA host's DNS name, %2 its NetBIOS name (Windows
Server's guidance; MS-CSRA's CA certificate table reverses the two: README Known limits), %3 the CA's name, %8 empty
(the first CRL key's suffix) and %9 empty in a CRL location and + in a delta CRL one. Any other variable (%4, %6, %7,
%10, %11) stays as it is, and the CA's template is kept with the endpoint.
"""
import re

CRL_KINDS = ((0x02, "crl"), (0x04, "delta-crl"))
CA_CERT_KINDS = ((0x02, "ca-issuers"), (0x20, "ocsp"))
VARIABLE = re.compile(r"%(1[01]|[1-9])")


def split_entry(entry):
    """(flags, template) of a registry entry, split at its first colon (paths and URLs hold others), or None when
    it isn't one (no decimal flags)."""
    flags, sep, template = str(entry).partition(":")
    return (int(flags), template.strip()) if sep and flags.strip().isdigit() else None


def expand(template, values):
    """(text, unfilled): the template with each variable values gives ({"1": text, ...}; None: unknown) filled, and
    the variables left as they are."""
    left = tuple(dict.fromkeys(f"%{m.group(1)}" for m in VARIABLE.finditer(template)
                               if values.get(m.group(1)) is None))
    return VARIABLE.sub(lambda m: m.group(0) if values.get(m.group(1)) is None else values[m.group(1)], template), left


def endpoints(entries, kinds, ca):
    """((kind, url, template or None), ...), notices: the endpoints a value's entries put into issued certificates,
    by kind in entry order; ca: {"dns", "netbios", "name"} as the exporter stated them (None: not stated)."""
    parsed = tuple((e, split_entry(e)) for e in entries)
    found = tuple((kind, *expand(template, {"1": ca.get("dns"), "2": ca.get("netbios"), "3": ca.get("name"),
                                             "8": "", "9": "+" if kind == "delta-crl" else ""}), template)
                  for _, p in parsed if p for flags, template in (p,) for bit, kind in kinds if flags & bit)
    notices = (*(f"publication URL entry {e!r} has no decimal flags: left out" for e, p in parsed if p is None),
               *(f"{kind} endpoint {url}: {', '.join(left)} not filled (kept with the CA's template)"
                 for kind, url, left, _ in found if left))
    return tuple((kind, url, template if left else None) for kind, url, left, template in found), notices
