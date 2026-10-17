"""Revocation reasons as CA products name them (AWS Private CA's and Google CAS's enum names, the RFC 5280 names
themselves) read as RFC 5280 CRLReason codes, CA-neutral: for every CA whose inventory gives a reason by name rather
than by code. The record writes a reason's RFC 5280 name (core pki revocation_reason); a name no RFC reason matches is
kept as the product wrote it. Google CAS documents that its enum's numbers aren't RFC 5280's: names are matched, never
numbers. Pure."""
from opsdir.domains.pki.issued import revocation_reason

# the names products give each RFC 5280 section 5.3.1 reason code, upper case without separators
NAMES = {0: ("UNSPECIFIED", "REVOCATIONREASONUNSPECIFIED"), 1: ("KEYCOMPROMISE",),
         2: ("CACOMPROMISE", "CERTIFICATEAUTHORITYCOMPROMISE"), 3: ("AFFILIATIONCHANGED",), 4: ("SUPERSEDED",),
         5: ("CESSATIONOFOPERATION",), 6: ("CERTIFICATEHOLD",), 8: ("REMOVEFROMCRL",), 9: ("PRIVILEGEWITHDRAWN",),
         10: ("AACOMPROMISE", "ATTRIBUTEAUTHORITYCOMPROMISE")}
CODES = {n: code for code, names in NAMES.items() for n in names}


def revocation_code(name):
    """The RFC 5280 reason code a product's reason name stands for (KEY_COMPROMISE, keyCompromise and
    key-compromise alike), or None when it names none."""
    key = "".join(c for c in str(name or "") if c.isalnum()).upper()
    return CODES.get(key)


def reason_name(name):
    """The RFC 5280 name the record writes for a product's reason name (unspecified when none is given), else the
    name as the product wrote it."""
    if name in (None, ""):
        return revocation_reason(0)
    code = revocation_code(name)
    return revocation_reason(code) if code is not None else str(name)
