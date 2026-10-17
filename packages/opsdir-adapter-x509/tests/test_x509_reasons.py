"""Revocation reasons by name: AWS Private CA's and Google CAS's enum names and RFC 5280's own read as RFC 5280 codes
(case and separators ignored); the record writes the RFC name, unspecified for none, and keeps a name no RFC reason
matches as the product wrote it."""
from opsdir_adapter_x509.reasons import reason_name, revocation_code


def test_product_names_are_rfc_codes():
    assert [revocation_code(n) for n in ("KEY_COMPROMISE", "keyCompromise", "CERTIFICATE_AUTHORITY_COMPROMISE",
                                         "A_A_COMPROMISE", "ATTRIBUTE_AUTHORITY_COMPROMISE", "CERTIFICATE_HOLD",
                                         "REVOCATION_REASON_UNSPECIFIED", "PRIVILEGE_WITHDRAWN", "bogus", None)] == [
        1, 1, 2, 10, 10, 6, 0, 9, None, None]


def test_the_record_writes_rfc_names():
    assert [reason_name(n) for n in ("SUPERSEDED", "CESSATION_OF_OPERATION", "AFFILIATION_CHANGED", None, "",
                                     "VENDOR_SPECIAL")] == [
        "superseded", "cessationOfOperation", "affiliationChanged", "unspecified", "unspecified", "VENDOR_SPECIAL"]
