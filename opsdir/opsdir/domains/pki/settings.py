"""The estate settings the PKI domain declares (core.settings): values the platform's managers may change for the
whole estate, under an approved change."""
from ...core.contract import Setting

EXPIRY_MARGIN_DAYS = Setting("certificate-expiry-margin-days", "int", 30,
                             "How long after cutover (or today, when no cutover is planned) a certificate must stay "
                             "valid, in days: one expiring sooner is renewed before the move", minimum=0)
REVOCATION_MARGIN_HOURS = Setting("revocation-freshness-margin-hours", "int", 12,
                                  "How long before its nextUpdate a CRL or OCSP response an endpoint serves is stale, "
                                  "in hours: by then the CA should have published the next one (Microsoft AD CS's "
                                  "default overlap is at most 12 hours plus clock skew)", minimum=0)
ANCHOR_HORIZON_DAYS = Setting("trust-anchor-horizon-days", "int", 1825,
                              "How far ahead a trust policy's anchors are watched for expiry, in days: replacing a "
                              "root every relying party trusts takes years (the default, five years, sees DoD Root "
                              "CA 3 and ECA Root CA 4, both ending 2029-12-30, from 2025)", minimum=0)
BUNDLE_MAX_AGE_DAYS = Setting("trust-bundle-max-age-days", "int", 90,
                              "How long a trust bundle followed by a trust policy may go without being imported "
                              "again, in days (DISA adds CAs about yearly and publishes bundles without a schedule)",
                              minimum=1)
SETTINGS = (EXPIRY_MARGIN_DAYS, REVOCATION_MARGIN_HOURS, ANCHOR_HORIZON_DAYS, BUNDLE_MAX_AGE_DAYS)
