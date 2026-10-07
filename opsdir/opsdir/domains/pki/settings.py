"""The estate settings the PKI domain declares (core.settings): values the platform's managers may change for the
whole estate, under an approved change."""
from ...core.contract import Setting

EXPIRY_MARGIN_DAYS = Setting("certificate-expiry-margin-days", "int", 30,
                             "How long after cutover (or today, when no cutover is planned) a certificate must stay "
                             "valid, in days: one expiring sooner is renewed before the move", minimum=0)
SETTINGS = (EXPIRY_MARGIN_DAYS,)
