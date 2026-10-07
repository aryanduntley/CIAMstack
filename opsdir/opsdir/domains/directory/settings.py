"""The estate settings the directory domain declares (core.settings): values the platform's managers may change for
the whole estate, under an approved change."""
from ...core.contract import Setting

REVIEW_DAYS = Setting("consumer-review-interval-days", "int", 365,
                      "How often each consumer of the user directory must be reviewed, in days: a review older than "
                      "this is due again", minimum=1)
UNSEEN_DAYS = Setting("consumer-unseen-days", "int", 30,
                      "How long a consumer may go unseen in the captured access logs, in days, before it is asked "
                      "whether it is still in use", minimum=1)
SETTINGS = (REVIEW_DAYS, UNSEEN_DAYS)
