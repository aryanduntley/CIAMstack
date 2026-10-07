"""The estate settings the access domain declares (core.settings): values the platform's managers may change for the
whole estate, under an approved change."""
from ...core.contract import Setting

REVIEW_DAYS = Setting("access-review-interval-days", "int", 365,
                      "How often each principal's access must be reviewed, in days, unless the principal says "
                      "otherwise (ciamReviewIntervalDays): a review older than this is overdue", minimum=1)
TEST_DAYS = Setting("break-glass-test-interval-days", "int", 180,
                    "How often a break-glass procedure must be exercised, in days: one not tested for longer may no "
                    "longer work", minimum=1)
SETTINGS = (REVIEW_DAYS, TEST_DAYS)
