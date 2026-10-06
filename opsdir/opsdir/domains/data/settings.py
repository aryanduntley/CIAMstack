"""The estate settings the data domain declares (core.settings): values the platform's managers may change for the
whole estate, under an approved change."""
from ...core.contract import Setting

RESTORE_TEST_DAYS = Setting("restore-test-interval-days", "int", 90,
                            "How often each backup plan's restores must be tested, in days, unless the plan says "
                            "otherwise: a passed restore test older than this is overdue", minimum=1)
SETTINGS = (RESTORE_TEST_DAYS,)
