"""When a saved search runs and over what time: its cron schedule (cron_schedule, savedsearches.conf cron_schedule)
and, for a window aligned to the clock, its dispatch window snapped to the unit the schedule keeps (aligned_window:
Splunk's time modifiers [+|-]<time_integer><time_unit>@<time_unit>, the offset applied and then rounded down). Pure.
"""


def cron_schedule(seconds):
    """(cron schedule running every seconds, None) or (None, why it can't be): every N minutes dividing an hour, or
    every N hours dividing a day."""
    minutes = seconds // 60
    if seconds % 60 == 0 and 0 < minutes < 60 and 60 % minutes == 0:
        return f"*/{minutes} * * * *", None
    if seconds % 3600 == 0 and 0 < minutes // 60 <= 24 and 24 % (minutes // 60) == 0:
        return f"0 */{minutes // 60} * * *", None
    return None, f"its evaluation period ({seconds}s) isn't a schedule cron can run evenly (minutes dividing an hour)"


def aligned_window(seconds):
    """(dispatch.earliest_time, dispatch.latest_time) of the clock-aligned window of seconds just ended, for a search
    cron runs every seconds (cron_schedule): -<n>m@m to @m, or -<n>h@h to @h when it is whole hours."""
    unit, size = ("h", 3600) if seconds % 3600 == 0 else ("m", 60)
    return f"-{seconds // size}{unit}@{unit}", f"@{unit}"
