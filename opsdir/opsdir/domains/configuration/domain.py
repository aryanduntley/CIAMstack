"""Configuration domain: config files held in the record (captured setting by setting, whole, or as a reference)
and rebuilt from it, and bundles (code, scripts, templates, packages) recorded where they live. Vendor-neutral: a
file's format decides how it is read and written."""
from ...core.contract import Domain, directory_report
from ...core.directory import children, one
from .bundles import BUNDLE_HEADERS, bundle_rows
from .census import CENSUS_HEADERS, census_rows, check_census
from .checks import check_config_files
from .naming import CONFIG_FILES
from .schema import FRAGMENT

CAPTURE_HEADERS = ("file", "level", "format", "repo path", "settings", "withheld", "problem")


def capture_rows(d, dn=None):
    """One row per captured file: how the record holds it, its settings, how many values were withheld, and why it
    is not held as settings (when it isn't)."""
    def row(f):
        settings = children(d, f.dn, "ciamConfigSetting")
        held = sum(one(s, "ciamSecretRequired") == "TRUE" and not one(s, "ciamValueFrom") for s in settings)
        return (one(f, "cn"), one(f, "ciamCaptureLevel"), one(f, "ciamFormat"), one(f, "ciamRepoPath"),
                len(settings), held, one(f, "ciamCaptureProblem") or "")
    return [row(f) for f in children(d, CONFIG_FILES, "ciamConfigFile")]


DOMAIN = Domain(name="configuration", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"capture": directory_report(CAPTURE_HEADERS, capture_rows),
                         "bundles": directory_report(BUNDLE_HEADERS, bundle_rows),
                         "census": directory_report(CENSUS_HEADERS, census_rows)},
                checks=(check_config_files, check_census),
                order=55,
                vocabulary={})
