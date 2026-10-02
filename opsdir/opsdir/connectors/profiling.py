"""The data profile's collection: directory data streamed from LDIF (ldapsearch output, an export) and reduced to
counts, with what the installed adapters' products mean by their attributes. The lines are read once and nothing they
hold is kept; only the counts reach the profile file."""
from ..core.interchange.ldif import content_entries
from ..domains.directory.profile import TERM_NAMES, STANDARD, combined, defined_terms, profile, profile_json
from .registry import ADAPTERS


def profile_terms(installed=ADAPTERS):
    """What directory attributes mean to the data profile: the LDAP standards' and every installed adapter's."""
    return combined(STANDARD, *(a.profile_terms for a in installed if a.profile_terms))


def profile_file(lines, label, as_of, captured, definitions=(), installed=ADAPTERS):
    """The profile file (JSON text) of environment 'cloud/env's directory data, an LDIF line stream: ages counted on
    date as_of, the file dated captured (a UTC datetime), with the installed adapters' terms and the operator's
    definitions (NAME=ATTRIBUTE[=VALUE]). Refuses definitions that aren't terms (ValueError) before reading a line."""
    extra, refused = defined_terms(definitions)
    if refused:
        raise ValueError(f"not a term (NAME=ATTRIBUTE[=VALUE], NAME one of {', '.join(TERM_NAMES)}): "
                         f"{', '.join(refused)}")
    return profile_json(profile(content_entries(lines), as_of, combined(profile_terms(installed), extra)), label,
                        captured)
