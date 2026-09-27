"""A directory snapshot as LDIF: every entry under a base, parents before children (Git review, workspace bases)."""
from ..directory import subtree
from .ldif import write_entry


def export_text(d, base):
    """Every entry under base as LDIF, parents before children."""
    entries = sorted(subtree(d, base), key=lambda e: (e.norm.count(","), e.norm))
    return "\n".join(write_entry(e.dn, e.classes, e.attrs) for e in entries)
