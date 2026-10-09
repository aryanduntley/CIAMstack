"""Estate settings across the installed domains and adapters: what each declares, the values the record holds, the
settings report, and the change records giving one a value. A connector: domains and adapters declare their settings
(an adapter's are those about what only it knows, such as which in-cluster gateway its kit renders), the core reads
them."""
from ..core.contract import directory_report
from ..core.directory import children, one, rdn_value
from ..core.settings import (SETTING_CLASS, SETTINGS, parse_setting, recorded_setting, setting_changes, setting_text,
                             setting_value)
from .registry import ADAPTERS, DOMAINS

SETTING_HEADERS = ("setting", "declared by", "kind", "default", "value", "in effect", "status", "what it tunes")


def declared_settings(domains=DOMAINS, installed=ADAPTERS):
    """((domain or adapter name, Setting), ...) every installed domain and adapter declares, by setting name."""
    return tuple(sorted(((x.name, s) for x in (*domains, *installed) for s in x.settings),
                        key=lambda pair: pair[1].name))


def _kind(s):
    bounds = (*((f"min {s.minimum}",) if s.minimum is not None else ()),
              *((f"max {s.maximum}",) if s.maximum is not None else ()),
              *((f"one of {', '.join(s.choices)}",) if s.choices else ()))
    return f"{s.kind} ({', '.join(bounds)})" if bounds else s.kind


def _status(s, text):
    problem = parse_setting(s, text)[1] if text is not None else None
    return "default" if text is None else f"invalid: {problem}; the default applies" if problem else "set"


def settings_rows(d, domains=DOMAINS, installed=ADAPTERS):
    """One row per declared setting (the domain or adapter declaring it, kind and bounds or choices, default, the
    record's value, the value in effect, whether it is the default, set, or invalid, what it tunes), then entries under
    ou=settings nothing installed declares."""
    declared = declared_settings(domains, installed)
    names = {s.name for _, s in declared}
    return [*((s.name, domain, _kind(s), setting_text(s.default), recorded_setting(d, s.name) or "",
               setting_text(setting_value(d, s)), _status(s, recorded_setting(d, s.name)), s.description)
              for domain, s in declared),
            *sorted((rdn_value(e), "", "", "", one(e, "ciamEstateValue") or "", "",
                     "not declared by any installed domain or adapter", one(e, "description") or "")
                    for e in children(d, SETTINGS, SETTING_CLASS) if rdn_value(e) not in names)]


SETTINGS_REPORT = directory_report(SETTING_HEADERS, lambda d, dn=None: settings_rows(d))


def changes_for_setting(d, name, text, domains=DOMAINS, installed=ADAPTERS):
    """The change records giving the named estate setting a value; ValueError when nothing installed declares it, or
    the value isn't valid for it."""
    found = [s for _, s in declared_settings(domains, installed) if s.name == name]
    if not found:
        raise ValueError(f"no installed domain or adapter declares setting {name}: `opsdir report settings` lists "
                         "them")
    return setting_changes(d, found[0], text)
