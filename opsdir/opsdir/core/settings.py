"""Estate settings: the values the platform's managers give the settings domains declare (contract.Setting), held as
governed entries under ou=settings (one ciamEstateSetting each, named as declared, its value in ciamEstateValue) and
read with the declared default wherever the record holds none, or one that isn't valid for the setting. A value is
changed like any other entry: under an approved change, kept in history. Technology-neutral and pure."""
from .changeset import new_entry, set_values
from .directory import get, one
from .naming import branch

SETTINGS = branch("settings")
SETTING_CLASS = "ciamEstateSetting"
_BOOLEANS = {"TRUE": True, "FALSE": False}


def setting_dn(name):
    """DN of an estate setting's entry."""
    return f"cn={name},{SETTINGS}"


def _int(setting, text):
    if not text.strip().lstrip("-").isdigit():
        return None, f"{text!r} isn't a whole number"
    n = int(text)
    if setting.minimum is not None and n < setting.minimum:
        return None, f"{n} is less than {setting.minimum}"
    if setting.maximum is not None and n > setting.maximum:
        return None, f"{n} is more than {setting.maximum}"
    return n, None


def parse_setting(setting, text):
    """(value, problem) of a setting's text: the value its kind reads (an int within its bounds, TRUE or FALSE, a
    string), or None and why the text isn't one."""
    if setting.kind == "int":
        return _int(setting, text)
    if setting.kind == "bool":
        return (_BOOLEANS[text.strip().upper()], None) if text.strip().upper() in _BOOLEANS else \
            (None, f"{text!r} isn't TRUE or FALSE")
    return (text, None) if text.strip() else (None, "it is empty")


def setting_text(value):
    """The text a setting's value is recorded as (TRUE or FALSE for a bool)."""
    return ("TRUE" if value else "FALSE") if isinstance(value, bool) else str(value)


def recorded_setting(d, name):
    """The text the record holds for a setting, or None."""
    e = get(d, setting_dn(name))
    return one(e, "ciamEstateValue") if e is not None else None


def setting_value(d, setting):
    """A setting's value in effect: the record's when it holds a valid one, else the declared default."""
    text = recorded_setting(d, setting.name)
    value = parse_setting(setting, text)[0] if text is not None else None
    return setting.default if value is None else value


def setting_changes(d, setting, text):
    """The change records giving a setting a value (ou=settings added when missing; none when it already holds it);
    ValueError when the value isn't valid for the setting."""
    value, problem = parse_setting(setting, text)
    if problem:
        raise ValueError(f"setting {setting.name}: {problem}")
    canonical, e = setting_text(value), get(d, setting_dn(setting.name))
    if e is not None:
        return () if one(e, "ciamEstateValue") == canonical else (set_values(e, "ciamEstateValue", (canonical,)),)
    return (*(() if get(d, SETTINGS) is not None else
              (new_entry(SETTINGS, ("top", "organizationalUnit"), {"ou": ("settings",)}),)),
            new_entry(setting_dn(setting.name), ("top", SETTING_CLASS),
                      {"cn": (setting.name,), "ciamEstateValue": (canonical,), "description": (setting.description,)}))
