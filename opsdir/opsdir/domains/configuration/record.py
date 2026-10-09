"""Config files as entries, and back: pure.

Import turns a file into entries at one of three levels. `settings`: the file's layout on the file entry (each
setting's place marked) and one ciamConfigSetting per setting. `whole-file`: the file can't be parsed as its format,
so its whole text is kept (still rebuilt byte for byte, not editable setting by setting). `reference`: nothing of the
text is stored because it may hold secret material; the entry records where the file is, its hash and why.

Nothing that may be secret is stored. A setting whose value is secret material, whose name says it holds a secret, or
whose value looks random is withheld: its entry says a secret reference must supply it. A layout or whole text is
stored only when nothing in it raises a concern (core.secrets.text_concerns), unless the operator has reviewed it and
accepts it (the store's own guard applies regardless).
"""
import hashlib
import re
from functools import reduce

from ...core.capture import Captured, Slot, attempt_capture, render_captured
from ...core.directory import children, is_a, make_entry, one
from ...core.environment import one_role
from ...core.secrets import text_concerns, withheld
from ..compute.workloads import kubernetes_roles
from ..network.proxies import derived
from .naming import CONFIG_FILES, file_dn, setting_dn, setting_rdn

# A setting's place in a skeleton: MARK_OPEN locator MARK_CLOSE. Private-use characters no config file contains,
# opened with "${" so that no secret pattern takes a setting's place for a value (they skip placeholders).
MARK_OPEN, MARK_CLOSE = "${\ue000", "\ue001}"
_MARKED = re.compile(re.escape(MARK_OPEN) + "([^\ue001]*)" + re.escape(MARK_CLOSE))
_STANDS_IN = "${value}"                              # a setting's place when a layout is checked for concerns


def marked(skeleton, fill=None):
    """A skeleton as text: literal text, and each slot as its marked locator (or `fill`)."""
    return "".join(p if isinstance(p, str) else (fill if fill is not None else f"{MARK_OPEN}{p.locator}{MARK_CLOSE}")
                   for p in skeleton)


def slots_of(text):
    """A marked skeleton back as literal text and locators (str, or ("slot", locator))."""
    parts = _MARKED.split(text)
    return tuple(p if k % 2 == 0 else ("slot", p) for k, p in enumerate(parts) if k % 2 == 1 or p)


def _concerns(text, patterns):
    return tuple(f"line {n}: {what}" for n, what in text_concerns(text, patterns))


def _setting_entry(name, fmt, slot, value, patterns):
    reason = withheld(slot.locator, value, patterns)
    base = {"cn": (setting_rdn(slot.locator),), "ciamLocator": (slot.locator,)}
    if reason is None:
        return make_entry(setting_dn(name, slot.locator), ("top", "ciamConfigSetting"),
                          {**base, **({"ciamSettingValue": (value,)} if value else {}),
                           **({"ciamSettingRaw": (slot.raw,)} if slot.raw else {})})
    try:
        style = fmt.codec.encode("", slot.raw)      # the setting's shape (quoting, type) without its value
    except ValueError:
        style = ""
    return make_entry(setting_dn(name, slot.locator), ("top", "ciamConfigSetting"),
                      {**base, "ciamSecretRequired": ("TRUE",), "ciamCaptureProblem": (f"value withheld: {reason}",),
                       **({"ciamSettingRaw": (style,)} if style else {})})


def _file_entry(name, attrs):
    return make_entry(file_dn(name), ("top", "ciamConfigFile"), {"cn": (name,), **attrs})


def file_entries(fmt, text, name, repo_path, patterns, role=None, deploy_path=None, accept_concerns=False):
    """(entries, notices): the file entry and its setting entries at the level the file allows, and what the
    operator should know (the level and why, withheld values)."""
    base = {"ciamFormat": (fmt.name,), "ciamRepoPath": (repo_path,),
            "ciamSha256": (hashlib.sha256(text.encode()).hexdigest(),),
            **({"ciamTargetRole": (role,)} if role else {}),
            **({"ciamDeployPath": (deploy_path,)} if deploy_path else {})}
    captured, problem = attempt_capture(fmt, text)
    if captured and ("\ue000" in text or "\ue001" in text):
        captured, problem = None, "the file contains the characters opsdir marks settings with (U+E000, U+E001)"
    stored = marked(captured.skeleton, _STANDS_IN) if captured else text
    concerns = () if accept_concerns else _concerns(stored, patterns)
    if concerns:
        why = ("its layout" if captured else "its text") + " may hold secret material: " + "; ".join(concerns)
        return ((_file_entry(name, {**base, "ciamCaptureLevel": ("reference",), "ciamCaptureProblem": (why,)}),),
                (f"{name}: reference only (nothing of the file is stored): {why}",))
    if captured is None:
        entry = _file_entry(name, {**base, "ciamCaptureLevel": ("whole-file",), "ciamSkeleton": (text,),
                                   "ciamCaptureProblem": (f"not parsed as {fmt.name}: {problem}",)})
        return (entry,), (f"{name}: stored whole (not setting by setting): not parsed as {fmt.name}: {problem}",)
    slots = [p for p in captured.skeleton if isinstance(p, Slot)]
    settings = tuple(_setting_entry(name, fmt, s, v, patterns) for s, (_, v) in zip(slots, captured.settings))
    held = [one(s, "ciamLocator") for s in settings if one(s, "ciamSecretRequired") == "TRUE"]
    entry = _file_entry(name, {**base, "ciamCaptureLevel": ("settings",), "ciamSkeleton": (marked(captured.skeleton),)})
    return (entry, *settings), (f"{name}: {len(settings)} settings", *(f"{name}: value withheld, needs a secret "
                                                                        f"reference: {loc}" for loc in held))


def captured_file(fmt, prefix, folder, path, text, patterns, role=None):
    """(DN, entries, notices) of a product's config file captured into the record: named prefix.path (slashes as
    dots), its repository path folder/path. Product importers that keep files they don't model share this."""
    name = f"{prefix}." + path.replace("/", ".")
    entries, notices = file_entries(fmt, text, name, f"{folder}/{path}", patterns, role)
    return file_dn(name), entries, notices


VALUE_ATTRS = ("ciamSettingValue", "ciamValueFrom")


def setting_attrs(value=None, link=None):
    """A setting's value attributes: a link (ciamValueFrom, role#attribute or role#kind:name) or a literal."""
    return {"ciamValueFrom": (link,)} if link else {"ciamSettingValue": (value,)} if value else {}


def revalued(setting, attrs):
    """A setting entry with its value attributes replaced by attrs (setting_attrs); its raw text kept, so a changed
    value is written in the original's style."""
    kept = {k: v for k, v in setting.attrs.items() if k not in VALUE_ATTRS}
    return make_entry(setting.dn, setting.classes, {**kept, **attrs})


def added_settings(fmt, file_entry, new):
    """(the file entry with each new setting's place appended to its layout, the new setting entries) for new:
    ((locator, value attributes), ...); None when the file isn't held setting by setting or its format can't place a
    new setting (codec.add)."""
    add = fmt.codec.add if fmt.codec is not None else None
    if add is None or one(file_entry, "ciamCaptureLevel") != "settings":
        return None

    def append(text, locator):
        before, after = add(text, locator)
        return text + before + MARK_OPEN + locator + MARK_CLOSE + after
    skeleton = reduce(append, (loc for loc, _ in new), one(file_entry, "ciamSkeleton"))
    name = one(file_entry, "cn")
    return (make_entry(file_entry.dn, file_entry.classes, {**file_entry.attrs, "ciamSkeleton": (skeleton,)}),
            tuple(make_entry(setting_dn(name, loc), ("top", "ciamConfigSetting"),
                             {"cn": (setting_rdn(loc),), "ciamLocator": (loc,), **attrs}) for loc, attrs in new))


def _linked(setting, m):
    role, attr = one(setting, "ciamValueFrom").split("#", 1)
    b = one_role(m, role)
    if ":" in attr:            # a value derived from the binding (role#proxy:host); empty where m doesn't bind it
        return derived(m, b, attr) if b is not None else ""
    if b is None:
        raise ValueError(f"{one(setting, 'ciamLocator')}: {m.label} binds no {role}")
    if is_a(b, "ciamSecretRef") or is_a(b, "ciamKeyRef"):
        return "${secret:" + one(b, "ciamRefUri") + "}"
    value = one(b, attr)
    if value is None:
        raise ValueError(f"{one(setting, 'ciamLocator')}: {role} in {m.label} has no {attr}")
    return value


def setting_value(setting, m=None):
    """A setting's value: its link resolved for environment m, else its literal; ValueError when it has neither."""
    if one(setting, "ciamValueFrom") and m is not None:
        return _linked(setting, m)
    if one(setting, "ciamSettingValue") is not None:
        return one(setting, "ciamSettingValue")
    if one(setting, "ciamSecretRequired") == "TRUE":
        raise ValueError(f"{one(setting, 'ciamLocator')}: its value was withheld; link it to a secret reference")
    if one(setting, "ciamValueFrom"):
        raise ValueError(f"{one(setting, 'ciamLocator')}: its value comes from an environment; name one")
    return ""


def captured_files(d):
    """Every captured file entry, in DN order."""
    return children(d, CONFIG_FILES, "ciamConfigFile")


def deployed_files(d, m):
    """The captured files environment m receives: those whose deploy role it runs, on its servers or on Kubernetes
    (the file goes into the image or the pod's configuration there), or that name none."""
    roles = {*(one(s, "ciamServerRole") for s in m.servers), *kubernetes_roles(m)}
    return tuple(f for f in captured_files(d) if one(f, "ciamTargetRole") in (None, *roles))


def _problem(setting, m):
    try:
        setting_value(setting, m)
        return None
    except ValueError as e:
        return str(e)


def render_problems(d, file_entry, m):
    """Why a captured file can't be rendered for environment m: held only as a reference, or settings whose value
    can't be found there (a link to a role m doesn't bind, a withheld value with no secret reference). Empty when
    it renders."""
    if one(file_entry, "ciamCaptureLevel") == "reference":
        return (f"held only as a reference ({one(file_entry, 'ciamCaptureProblem')})",)
    settings = children(d, file_entry.dn, "ciamConfigSetting")
    return tuple(p for p in (_problem(s, m) for s in settings) if p)


def linked(d, file_entry):
    """Whether any setting of the file takes its value from the environment (so it differs between environments)."""
    return any(one(s, "ciamValueFrom") for s in children(d, file_entry.dn, "ciamConfigSetting"))


def rebuild(d, fmt, file_entry, m=None):
    """The file's text from the record: its whole text, or its layout with every setting's value (links resolved
    for environment m). ValueError for a file held only as a reference, or a setting without a value."""
    level = one(file_entry, "ciamCaptureLevel")
    if level == "reference":
        raise ValueError(f"{one(file_entry, 'cn')} is held only as a reference: the file stays at "
                         f"{one(file_entry, 'ciamRepoPath')} ({one(file_entry, 'ciamCaptureProblem')})")
    if level == "whole-file":
        return one(file_entry, "ciamSkeleton")
    settings = {one(s, "ciamLocator"): s for s in children(d, file_entry.dn, "ciamConfigSetting")}
    parts = slots_of(one(file_entry, "ciamSkeleton"))
    missing = [p[1] for p in parts if not isinstance(p, str) and p[1] not in settings]
    if missing:
        raise ValueError(f"{one(file_entry, 'cn')}: settings missing from the record: {', '.join(missing)}")
    skeleton = tuple(p if isinstance(p, str) else Slot(p[1], one(settings[p[1]], "ciamSettingRaw") or "")
                     for p in parts)
    values = {loc: setting_value(s, m) for loc, s in settings.items()}
    return render_captured(fmt, Captured(fmt.name, skeleton, ()), values)
