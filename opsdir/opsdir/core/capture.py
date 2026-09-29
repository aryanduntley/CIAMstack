"""Config files held in the record and rebuilt from it byte for byte.

A captured file is its format's name, a skeleton and its settings. The skeleton is the file's text cut at every
setting: literal text (comments, layout, keys, punctuation) and Slots, each the place of one setting with its raw text
exactly as the file had it. A locator a file repeats (a key given twice) is numbered from its second occurrence:
key, key#2, key#3. The settings are (locator, value) in file order: the values the record manages. Rendering
writes a slot's original raw text while its value is unchanged, so an unchanged file comes back identical, and the
codec's encoding of the new value when it changed. A file its codec can't reproduce exactly is refused.

Failures are ValueErrors naming where and why (line and column where the codec can tell); attempt_capture returns
the problem instead, so a caller can fall back (store the file whole, or only point to it).
"""
from collections import Counter
from itertools import groupby
from typing import NamedTuple

Slot = NamedTuple("Slot", [("locator", str), ("raw", str)])
Captured = NamedTuple("Captured", [("format", str), ("skeleton", tuple), ("settings", tuple)])


def _duplicates(locators):
    return sorted(x for x, n in Counter(locators).items() if n > 1)


def _numbered(parts):
    """Slots for the codec's (locator, raw) parts, repeated locators numbered from their second occurrence."""
    positions = [i for i, p in enumerate(parts) if not isinstance(p, str)]
    locators = [parts[i][0] for i in positions]
    order = sorted(range(len(locators)), key=lambda k: (locators[k], k))
    nth = {k: n for _, same in groupby(order, key=lambda k: locators[k]) for n, k in enumerate(same)}
    names = {i: locators[k] if nth[k] == 0 else f"{locators[k]}#{nth[k] + 1}" for k, i in enumerate(positions)}
    return tuple(Slot(names[i], p[1]) if i in names else p for i, p in enumerate(parts))


def capture(fmt, text):
    """The file as a Captured: skeleton and settings. Refuses a format without a codec, settings whose numbered
    locators still collide, and a file that doesn't render back to exactly the same text."""
    if fmt.codec is None:
        raise ValueError(f"files in {fmt.name} can't be captured as settings (the format registers no codec)")
    skeleton = _numbered(tuple(fmt.codec.split(text)))
    slots = [p for p in skeleton if isinstance(p, Slot)]
    repeated = _duplicates([s.locator for s in slots])
    if repeated:
        raise ValueError(f"{fmt.name} settings share a locator: {', '.join(repeated)}")
    captured = Captured(fmt.name, skeleton, tuple((s.locator, fmt.codec.decode(s.raw)) for s in slots))
    if render_captured(fmt, captured, dict(captured.settings)) != text:
        raise ValueError(f"this {fmt.name} file can't be captured exactly (it would not render back identical)")
    return captured


def attempt_capture(fmt, text):
    """(Captured, None), or (None, why the file can't be captured as settings)."""
    try:
        return capture(fmt, text), None
    except ValueError as e:
        return None, str(e)


def _slot_text(codec, slot, values):
    if slot.locator not in values:
        raise ValueError(f"no value for setting {slot.locator}")
    value = values[slot.locator]
    return slot.raw if value == codec.decode(slot.raw) else codec.encode(value, slot.raw)


def render_captured(fmt, captured, values):
    """The file's text with each setting's value from values ({locator: value}): its original raw text while
    unchanged, the codec's encoding once changed."""
    return "".join(p if isinstance(p, str) else _slot_text(fmt.codec, p, values) for p in captured.skeleton)


def changed_settings(captured, values):
    """(locator, captured value, new value) for every setting values change."""
    return tuple((loc, v, values[loc]) for loc, v in captured.settings if loc in values and values[loc] != v)
