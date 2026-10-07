"""The estate's tag policy: which tags every resource rendered for an environment carries and the value each takes
there (its owner, that owner's cost center, its data classification, the environment, its cloud, or a literal); what
an environment can't give a value; and, on import, the resources a cloud reports without a required tag (keys compared
in label form, as a cloud that only has lowercase labels writes them). Pure."""
import re

from ...core.directory import children, get, one, rdn_value, values
from .naming import TAG_POLICY
from .regions import named

RULE = "ciamTagRule"
EXAMPLES = 3                      # resources named per missing tag in an import notice


def tag_rules(d):
    """Every tag rule of the tag policy, by tag key."""
    return tuple(sorted(children(d, TAG_POLICY, RULE), key=lambda r: one(r, "ciamTagKey").lower()))


def _owners(m):
    return [o for o in (get(m.d, v) for v in values(m.env, "ciamOwner")) if o is not None]


def tag_value(m, rule):
    """(value, None) of a tag rule in environment m, or (None, why it has none)."""
    source, owners = one(rule, "ciamTagSource"), _owners(m)
    if source == "owner":
        return (rdn_value(owners[0]), None) if owners else (None, f"{m.label} has no owner")
    if source == "cost-center":
        charged = next((one(o, "ciamCostCenter") for o in owners if one(o, "ciamCostCenter")), None)
        return (charged, None) if charged else (
            None, f"{m.label}'s owner {rdn_value(owners[0])} has no cost center (ciamCostCenter)" if owners else
            f"{m.label} has no owner to take a cost center from")
    if source == "classification":
        level = one(m.env, "ciamDataClassification")
        return (level, None) if level else (None, f"{m.label} has no data classification (ciamDataClassification)")
    if source == "environment":
        return m.label, None
    if source == "cloud":
        return rdn_value(m.cloud), None
    literal = one(rule, "ciamTagValue")
    return (literal, None) if literal else (None, f"tag rule {rdn_value(rule)} is literal but has no ciamTagValue")


def required_tags(m):
    """{tag key: value} every resource rendered for environment m carries (rules it can give no value left out)."""
    return {one(r, "ciamTagKey"): v for r in tag_rules(m.d) for v, _ in (tag_value(m, r),) if v}


def missing_tags(m):
    """((rule, why), ...) for the tag rules environment m can give no value."""
    return tuple((r, why) for r in tag_rules(m.d) for v, why in (tag_value(m, r),) if not v)


def _label_form(key):
    return re.sub(r"[^a-z0-9_-]", "-", key.lower())


def tag_notices(d, spec, resources):
    """Import notices: the reported resources whose source gives their tags and that lack required tags (case and
    punctuation aside), one notice per set of tags lacking, naming a few of them."""
    keys = [one(r, "ciamTagKey") for r in tag_rules(d)]
    groups = {}
    for r in (r for r in resources if r.tags is not None):
        has = {_label_form(k) for k in r.tags}
        lacking = tuple(k for k in keys if _label_form(k) not in has)
        if lacking:
            groups.setdefault(lacking, []).append(r)
    return tuple(f"{spec}: {len(rs)} resource(s) lack the required tag{'s' if len(lacking) > 1 else ''} "
                 f"{', '.join(lacking)} ({_named(rs)})" for lacking, rs in groups.items())


def _named(rs):
    return named([f"{r.kind} {r.name or r.ref}" for r in rs], EXAMPLES)
