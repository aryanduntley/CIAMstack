"""What of the record an OSCAL document is about: the operator's system boundaries (ciamSystemBoundary) and the
environments inside each, the POA&M items, exceptions and assessments that name those environments, the control
responsibilities under the authorizations they rely on, and an assessment's own POA&M items. Reads the estate domain's
entries; changes nothing. Pure."""
from opsdir.core.directory import get, norm_dn, one, rdn_value, subtree, values
from opsdir.core.naming import SUFFIX, env_label
from opsdir.domains.estate.naming import BOUNDARIES

ITEM, EXCEPTION, ASSESSMENT = "ciamPoamItem", "ciamRiskException", "ciamComplianceAssessment"
BOUNDARY, RESPONSIBILITY = "ciamSystemBoundary", "ciamControlResponsibility"
DEVIATIONS = {"approved": "deviation-approved", "requested": "deviation-requested"}   # exceptions written as risks


def boundaries(d):
    """The operator's system boundaries, by name."""
    return tuple(sorted(subtree(d, BOUNDARIES, BOUNDARY), key=rdn_value))


def environments(e):
    """The DNs of the environments an entry names (ciamAffectedEnvironment), as the record compares them."""
    return frozenset(norm_dn(r) for r in values(e, "ciamAffectedEnvironment"))


def labels(dns):
    """The labels (cloud/env) of environment DNs, sorted."""
    return sorted(env_label(dn) for dn in dns)


def system_id(b):
    """The id a boundary's documents carry: the SSP it names (ciamSspRef), else its name."""
    return one(b, "ciamSspRef") or rdn_value(b)


def _naming(d, oc, envs):
    return tuple(sorted((e for e in subtree(d, SUFFIX, oc) if environments(e) & envs), key=rdn_value))


def boundary_items(d, b):
    """The POA&M items naming an environment inside a boundary, by name."""
    return _naming(d, ITEM, environments(b))


def boundary_exceptions(d, b):
    """The exceptions (requested or approved: deviations) naming an environment inside a boundary, by name."""
    return tuple(e for e in _naming(d, EXCEPTION, environments(b)) if one(e, "ciamExceptionStatus") in DEVIATIONS)


def item_exceptions(exceptions, item):
    """The exceptions that belong to a POA&M item (ciamPoamRef)."""
    return tuple(e for e in exceptions if norm_dn(one(e, "ciamPoamRef") or "") == norm_dn(item.dn))


def boundary_responsibilities(d, b):
    """(authorization, responsibility) for each control responsibility under an authorization an environment inside
    the boundary relies on (its ciamAuthorizationRef), by authorization and name."""
    auths = {norm_dn(a) for env in environments(b) for e in (get(d, env),) if e is not None
             for a in values(e, "ciamAuthorizationRef")}
    return tuple(sorted(((get(d, one(r, "ciamAuthorizationRef")), r) for r in subtree(d, SUFFIX, RESPONSIBILITY)
                        if norm_dn(one(r, "ciamAuthorizationRef") or "") in auths and
                        get(d, one(r, "ciamAuthorizationRef")) is not None),
                       key=lambda pair: (rdn_value(pair[0]), rdn_value(pair[1]))))


def assessments(d):
    """The compliance assessments, by name."""
    return tuple(sorted(subtree(d, SUFFIX, ASSESSMENT), key=rdn_value))


def assessment_items(d, a):
    """An assessment's open POA&M items: those whose ciamAssessmentRef names it (its name or its own reference)."""
    names = {rdn_value(a), *values(a, "ciamAssessmentRef")}
    return tuple(sorted((i for i in subtree(d, SUFFIX, ITEM) if one(i, "ciamAssessmentRef") in names
                         and one(i, "ciamPoamStatus") == "open"), key=rdn_value))
