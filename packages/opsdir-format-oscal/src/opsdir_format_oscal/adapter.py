"""The `oscal` compliance adapter: declaration-only (it renders only where a stack declares it). Its environment-neutral
render writes the record's OSCAL documents: each system boundary's POA&M (oscal/<boundary>/poam.json) and SSP
(oscal/<boundary>/ssp.json), and each compliance assessment's results (oscal/assessment-results-<assessment>.json);
its notes name what they hold UNBOUND, the documents it couldn't write and the control ids written in interim form.
Its importers read OSCAL POA&Ms, assessment results and catalogs. Pure."""
from opsdir.core.contract import Adapter, Importer
from opsdir.core.directory import rdn_value, subtree, values
from opsdir.core.jsondata import indented
from opsdir.core.naming import SUFFIX
from opsdir.core.notes import note

from .common import AREA, control_id, slug
from .poam import poam_document
from .readers import read_assessment_results, read_catalog, read_poam
from .record import EXCEPTION, ITEM, RESPONSIBILITY, assessments, boundaries, boundary_items
from .results import assessment_results_document
from .ssp import has_ssp, ssp_document

FILES = (("oscal/*.json", "oscal-json"),)


def oscal_documents(d):
    """{path: OscalDoc} of every OSCAL document the record gives: a boundary's POA&M where POA&M items name its
    environments, its SSP where control responsibilities apply to it, an assessment's results."""
    named = {}
    for b in boundaries(d):
        at = f"oscal/{slug(rdn_value(b))}"
        named.update({f"{at}/poam.json": poam_document(d, b)} if boundary_items(d, b) else {})
        named.update({f"{at}/ssp.json": ssp_document(d, b)} if has_ssp(d, b) else {})
    named.update({f"oscal/assessment-results-{slug(rdn_value(a))}.json": assessment_results_document(d, a)
                  for a in assessments(d)})
    return named


def render_oscal(d):
    """The environment-neutral render: every OSCAL document the record gives, as JSON."""
    return {p: indented(doc.document) for p, doc in sorted(oscal_documents(d).items())}


def _unwritten(d):
    return tuple(note(AREA, "note", f"OSCAL {what} of {rdn_value(b)}", f"not written: {why}", (how,), entry=b.dn)
                 for b in boundaries(d) for what, has, why, how in (
                     ("POA&M", boundary_items(d, b), "no POA&M item names its environments",
                      "Nothing to do unless the boundary has weaknesses to track"),
                     ("SSP", has_ssp(d, b), "no control responsibility applies to it",
                      "Record the control responsibilities under the authorizations its environments rely on"))
                 if not has)


def _interim(d):
    """A note per framework whose control ids are written in interim form ('_' before a digit-led id)."""
    frameworks = sorted({control_id(r)[0] for oc in (ITEM, EXCEPTION, RESPONSIBILITY) for e in subtree(d, SUFFIX, oc)
                         for r in values(e, "ciamControlRef") if ":" in r and control_id(r)[1].startswith("_")})
    return tuple(note(AREA, "note", f"OSCAL control ids of {fw}", "written as '_' and the recorded id (_3.13.11): "
                      "OSCAL ids can't start with a digit, and the framework's OSCAL catalog may name them otherwise "
                      "(interim)", ("Check them against the framework's catalog: `opsdir import oscal/catalog FILE` "
                                    "names the controls it doesn't hold",)) for fw in frameworks)


def oscal_notes(m, services):
    """The render's notes: each document's (its UNBOUND fields), the documents not written, the interim control ids."""
    return (*(n for _, doc in sorted(oscal_documents(m.d).items()) for n in doc.notes), *_unwritten(m.d),
            *_interim(m.d))


POAM_IMPORTER = Importer("poam", "An OSCAL plan of action and milestones (JSON), as the POA&M items of the system "
                                 "boundary its system-id names", read_poam)
RESULTS_IMPORTER = Importer("assessment-results", "OSCAL assessment results (JSON), as compliance assessments and "
                                                  "their not-satisfied findings as POA&M items",
                            read_assessment_results)
CATALOG_IMPORTER = Importer("catalog", "An OSCAL catalog (JSON), checked against the controls the record names "
                                       "(nothing imported)", read_catalog)

ADAPTER = Adapter(name="oscal", kind="compliance", applies=None, required_roles=(), render_neutral=render_oscal,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None,
                  neutral_label="OSCAL documents", vocabulary={}, schema=None, formats=FILES, products=(),
                  secret_patterns=(), importers=(POAM_IMPORTER, RESULTS_IMPORTER, CATALOG_IMPORTER),
                  profile_terms=None, access=None, notes=oscal_notes)
