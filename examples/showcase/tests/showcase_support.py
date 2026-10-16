"""Showcase test support: where the example estate lives, the approved changes it applies, the estate as an
in-memory directory, the snapshot of every command, and its scripts as modules."""
import datetime as dt
import importlib.util
from functools import reduce
import os
import pathlib
import subprocess
from collections import namedtuple
from typing import NamedTuple

from opsdir import operations as ops
from opsdir.cli import import_time, read_texts
from opsdir.connectors.capture import census_changes
from opsdir.connectors import importing
from opsdir.connectors.evidence import assemble_package, directory_output
from opsdir.connectors.reports import HISTORY_HEADERS, catalogue
from opsdir.core.directory import norm_dn
from opsdir.domains.estate.evidence import boundary_named, run_records
from opsdir.store import postgres as db
from opsdir.store.postgres import read_ldif_files
from support import build_directory, schema_for

SHOWCASE = pathlib.Path(__file__).resolve().parents[1]
DATA = SHOWCASE / "data"
GOLDEN = SHOWCASE / "golden"
SCRIPTS = SHOWCASE / "scripts"
# An approved change made by an import (the record's region catalog fetched from a provider): the importer, the export
# directory, when it was taken, and the conflicts it decides (keys taking the live value, keys keeping the record's).
ImportStep = namedtuple("ImportStep", ("spec", "root", "at", "take", "keep"), defaults=((), ()))
# An approved change that records a system boundary's evidence package (`opsdir evidence --change`): the boundary.
EvidenceStep = NamedTuple("EvidenceStep", [("boundary", str)])
REGIONS = SHOWCASE / "exports" / "regions"
QUOTAS = SHOWCASE / "exports" / "quotas"
FRAMEWORKS = SHOWCASE / "exports" / "frameworks"
# CHG-2048's decision on the lab Panorama's read-back: keep the record's admin range (the next push restores it)
FIREWALL_ADMIN = "cn=fw-admin,ou=bindings,env=lab,cloud=hq,ou=environments,dc=ciam-ops|ciamSourceCidr"
# the approved changes the showcase applies, in order: (change id, LDIF file, ImportStep or EvidenceStep)
APPROVED = (("CHG-2001", SHOWCASE / "changes" / "CHG-2001-mro-firewall-target.ldif"),
            ("CHG-2003", SHOWCASE / "changes" / "CHG-2003-stable-ldaps-name.ldif"),
            ("CHG-2005", SHOWCASE / "changes" / "CHG-2005-credential-roles.ldif"),
            ("CHG-2011", SHOWCASE / "changes" / "CHG-2011-job-owners.ldif"),
            ("CHG-2013", SHOWCASE / "changes" / "CHG-2013-corporate-ca.ldif"),
            ("CHG-2015", SHOWCASE / "changes" / "CHG-2015-target-ad-forwarder.ldif"),
            ("CHG-2016", SHOWCASE / "changes" / "CHG-2016-grant-database-protection.ldif"),
            ("CHG-2017", SHOWCASE / "changes" / "CHG-2017-target-backup-container.ldif"),
            ("CHG-2018", SHOWCASE / "changes" / "CHG-2018-target-directory-volume-size.ldif"),
            ("CHG-2019", SHOWCASE / "changes" / "CHG-2019-target-disk-backup.ldif"),
            ("CHG-2020", ImportStep("aws/regions", REGIONS / "aws", "20260923090000Z")),
            ("CHG-2021", ImportStep("azure/regions", REGIONS / "azure", "20260923090000Z")),
            ("CHG-2022", ImportStep("gcp/regions", REGIONS / "gcp", "20260923090000Z")),
            ("CHG-2023", SHOWCASE / "changes" / "CHG-2023-us-residency.ldif"),
            ("CHG-2024", SHOWCASE / "changes" / "CHG-2024-target-config-history.ldif"),
            ("CHG-2025", ImportStep("aws/quotas", QUOTAS / "aws", "20260923090000Z")),
            ("CHG-2026", ImportStep("azure/quotas", QUOTAS / "azure", "20260923090000Z")),
            ("CHG-2027", ImportStep("gcp/quotas", QUOTAS / "gcp", "20260923090000Z")),
            ("CHG-2028", SHOWCASE / "changes" / "CHG-2028-target-budget-and-quota.ldif"),
            ("CHG-2029", SHOWCASE / "changes" / "CHG-2029-target-incident-reporting.ldif"),
            ("CHG-2030", SHOWCASE / "changes" / "CHG-2030-target-exceptions.ldif"),
            ("CHG-2031", ImportStep("fedramp/cpo", SHOWCASE / "exports" / "fedramp", "20260923090000Z")),
            ("CHG-2032", SHOWCASE / "changes" / "CHG-2032-target-ssp-and-key-management.ldif"),
            ("CHG-2033", SHOWCASE / "changes" / "CHG-2033-target-boundary.ldif"),
            ("CHG-2034", SHOWCASE / "changes" / "CHG-2034-target-data-discovery.ldif"),
            ("CHG-2035", ImportStep("onprem/sites", SHOWCASE / "exports" / "sites" / "onprem", "20260923090000Z")),
            ("CHG-2036", SHOWCASE / "changes" / "CHG-2036-scoped-agents-and-jobs.ldif"),
            ("CHG-2037", SHOWCASE / "changes" / "CHG-2037-target-hybrid-identity.ldif"),
            ("CHG-2038", SHOWCASE / "changes" / "CHG-2038-target-change-history.ldif"),
            ("CHG-2039", SHOWCASE / "changes" / "CHG-2039-standby-compliance-frameworks.ldif"),
            ("CHG-2041", ImportStep("gcp/frameworks", FRAMEWORKS / "gcp", "20260923090000Z")),
            ("CHG-2042", SHOWCASE / "changes" / "CHG-2042-standby-itar-data.ldif"),
            ("CHG-2043", SHOWCASE / "changes" / "CHG-2043-target-profiles.ldif"),
            ("CHG-2044", SHOWCASE / "changes" / "CHG-2044-skyline-signing-answer.ldif"),
            ("CHG-2046", EvidenceStep("SSP-CIAM-2026")),
            ("CHG-2047", ImportStep("cyberark/accounts", SHOWCASE / "exports" / "cyberark", "20260923090000Z")),
            ("CHG-2048", ImportStep("panos/running-config", SHOWCASE / "exports" / "panos", "20260923090000Z",
                                    keep=(FIREWALL_ADMIN,))),
            ("CHG-2049", ImportStep("splunk/rest", SHOWCASE / "exports" / "splunk", "20260923090000Z")),
            ("CHG-2050", ImportStep("adcs/inventory", SHOWCASE / "exports" / "adcs", "20260923090000Z")),
            ("CHG-2051", SHOWCASE / "changes" / "CHG-2051-issuing-ca-and-template-owners.ldif"),
            ("CHG-2055", SHOWCASE / "changes" / "CHG-2055-ticket-links.ldif"),
            ("CHG-2056", ImportStep("servicenow/change-requests", SHOWCASE / "exports" / "servicenow",
                                    "20260923090000Z")),
            ("CHG-2060", SHOWCASE / "changes" / "CHG-2060-pingaccess-servers.ldif"),
            ("CHG-2061", ImportStep("pingaccess/admin-api", SHOWCASE / "exports" / "pingaccess", "20260923090000Z")),
            ("CHG-2062", SHOWCASE / "changes" / "CHG-2062-pingaccess-session-and-header.ldif"),
            ("CHG-2063", ImportStep("siteminder/xps", SHOWCASE / "exports" / "siteminder", "20260923090000Z")),
            ("CHG-2064", SHOWCASE / "changes" / "CHG-2064-siteminder-owners-and-aog-to-sso.ldif"),
            ("CHG-2065", ImportStep("pingfederate/bulk", SHOWCASE / "exports" / "pingfederate-aog", "20260923090000Z")),
            ("CHG-2066", SHOWCASE / "changes" / "CHG-2066-target-partners-external-id.ldif"),
            ("CHG-2067", SHOWCASE / "changes" / "CHG-2067-source-tech-pubs-user-pool.ldif"),
            ("CHG-2068", SHOWCASE / "changes" / "CHG-2068-external-id-signing-answer.ldif"),
            ("CHG-2069", SHOWCASE / "changes" / "CHG-2069-issuing-ca-certificate.ldif"),
            ("CHG-2075", ImportStep("linux/baseline", SHOWCASE / "exports" / "hosts-pingaccess", "20260923090000Z")),
            ("CHG-2076", SHOWCASE / "changes" / "CHG-2076-pingaccess-scoped-agents.ldif"),
            ("CHG-2081", SHOWCASE / "changes" / "CHG-2081-crew-portal-client-and-target-bindings.ldif"),
            ("CHG-2082", SHOWCASE / "changes" / "CHG-2082-target-pingaccess-protects-crew-portal.ldif"),
            ("CHG-2083", SHOWCASE / "changes" / "CHG-2083-target-pinggateway-protects-tech-pubs.ldif"),
            ("CHG-2086", ImportStep("adcs/inventory", SHOWCASE / "exports" / "adcs-templates", "20260923090000Z",
                                    take=("all",))),
            ("CHG-2089", SHOWCASE / "changes" / "CHG-2089-partners-external-tenant.ldif"),
            ("CHG-2090", ImportStep("azure/external-id", SHOWCASE / "exports" / "external-id", "20260923090000Z")))
# the product exports the demo imports right after loading: (change id, importer, export directory, when taken: the
# night before, all of them)
IMPORTS = (("CHG-2004", "pingam", SHOWCASE / "exports" / "amster", "20260920030000Z"),
           ("CHG-2004", "pingidm", SHOWCASE / "exports" / "idm", "20260920030000Z"),
           ("CHG-2004", "pinggateway", SHOWCASE / "exports" / "ig", "20260920030000Z"),
           ("CHG-2006", "pingds/config", SHOWCASE / "exports" / "ds-config", "20260920030000Z"),
           ("CHG-2007", "pingds/access-log", SHOWCASE / "exports" / "ds-access-logs", "20260920030000Z"),
           ("CHG-2008", "pingfederate/bulk", SHOWCASE / "exports" / "pingfederate", "20260920030000Z"),
           ("CHG-2008", "pingfederate/node-files", SHOWCASE / "exports" / "pingfederate-nodes", "20260920030000Z"),
           ("CHG-2010", "linux/jobs", SHOWCASE / "exports" / "hosts", "20260920030000Z"),
           ("CHG-2010", "github-actions/workflows", SHOWCASE / "exports" / "pipelines", "20260920030000Z"),
           ("CHG-2012", "linux/baseline", SHOWCASE / "exports" / "hosts", "20260920030000Z"))
# then the production user data's profile, as `opsdir data-profile` writes it from ldapsearch output: (change id,
# environment, LDIF, when read, the estate's terms)
PROFILE = ("CHG-2014", "source/prod", SHOWCASE / "exports" / "ds-data" / "source-prod.ldif", "20260920030000Z",
           ("last-login=lastLoginTime", "kba=challengeAnswer", "pending=registrationStatus=pending",
            "disabled=registrationStatus=disabled"))
AS_OF = dt.date(2026, 9, 23)                     # the date the showcase runs as of
# then the census of files that copy the record's values (change id, directory)
CENSUS = ("CHG-2009", SHOWCASE / "exports" / "census")


def cmd_output(text, status=0):
    """What the snapshot script captures for a command that printed text and exited with status."""
    return f"{text}\nexit {status}\n"


def export_files(root):
    """Effect: a product export's files, {relative path: text}, as `opsdir import` reads them (.gz decompressed)."""
    return read_texts(root)[0]


def profile_files():
    """Effect (reads the LDIF): {file name: text} of the data profile `opsdir data-profile` writes (PROFILE)."""
    _, env, ldif, at, terms = PROFILE
    return {"source-prod.json": ops.data_profile(ldif.read_text().splitlines(True), env, AS_OF, import_time(at), terms)}


def import_records(schema, records):
    """Effect (reads the exports): the change records importing the product exports (IMPORTS) and the data profile
    (PROFILE) into the loaded estate makes, one after the other (each import sees what the ones before it added, as in
    the store), then the census's."""
    def step(done, imported):
        change_id, spec, files, at = imported
        d = build_directory(schema, records, done)
        plan = importing.import_plan(d, spec, files, at=import_time(at))
        return (*done, *importing.import_records(d, plan, change_id))
    imported = reduce(step, (*((c, s, export_files(root), at) for c, s, root, at in IMPORTS),
                             (PROFILE[0], "ldap/data-profile", profile_files(), PROFILE[3])), ())
    return (*imported, *census_changes(build_directory(schema, records, imported), export_files(CENSUS[1]))[0])


def import_exports(conn):
    """Effect: import the product exports (IMPORTS) and the data profile (PROFILE) into a store that holds the loaded
    estate, then take the census (CENSUS), as the demo does."""
    return [*(ops.apply_import(conn, ops.preview_import(conn, spec, export_files(root), import_time(at)), change_id)
              for change_id, spec, root, at in IMPORTS),
            ops.apply_import(conn, ops.preview_import(conn, "ldap/data-profile", profile_files(),
                                                      import_time(PROFILE[3])), PROFILE[0]),
            ops.apply_preview(conn, ops.preview_census(conn, export_files(CENSUS[1])), CENSUS[0])]


def _changed(schema, records, done, changes):
    """Effect (reads files): done followed by the change records of changes ((change id, LDIF file, ImportStep or
    EvidenceStep), ...) in order, each import and evidence run made in the estate as the changes before it leave
    it."""
    def step(so_far, change):
        change_id, source = change
        if isinstance(source, EvidenceStep):
            return (*so_far, *evidence_records(build_directory(schema, records, so_far), source.boundary, change_id))
        if not isinstance(source, ImportStep):
            return (*so_far, *read_ldif_files([source]))
        d = build_directory(schema, records, so_far)
        plan = importing.import_plan(d, source.spec, export_files(source.root), at=import_time(source.at))
        return (*so_far, *importing.import_records(d, plan, change_id, source.take, source.keep))
    return reduce(step, changes, tuple(done))


def evidence_records(d, boundary, change_id):
    """The records of a boundary's evidence run as the demo takes it (`opsdir evidence --change`), in memory: the
    directory answers every query but the change history, the store's (its times are masked in golden, and the run's
    hashes: scripts/mask-evidence.py)."""
    b, reports = boundary_named(d, boundary), catalogue()
    p = assemble_package(d, b, (), AS_OF, lambda q: directory_output(d, q, AS_OF, reports) or (HISTORY_HEADERS, ()),
                         None, reports)
    return run_records(d, b, AS_OF, {**p.files, "MANIFEST.json": p.manifest}, p.plan, change_id)


def fixture_directory(changes=()):
    """Effect (reads files): the example estate as a Directory, as the demo builds it: loaded, the product exports
    imported (IMPORTS), then after (change id, LDIF file, ImportStep or EvidenceStep) changes."""
    records = read_ldif_files(sorted(DATA.glob("*.ldif")))
    schema = schema_for(records)
    return build_directory(schema, records, _changed(schema, records, import_records(schema, records), changes))


def approved_records():
    """Effect (reads files): the change records of every approved change (APPROVED), in order (an import's as it
    makes them in the estate the changes before it leave)."""
    records = read_ldif_files(sorted(DATA.glob("*.ldif")))
    schema = schema_for(records)
    imported = import_records(schema, records)
    return _changed(schema, records, imported, APPROVED)[len(imported):]


def apply_approved(conn, changes=APPROVED):
    """Effect: apply the approved changes to a store as the demo does: an LDIF file's records, or an import."""
    for change_id, source in changes:
        if isinstance(source, EvidenceStep):
            ops.evidence(conn, source.boundary, AS_OF, change_id=change_id)
        elif isinstance(source, ImportStep):
            ops.apply_import(conn, ops.preview_import(conn, source.spec, export_files(source.root),
                                                      import_time(source.at)), change_id, source.take, source.keep)
        else:
            db.apply_changes(conn, source, change_id)


def approved_targets():
    """Effect (reads files): {normalized DN: change type} of every entry the approved changes touch, as one change set
    has it (an entry added and then modified is an add; an entry two changes modify is one modify). What tests of
    change sets expect, so adding an approved change to the showcase needs no test edits."""
    records = approved_records()
    return {n: next(r.changetype for r in records if norm_dn(r.dn) == n)
            for n in dict.fromkeys(norm_dn(r.dn) for r in records)}


def approved_attributes(dn):
    """Effect (reads files): the attributes the approved changes modify on one entry."""
    return {attr for r in approved_records() if norm_dn(r.dn) == norm_dn(dn) for _, attr, _ in r.mods}


def run_snapshot(dsn, out):
    """Effect: scripts/snapshot-outputs.sh against dsn into out (drops and reloads dsn's opsdir schema;
    regenerates the published schema and data/ in place, which must reproduce the committed files)."""
    return subprocess.run([str(SCRIPTS / "snapshot-outputs.sh"), str(out)], capture_output=True,
                          text=True, env={**os.environ, "OPSDIR_DSN": dsn}, check=False)


def load_script(name):
    """Effect: a script from scripts/ (file names with dashes) as a module."""
    path = SCRIPTS / name
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
