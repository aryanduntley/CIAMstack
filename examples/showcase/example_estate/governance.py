"""Governance fixture data: owners (10-owners), change records (20-changes), work instructions
(65-runbooks) and incidents (85-incidents)."""
from .common import AWS, CERTS, CHG, DECL, INC, INTS, OWN, RB, R, owner, spec, t
from .estate import COST_CENTERS

PARTIES = (      # cn, kind, mail, contact url, display name
    ("ciam-platform", "team", "ciam-platform@example-aero.test", None, "CIAM platform team"),
    ("customer-portal-team", "team", "customer-portal@example-aero.test", None, None),
    ("supplier-portal-team", "team", "supplier-portal@example-aero.test", None, None),
    ("mro-analytics-team", "team", "mro-analytics@example-aero.test", None, None),
    ("tech-pubs-team", "team", "tech-pubs@example-aero.test", None, None),
    ("mobile-team", "team", "mobile@example-aero.test", None, None),
    ("network-security", "team", "netsec@example-aero.test", None, None),
    ("cloud-landing-zone", "team", "landing-zone@example-aero.test", None, "Cloud landing zone team"),
    ("corporate-dns", "team", "dns@example-aero.test", "https://servicedesk.example-aero.test/dns", "Corporate DNS team"),
    ("skyline-air", "partner", "identity-ops@skyline-air.example", "https://partners.skyline-air.example/it-requests", None),
    ("harbor-mro", "partner", "it-security@harbor-mro.example", "https://portal.harbor-mro.example/support", None),
    ("example-aero", "operator", None, None, "Example Aero"),
)
CHANGES = (
    ("CHG-0877", "Grant PingFederate read access to profile attributes", "applied", "CAB 2024-01-02", "2024-01-03"),
    ("CHG-0931", "Reconfigure mail index (equality only)", "applied", "CAB 2026-06-11", "2026-06-14"),
    ("CHG-2040", "Allow target DS subnet on the replication port", "applied", "CAB 2026-09-04", "2026-09-06"),
    ("CHG-2001", "Add NSG rule for the MRO batch export in the target environment", "approved", "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2003", "Restore the stable LDAPS service name in the target environment", "approved", "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2004", "Import the partner realm's PingAM configuration (Amster export)", "approved", "CAB 2026-09-18",
     "2026-09-22"),
    ("CHG-2005", "Name the secrets the IDM connectors and PingFederate data stores use (credential roles)", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2006", "Record the production directory servers' configuration (config.ldif exports)", "approved",
     "CAB 2026-09-18", "2026-09-20"),
    ("CHG-2007", "Record the directory's consumers from the production access logs", "approved", "CAB 2026-09-18",
     "2026-09-23"),
    ("CHG-2008", "Import PingFederate's configuration (Admin API bulk export)", "approved", "CAB 2026-09-18",
     "2026-09-23"),
    ("CHG-2009", "Census of the servers' and applications' files for values of the record", "approved",
     "CAB 2026-09-18", "2026-09-23"),
    ("CHG-2010", "Import the platform's hidden automation (servers' schedulers, CI pipelines)", "approved",
     "CAB 2026-09-18", "2026-09-23"),
    ("CHG-2011", "Name the owners of the imported jobs", "approved", "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2012", "Import the servers' host baselines", "approved", "CAB 2026-09-18", "2026-09-23"),
    ("CHG-2013", "Record the corporate root CA the PingFederate servers trust", "approved", "CAB 2026-09-18",
     "2026-09-24"),
    ("CHG-2014", "Record the shape of the production user data (values-free data profile)", "approved",
     "CAB 2026-09-18", "2026-09-23"),
    ("CHG-2015", "Forward the AD domain to the domain controllers from the target environment", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2016", "Keep the target's grant database's backups 14 days and protect it from deletion", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2017", "Give the target environment its directory backup target", "approved", "CAB 2026-09-18",
     "2026-09-24"),
    ("CHG-2018", "Make the target's directory data volume as large as production's", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2019", "Snapshot the target's directory data volume daily with Azure Backup", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2020", "Fetch AWS's region list into the region catalog (prerequisite aws-regions)", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2021", "Fetch Azure's region list into the region catalog (prerequisite azure-regions)", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2022", "Fetch Google Cloud's region list into the region catalog (prerequisite gcp-regions)", "approved",
     "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2023", "Hold the estate's environments to the us residency", "approved", "CAB 2026-09-18", "2026-09-24"),
    ("CHG-2002", "Grant legacy report account write access", "proposed", None, None),
)
RUNBOOKS = (
    ("WI-CIAM-001", "Rotate a partner SAML signing certificate", "2026-05-10",
     [f"cn=skyline-air-idp-signing,{CERTS}", f"cn=harbor-mro-idp-signing,{CERTS}"]),
    ("WI-CIAM-002", "Rotate the directory LDAPS certificate", "2026-08-01", [f"cn=ds-ldaps-2026,{CERTS}"]),
    ("WI-CIAM-004", "Add or rebuild a backend index", "2026-02-01",
     [f"cn=mail,cn=userData,ou=backends,{DECL}", f"cn=uid,cn=userData,ou=backends,{DECL}"]),
    ("WI-CIAM-007", "Recover replication after a replica outage", "2026-08-01", [f"cn=topology,ou=replication,{DECL}"]),
    ("WI-CIAM-010", "Onboard a SAML application", "2026-03-15",
     [f"cn=customer-portal,{INTS}", f"cn=pf-signing-2025,{CERTS}"]),
    ("WI-CIAM-012", "Use the break-glass account (directory root)", "2025-11-03",
     [f"cn=secret-ds-root-password,ou=bindings,{AWS}"]),
    ("WI-CIAM-015", "Restore a directory server's data volume from a snapshot", "2026-08-14",
     [f"cn=vol-ds-data,ou=bindings,{AWS}"]),
    ("WI-CIAM-016", "Fail production over to the warm standby", "2026-09-10", None),
)
# restore tests done: (cn, date, environment, role restored, restored from, level, result, minutes, what was done)
RESTORE_TESTS = (
    ("RT-2026-08-14-ds-data", "2026-08-14", AWS, "volume-ds-data", "snapshots-daily", "application", "passed", 95,
     "ds-2's data volume restored from the night's snapshot onto a scratch server; PingDS started on it, "
     "verify-integrity passed and the replication status was read"),
)


def owners():
    return tuple(spec("10-owners", f"cn={cn},{OWN}", ["top", "ciamParty", *(("ciamChargedParty",) if cn in COST_CENTERS
                                                                            else ())],
                      cn=cn, ciamOwnerKind=kind, mail=mail, ciamContactUrl=url, ciamDisplayName=display,
                      ciamCostCenter=COST_CENTERS.get(cn))
                 for cn, kind, mail, url, display in PARTIES)


def changes():
    return tuple(spec("20-changes", f"cn={cn},{CHG}", ["top", "ciamChange"], cn=cn, ciamTitle=title,
                      ciamChangeStatus=status, ciamApprovedBy=by, ciamPlannedAt=t(when) if when else None)
                 for cn, title, status, by, when in CHANGES)


def runbooks():
    return tuple(spec("65-runbooks", f"cn={cn},{RB}", ["top", "ciamRunbook"], cn=cn, ciamTitle=title, ciamVersion="1.0",
                      ciamLastValidated=t(validated), ciamAppliesTo=applies,
                      ciamDocUrl=f"https://wiki.example-aero.test/ciam/{cn}", ciamOwner=owner("ciam-platform"))
                 for cn, title, validated, applies in RUNBOOKS)


def restore_tests():
    """The restore tests done (the target has none yet: the planner asks for one before cutover)."""
    return tuple(spec("86-restore-tests", f"cn={cn},ou=restore-tests,{R}", ["top", "ciamRestoreTest"], cn=cn,
                      ciamTestedOn=t(on, "100000"), ciamTestEnvironment=env, ciamRestoredRole=role,
                      ciamRestoredFromRole=src, ciamRestoreLevel=level, ciamTestResult=result,
                      ciamRestoreMinutes=minutes, ciamRunbookRef=f"cn=WI-CIAM-015,{RB}", description=what,
                      ciamOwner=owner("ciam-platform"))
                 for cn, on, env, role, src, level, result, minutes, what in RESTORE_TESTS)


def incidents():
    return (spec("85-incidents", f"cn=INC-2231,{INC}", ["top", "ciamIncident"], cn="INC-2231",
                 ciamTitle="Search latency spike on ds-2", ciamOpenedAt=t("2026-09-14", "141200"), ciamSeverity="sev3",
                 ciamInvolved=[f"cn=ds-2,{AWS}", f"cn=mail,cn=userData,ou=backends,{DECL}"],
                 ciamRootCause="mail equality index missing on ds-2 (unrecorded manual change); searches by mail went "
                               "unindexed",
                 ciamOwner=owner("ciam-platform")),)
