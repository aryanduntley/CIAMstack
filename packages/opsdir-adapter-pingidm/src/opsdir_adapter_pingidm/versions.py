"""What changes between PingIDM releases (contract.VersionChange; milestone 86), from the vendor's release notes
(research 2402): what the record holds that each change touches, so the planner names it when a move upgrades IDM.
Pure."""
import re

from opsdir.core.contract import VersionChange
from opsdir.core.directory import children, one
from opsdir.domains.compute.hosts import baseline_for
from opsdir.domains.configuration.record import touching_files
from .naming import CONNECTORS, SERVER_ROLES

SELF_SERVICE = r"^pingidm/conf/selfservice[-.]"
LOGGING = r"^pingidm/conf/logging\.properties$"
DATASOURCES = r"^pingidm/conf/datasource\.jdbc-[^/]*\.json$"
# connectors IDM 8 no longer ships (bundle or implementation name): Office 365 (replaced by Microsoft Graph), the
# .NET Active Directory connector, Scripted CREST (replaced by Scripted REST)
REMOVED_CONNECTORS = re.compile(r"office365|scriptedcrest|ActiveDirectoryConnector", re.IGNORECASE)
JAVA = 21                                    # the Java release PingIDM 8.1 requires


def _ours(role):
    return role in SERVER_ROLES


def removed_connectors(d, m, role):
    """The record's connectors whose bundle or implementation IDM 8 removed."""
    named = lambda c: f"{one(c, 'pingidmBundle') or ''} {one(c, 'pingidmConnectorName') or ''}"    # noqa: E731
    return tuple(one(c, "cn") for c in children(d, CONNECTORS, "pingidmConnector")
                 if REMOVED_CONNECTORS.search(named(c))) if _ours(role) else ()


def _java_release(jdk):
    found = re.search(r"(\d+)", (jdk or "").rsplit(" ", 1)[-1])
    return int(found.group(1)) if found else None


def older_java(d, m, role):
    """The host baseline of environment m's IDM servers when it records a Java release older than IDM 8.1 needs."""
    b = baseline_for(d, role, m) if _ours(role) else None
    release = _java_release(one(b, "ciamJdk")) if b is not None else None
    return (f"host baseline {role}: {one(b, 'ciamJdk')}",) if release is not None and release < JAVA else ()


VERSION_CHANGES = (
    VersionChange(">=8.0", "standalone self-service (password reset, registration, KBA) is removed",
                  "captured self-service configuration", "blocker", "Move self-service to PingAM journeys (or "
                  "PingOne) and drop the captured selfservice files before the cutover.",
                  touching_files(SELF_SERVICE, SERVER_ROLES)),
    VersionChange(">=8.0", "the Office 365, .NET Active Directory and Scripted CREST connectors are removed",
                  "connectors", "blocker", "Replace them (Microsoft Graph, the LDAP connector for Active Directory, "
                  "Scripted REST) and record the new connectors.", removed_connectors),
    VersionChange(">=8.0", "logging moves from java.util.logging to Logback (conf/logback.xml); "
                  "conf/logging.properties is no longer read", "captured logging configuration", "action",
                  "Carry the levels and handlers over to conf/logback.xml and capture it.",
                  touching_files(LOGGING, SERVER_ROLES)),
    VersionChange(">=8.0", "Jetty 12: conf/jetty.xml is removed (webserver.json and webserver.listener-*.json "
                  "configure the listeners)", "the web server configuration, which the record doesn't hold", "info",
                  "Where a deployment customised conf/jetty.xml, carry it over to webserver.json and "
                  "webserver.listener-*.json and capture them."),
    VersionChange(">=8.0", "the embedded DS repository is removed", "IDM's repository", "info",
                  "Its repository must be an external directory server or a JDBC database."),
    VersionChange((">=7.5.3,<8", ">=8.0.2"), "the Oracle datasource template uses UCP (a service-name URL, "
                  "connectionWaitTimeout)", "captured JDBC datasources", "info", "For an Oracle repository, compare "
                  "the captured datasource with the release's template.", touching_files(DATASOURCES, SERVER_ROLES)),
    VersionChange(">=8.1", f"Java {JAVA} is required", "the IDM servers' host baseline", "action",
                  f"Record a Java {JAVA} JDK in the baseline and build the target's servers or image with it.",
                  older_java),
    VersionChange(">=8.1", "/openidm/info/ping and /openidm/health are deprecated (/openidm/health/live and "
                  "/ready)", "health checks", "info", "The render and the edge's health checks use "
                  "/openidm/health/ready from 8.1; move outside monitors too."),
    VersionChange(">=8.1", "the legacy admin UI is no longer bundled", "operators' admin access", "info",
                  "Deploy the separate admin UI where operators use it (ForgeOps' idm-admin-ui component)."),
)
