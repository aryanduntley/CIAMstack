"""The ForgeOps release this adapter renders for, as read in its source: the pinned release, its components (chart and
values key, Kustomize base, image, main container) and the Secrets its pods read. Data, and lookups on it. Pure.

ForgeOps is Ping Identity's deployment kit for PingAM, PingIDM, PingDS and PingGateway on Kubernetes. Its Helm charts
and Kustomize bases are supported as published; its Docker images are for development and testing only (production
customers build their own), so no image here is ForgeOps': the record names them.

Secrets: the chart and the bases are used in their secret-generator layout (the keystore-create job makes the AM/IDM
keystore from the keystore-create Secret's password) with no generator, so nothing in ForgeOps writes the Secrets the
record delivers (opsdir-adapter-kubernetes: External Secrets, CSI, or the operator).
"""
from collections import namedtuple

VERSION = "2026.3.1"
COMMIT = "8c79cbbac7ca72e579e7ab8391284785acad3690"
SOURCE = f"https://codeload.github.com/ForgeRock/forgeops/tar.gz/{COMMIT}"
SOURCE_SHA256 = "4b8ea403f4770bd0d7cdcf77c6b832157ff698e49dda6f01090242911e674c79"
PUBLIC_IMAGES = "us-docker.pkg.dev/forgeops-public/"
IDENTITY_PLATFORM, PING_GATEWAY = "identity-platform", "ping-gateway"
CHART_VERSION = "1.0.0"                 # both charts at this release
HELM, KUSTOMIZE = "helm", "kustomize"
DS_LDAPS_PORT = 1636                    # the in-cluster DS LDAPS port ForgeOps addresses (ds-idrepo-0.ds-idrepo:1636)

# One component. name: ForgeOps' own (its workload's, its overlay folder's); chart and values: its chart and key in the
# chart's values; base: its Kustomize base under kustomize/base; kind and container: its workload object and main
# container (None for a Job); image: its image's name in the Kustomize bases; helm_image: the values key of that image;
# containers: the record's container names whose image it runs (ciamContainerImage, first found wins); ingress: it has
# an Ingress of its name.
Component = namedtuple("Component", ("name", "chart", "values", "base", "kind", "container", "image", "helm_image",
                                     "containers", "ingress"))

COMPONENTS = (
    Component("am", IDENTITY_PLATFORM, "am", "am/secret-generator", "Deployment", "openam", "am", "image",
              ("openam", "am"), True),
    Component("amster", IDENTITY_PLATFORM, "amster", "amster/secret-generator", "Job", None, "amster", "image",
              ("amster",), False),
    Component("idm", IDENTITY_PLATFORM, "idm", "idm/secret-generator", "Deployment", "openidm", "idm", "image",
              ("openidm", "idm"), True),
    Component("ds-idrepo", IDENTITY_PLATFORM, "ds_idrepo", "ds/idrepo", "StatefulSet", "ds", "ds", "image",
              ("ds-idrepo", "ds"), False),
    Component("ds-cts", IDENTITY_PLATFORM, "ds_cts", "ds/cts", "StatefulSet", "ds", "ds", "image",
              ("ds-cts", "ds"), False),
    Component("ds-set-passwords", IDENTITY_PLATFORM, "ds_set_passwords", "ds/set-passwords", "Job", None, "ds",
              "image", ("ds-idrepo", "ds"), False),
    # its Java image (keytool) is AM's (IDM's without AM); its own image is ForgeOps' kubectl, left as published
    Component("keystore-create", IDENTITY_PLATFORM, "keystore_create", "keystore-create", "Job", None, "am",
              "initImage", ("openam", "am", "openidm", "idm"), False),
    Component("admin-ui", IDENTITY_PLATFORM, "admin_ui", "admin-ui", "Deployment", "admin-ui", "admin-ui", "image",
              ("admin-ui",), True),
    Component("end-user-ui", IDENTITY_PLATFORM, "end_user_ui", "end-user-ui", "Deployment", "end-user-ui",
              "end-user-ui", "image", ("end-user-ui",), True),
    Component("login-ui", IDENTITY_PLATFORM, "login_ui", "login-ui", "Deployment", "login-ui", "login-ui", "image",
              ("login-ui",), True),
    Component("ig", PING_GATEWAY, "ig", "ig", "Deployment", "ig", "ig", "image", ("ig",), True),
)
_BY_NAME = {c.name: c for c in COMPONENTS}

# The tooling images the Kustomize bases name (init containers, jobs), set to the identity-platform chart's defaults at
# this release so both targets run the same: (base image name, reference). Not products, so not the record's.
TOOLING_IMAGES = (("am-custom", "busybox:musl"), ("idm-custom", "busybox:musl"),
                  ("kubectl", f"{PUBLIC_IMAGES}images/kubectl:1.36.1"))

# The components a server role runs as (ds: by the workload's name, ForgeOps' ds-idrepo or ds-cts).
ROLE_COMPONENTS = {"am": ("am",), "idm": ("idm",), "ig": ("ig",), "ds": ("ds-idrepo", "ds-cts")}
UIS = ("admin-ui", "end-user-ui", "login-ui")

# The role a component without a workload of its own labels its pods with (opsdir.io/role), so the namespace's default
# deny of ingress lets in what reaches it: the UIs serve through the ingress as AM does (port 8080), ds-set-passwords
# reaches DS as its peers do. Jobs that only call out (amster, keystore-create) need none.
COMPANION_ROLES = (("admin-ui", "am"), ("end-user-ui", "am"), ("login-ui", "am"), ("ds-set-passwords", "ds"))

# The HTTP routes of the release's own Ingresses (kustomize/base/*/*-ingress.yaml, the charts' *-ingress.yaml), for a
# cluster gateway to serve instead: (component, roles whose service names' hosts carry it, path, match, Service, port,
# rewrite). The platform's UIs and IDM call AM and IDM on their own host, so IDM's paths are on AM's host too (and on an
# IDM service name when the record has one). IG's regex paths /ig(/|$)(.*) and /igadmin(/|$)(.*) with rewrite-target
# /$2 are prefixes replaced by /.
ROUTES = (("am", ("am",), "/am", "prefix", "am", 80, None),
          ("login-ui", ("am",), "/am/XUI", "prefix", "login-ui", 8080, None),
          ("admin-ui", ("am",), "/platform", "prefix", "admin-ui", 8080, None),
          ("end-user-ui", ("am",), "/enduser", "prefix", "end-user-ui", 8080, None),
          *(("idm", ("idm", "am"), path, "prefix", "idm", 80, None)
            for path in ("/openidm", "/upload", "/export", "/admin", "/openicf")),
          ("ig", ("ig",), "/ig", "prefix", "ig", 80, "/"),
          ("ig", ("ig",), "/igadmin", "prefix", "ig", 8085, "/"))
# The roles whose service names a chart's Ingresses serve: with any of them behind a cluster gateway, the chart's
# Ingresses are off (the gateway serves its routes).
CHART_ROLES = ((IDENTITY_PLATFORM, ("am", "idm")), (PING_GATEWAY, ("ig",)))

# What the release's pods listen on, per server role (the bases' and charts' containerPort): (role, port, purpose,
# peers) as contract.Listener's. AM, IDM and IG serve HTTP behind the ingress; DS serves LDAP and LDAPS to AM, IDM
# and its peers, its administration connector, and replication to its peers.
POD_PORTS = (("am", 8080, "HTTP (behind the ingress)", ("clients",)),
             ("idm", 8080, "HTTP (behind the ingress)", ("clients",)),
             ("ig", 8080, "HTTP (behind the ingress)", ("clients",)),
             ("ds", 1389, "LDAP", ("peers", "am", "idm")),
             ("ds", 1636, "LDAPS", ("peers", "am", "idm")),
             ("ds", 4444, "administration", ("admin",)),
             ("ds", 8989, "replication", ("peers",)))

# A Secret the release's pods read: name, keys (() when read whole and made in the cluster), readers (components),
# made: ((render target, what makes it), ...) when ForgeOps makes it in the cluster under that target.
KitSecret = namedtuple("KitSecret", ("name", "keys", "readers", "made"))
KIT_SECRETS = (
    KitSecret("am-env-secrets", ("AM_AUTHENTICATION_SHARED_SECRET", "AM_ENCRYPTION_KEY",
                                 "AM_OIDC_CLIENT_SUBJECT_IDENTIFIER_HASH_SALT", "AM_PASSWORDS_AMADMIN_CLEAR",
                                 "AM_SELFSERVICE_LEGACY_CONFIRMATION_EMAIL_LINK_SIGNING_KEY",
                                 "AM_SESSION_STATELESS_ENCRYPTION_KEY", "AM_SESSION_STATELESS_SIGNING_KEY"),
              ("am",), ()),
    KitSecret("ds-env-secrets", ("AM_STORES_APPLICATION_PASSWORD", "AM_STORES_CTS_PASSWORD", "AM_STORES_USER_PASSWORD"),
              ("am", "ds-set-passwords"), ()),
    KitSecret("amster-env-secrets", ("IDM_PROVISIONING_CLIENT_SECRET", "IDM_RS_CLIENT_SECRET"), ("amster", "idm"), ()),
    KitSecret("idm-env-secrets", ("OPENIDM_ADMIN_PASSWORD",), ("idm",), ()),
    KitSecret("ds-passwords", ("dirmanager.pw", "monitor.pw"),
              ("idm", "ds-idrepo", "ds-cts", "ds-set-passwords", "keystore-create"), ()),
    KitSecret("keystore-create", ("KEYSTORE_PASSWORD",), ("am", "idm", "keystore-create"), ()),
    KitSecret("amster", ("ssh-privatekey", "ssh-publickey"), ("am", "amster"), ((HELM, "the ssh-keygen job"),)),
    KitSecret("keystore", (), ("am", "idm"),
              ((HELM, "the keystore-create job"), (KUSTOMIZE, "the keystore-create job"))),
    KitSecret("ds-ssl-keypair", ("ca.crt", "tls.crt", "tls.key"), ("am", "idm", "ds-idrepo", "ds-cts"),
              ((HELM, "cert-manager (platform.ds_certs)"),)),
    KitSecret("ds-master-keypair", ("ca.crt", "tls.crt", "tls.key"), ("ds-idrepo", "ds-cts"),
              ((HELM, "cert-manager (platform.ds_certs)"),)),
)


def component(name):
    """The ForgeOps component of a name (am, idm, ds-idrepo, ...)."""
    return _BY_NAME[name]


# With no DS in the cluster, AM and IDM still read ds-ssl-keypair's ca.crt: the CA that signed the DS servers'
# certificates, which nothing in ForgeOps makes (its self-signed DS certificates are off).
SERVERS_CA = KitSecret("ds-ssl-keypair", ("ca.crt",), ("am", "idm"), ())


def kit_secrets(names, target):
    """((KitSecret, what makes it under the render target, or None), ...) for the Secrets the pods of these components
    read: None when the record (or the operator) supplies it. With no DS store among them, ds-ssl-keypair is
    SERVERS_CA."""
    wanted = set(names)
    servers = not wanted & set(ROLE_COMPONENTS["ds"])
    found = (SERVERS_CA if servers and s.name == SERVERS_CA.name else s for s in KIT_SECRETS)
    return tuple((s, dict(s.made).get(target)) for s in found if wanted & set(s.readers))


def public_image(ref):
    """Whether an image reference is one of ForgeOps' public images (for development and testing only)."""
    return ref.startswith(PUBLIC_IMAGES)
