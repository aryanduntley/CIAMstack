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

VERSION = "2026.3.2"                    # 2026-10-05; Kustomize deployments deprecated from it (removal a year later)
COMMIT = "3b61b9e0a18b65c4e370dc2512f133296990b363"
SOURCE = f"https://codeload.github.com/ForgeRock/forgeops/tar.gz/{COMMIT}"
SOURCE_SHA256 = "8a9e54a1505098acfe939d16b0a8219d4c46ca94951cd9e379ce9def9ab31d77"
PUBLIC_IMAGES = "us-docker.pkg.dev/forgeops-public/"
IDENTITY_PLATFORM, PING_GATEWAY = "identity-platform", "ping-gateway"
CHART_VERSION = "1.0.0"                 # both charts at this release
HELM, KUSTOMIZE = "helm", "kustomize"
CONFIG_PROFILES = "config-profiles"     # render target: the products' configuration as ForgeOps config profiles
PROFILE_NAME = "opsdir"                 # the profile's folder under each component's config-profiles/ (CONFIG_PROFILE)
# What each component's config profile builds into (docker/<component>/ at the release): (component, product whose
# profile it carries, how: "config" a busybox configuration image (Dockerfile-custom: /config/, read by the chart's
# <component>_custom init container; its image the record names for that container), "derived" the component's own
# image rebuilt on the record's base (Dockerfile: the profile under where it reads its configuration), destination).
# AM's own file-based configuration is left to its image: the record's AM configuration is Amster's (decision 2817).
CONFIG_INIT = "custom-vol-init"       # the init container running a component's configuration image
PROFILE_BUILDS = (("idm", "PingIDM", "config", "/config/"), ("amster", "PingAM", "derived", "/opt/amster"),
                  ("ig", "PingGateway", "derived", "${IG_INSTANCE_DIR}"))
# AM's and IDM's keystore (deferred 2136 part 4): the Secret and key the release mounts it from, and the roles the
# product adapters bind it to. A workload mapping that key delivers the record's keystore; the release then makes none.
KEYSTORE_SECRET, KEYSTORE_KEY = "keystore", "keystore.jceks"
KEYSTORE_PRODUCTS = ("PingAM", "PingIDM")     # their keystore roles: Adapter.roles kind keystore (roles_for)
# The Secret the amster job reads every variable from (envFrom): a profile's secrets for amster are its keys.
AMSTER_ENV_SECRET = "amster-env-secrets"
DS_LDAPS_PORT = 1636                    # the in-cluster DS LDAPS port ForgeOps addresses (ds-idrepo-0.ds-idrepo:1636)

# One component. name: ForgeOps' own (its workload's, its overlay folder's); chart and values: its chart and key in the
# chart's values; base: its Kustomize base under kustomize/base (None: the chart's only); kind and container: its
# workload object and main container (None for a Job); image: its image's name in the Kustomize bases; helm_image: the
# values key of that image; containers: the record's container names whose image it runs (ciamContainerImage, first
# found wins); ingress: it has an Ingress of its name.
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
    # IDM's legacy administration UI as a pod of its own (PingIDM 8.1 no longer bundles it): the chart's only, off by
    # default; on when an 8.1+ IDM workload's binding names its image (IDM_ADMIN_UI)
    Component("idm-admin-ui", IDENTITY_PLATFORM, "idm_admin_ui", None, "Deployment", "idm-admin-ui", "idm-admin-ui",
              "image", ("idm-admin-ui",), True),
    Component("ig", PING_GATEWAY, "ig", "ig", "Deployment", "ig", "ig", "image", ("ig",), True),
)
_BY_NAME = {c.name: c for c in COMPONENTS}

# The tooling images the Kustomize bases name (init containers, jobs), set to the identity-platform chart's defaults at
# this release so both targets run the same: (base image name, reference). Not products, so not the record's.
TOOLING_IMAGES = (("am-custom", "busybox:musl"), ("idm-custom", "busybox:musl"),
                  ("kubectl", f"{PUBLIC_IMAGES}images/kubectl:1.36.1"))

# The components a product's server role runs as (DS: by the workload's name, ForgeOps' ds-idrepo or ds-cts); the
# product's server roles are its adapter's (Adapter.roles kind server, core.environment.roles_for).
PRODUCT_COMPONENTS = (("PingAM", ("am",)), ("PingIDM", ("idm",)), ("PingGateway", ("ig",)),
                      ("PingDS", ("ds-idrepo", "ds-cts")))
UIS = ("admin-ui", "end-user-ui", "login-ui")
# Components without a workload of their own whose image the record keeps in a workload's binding under their first
# container name (Component.containers), the container of their pods that runs it (amster's: its init container):
# their pods carry opsdir.io/image-of, so the kubernetes importer folds the image back into that binding. Not the jobs
# that borrow another component's image (keystore-create, ds-set-passwords).
COMPANION_IMAGES = ("amster", "admin-ui", "end-user-ui", "login-ui", "idm-admin-ui")
IDM_ADMIN_UI, IDM_ADMIN_UI_VERSIONS = "idm-admin-ui", ">=8.1"

# The product whose server role a component without a workload of its own labels its pods with (opsdir.io/role), so
# the namespace's default deny of ingress lets in what reaches it: the UIs serve through the ingress as AM does (port
# 8080), ds-set-passwords reaches DS as its peers do. Jobs that only call out (amster, keystore-create) need none.
COMPANION_PRODUCTS = (("admin-ui", "PingAM"), ("end-user-ui", "PingAM"), ("login-ui", "PingAM"),
                      ("idm-admin-ui", "PingIDM"), ("ds-set-passwords", "PingDS"))

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
          ("idm-admin-ui", ("idm", "am"), "/admin", "prefix", "idm-admin-ui", 8080, None),
          ("idm-admin-ui", ("idm", "am"), "/api", "prefix", "idm-admin-ui", 8080, None),
          ("ig", ("ig",), "/ig", "prefix", "ig", 80, "/"),
          ("ig", ("ig",), "/igadmin", "prefix", "ig", 8085, "/"))
# Routes a component takes over when it is on: (component whose route it was, path, component taking it). With the
# IDM admin UI pod on, the chart's IDM Ingress sends /admin (and the UI's /api) to it (2026.3.2 idm-ingress.yaml).
TAKEN_ROUTES = (("idm", "/admin", "idm-admin-ui"),)
# The products whose server roles' service names a chart's Ingresses serve: with any of them behind a cluster gateway,
# the chart's Ingresses are off (the gateway serves its routes).
CHART_PRODUCTS = ((IDENTITY_PLATFORM, ("PingAM", "PingIDM")), (PING_GATEWAY, ("PingGateway",)))

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
    servers = not wanted & set(dict(PRODUCT_COMPONENTS)["PingDS"])
    found = (SERVERS_CA if servers and s.name == SERVERS_CA.name else s for s in KIT_SECRETS)
    return tuple((s, dict(s.made).get(target)) for s in found if wanted & set(s.readers))


def public_image(ref):
    """Whether an image reference is one of ForgeOps' public images (for development and testing only)."""
    return ref.startswith(PUBLIC_IMAGES)
