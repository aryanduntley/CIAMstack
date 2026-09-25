"""The resolved view of one environment that every renderer works from.

Renderers never look anything up by hostname or file path. They ask for *roles*
("ds-ldaps-service", "ds-deployment-password") and the environment's bindings answer.
That indirection is what lets the same intent render into a different cloud.
"""
import ipaddress
import re

R = "dc=ciam-ops"
DECL = f"ou=declared,ou=config,{R}"

# Roles every complete environment must bind. Renderers mark missing ones as UNBOUND.
REQUIRED_ROLES = ["network", "subnet-ds", "subnet-pf", "ds-ldaps-service", "pf-sso-service", "pf-egress",
                  "disk-encryption", "backup-target", "ds-deployment-id", "ds-deployment-password",
                  "ds-root-password", "ds-tls-keystore", "sso-tls-keystore", "pf-signing-key", "pf-admin-password"]


def env_dn(spec):
    """'aws-current/prod' → env=prod,cloud=aws-current,ou=environments,dc=ciam-ops (full DNs pass through)."""
    if "=" in spec:
        return spec
    cloud, env = spec.split("/")
    return f"env={env},cloud={cloud},ou=environments,{R}"


def tf_name(s):
    n = re.sub(r"[^a-z0-9_]", "_", s.lower())
    return n if n[0].isalpha() else "r_" + n


def is_private(ip):
    return ipaddress.ip_address(ip.split("/")[0]).is_private


class EnvModel:
    def __init__(self, d, spec):
        self.d = d
        self.dn = env_dn(spec)
        self.env = d.get(self.dn)
        if not self.env:
            raise SystemExit(f"no such environment: {self.dn}")
        self.cloud = d.get(self.dn.split(",", 1)[1])
        self.provider = self.cloud.one("ciamCloudProvider")
        self.label = f"{self.cloud.name}/{self.env.name}"
        self.servers = d.children(self.dn, "ciamServer")
        self.bindings = d.children(f"ou=bindings,{self.dn}")
        self.unbound = [r for r in REQUIRED_ROLES if not self.by_role(r)]

    # -------------------------------------------------------------- lookups
    def by_role(self, role):
        return [b for b in self.bindings if b.one("ciamBindingRole") == role]

    def one_role(self, role):
        found = self.by_role(role)
        return found[0] if found else None

    def of_class(self, oc):
        return [b for b in self.bindings if b.is_a(oc)]

    def servers_with_role(self, role):
        return [s for s in self.servers if s.one("ciamServerRole") == role]

    def subnet_of(self, server):
        return self.d.ref(server, "ciamSubnet")

    def secret(self, role):
        b = self.one_role(role)
        return b.one("ciamRefUri") if b else None

    @property
    def joins(self):
        """The environment whose DS replication deployment this one joins (migration), if any."""
        return self.d.ref(self.env, "ciamJoinsDeploymentOf")

    def declared(self, rel=""):
        return f"{rel},{DECL}" if rel else DECL


def peer_ds_hosts(d, m):
    """DS replication bootstrap servers: this environment's DS servers, plus the DS servers of
    the environment it joins (so target replicas join the *existing* deployment)."""
    hosts = [s.one("ciamHostname") for s in m.servers_with_role("ds")]
    if m.joins:
        hosts += [s.one("ciamHostname") for s in d.children(m.joins.dn, "ciamServer")
                  if s.one("ciamServerRole") == "ds"]
    return hosts


def fetch_secret_cmd(uri):
    """Shell command that resolves a secret reference at run time. The value never touches disk here."""
    scheme, rest = uri.split("://", 1)
    if scheme == "aws-sm":
        return f"aws secretsmanager get-secret-value --secret-id '{rest}' --query SecretString --output text"
    if scheme == "azkv":
        vault, name = rest.split("/", 1)
        return f"az keyvault secret show --vault-name '{vault}' --name '{name}' --query value -o tsv"
    if scheme == "vault":
        return f"vault kv get -field=value '{rest}'"
    raise SystemExit(f"no resolver for secret scheme {scheme}")


def hcl(v, indent=0):
    """Render a Python value as an HCL expression. Strings starting with '${' are raw expressions."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        if v.startswith("${") and v.endswith("}"):
            return v[2:-1]
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, list):
        return "[" + ", ".join(hcl(x) for x in v) + "]"
    if isinstance(v, dict):
        pad = "  " * (indent + 1)
        w = max(len(k) for k in v)
        body = "\n".join(f"{pad}{k.ljust(w)} = {hcl(x, indent + 1)}" for k, x in v.items())
        return "{\n" + body + "\n" + "  " * indent + "}"
    raise TypeError(v)


def block(kind, labels, body, indent=0):
    """HCL block. body: list of (key, value) or (key, Block) pairs, or raw lines."""
    pad = "  " * indent
    head = pad + kind + "".join(f' "{lab}"' for lab in labels) + " {"
    lines = [head]
    # like `terraform fmt`: align "=" within runs of single-line attributes; blocks and
    # multi-line values break the run
    simple = lambda kv: kv[0] != "#" and not isinstance(kv[1], (Block, dict))  # noqa: E731
    widths, run = {}, []
    for i, kv in enumerate(body + [("#", None)]):
        if i < len(body) and simple(kv):
            run.append(i)
        else:
            for j in run:
                widths[j] = max(len(body[x][0]) for x in run)
            run = []
    for i, (k, v) in enumerate(body):
        if k == "#":
            lines.append(f"{pad}  # {v}")
        elif isinstance(v, Block):
            lines.append(block(v.kind, v.labels, v.body, indent + 1))
        else:
            lines.append(f"{pad}  {k.ljust(widths.get(i, len(k)))} = {hcl(v, indent + 1)}")
    lines.append(pad + "}")
    return "\n".join(lines)


class Block:
    def __init__(self, kind, body, labels=()):
        self.kind, self.body, self.labels = kind, body, labels


def ref(expr):
    return "${" + expr + "}"


def header(m, what):
    return (f"# Generated by opsdir from {m.dn}\n"
            f"# {what}\n"
            f"# Do not edit. Change the operations directory (under an approved change) and re-render.\n")
