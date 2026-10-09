"""Managed databases: the databases report, and the planner check comparing each database the source and the target
both bind by role. A move carries the engine and its version unchanged (an upgrade or a conversion is its own change),
and keeps the database as available, encrypted, protected and backed up as it was, its backups copied out of its region
where the source's are (ciamCopyRegion: the region its automated backups and point-in-time logs are copied to). Pure."""
from ...core.changeset import set_values
from ...core.directory import one, subtree, values
from ...core.environment import bound_nowhere, environment_of, of_class
from ...core.findings import Fix, Input, findings, merge_findings, responsible
from ...core.naming import branch, env_label
from .kept import carry_fix, key_choice_fix
from .naming import DEFAULT_PORTS

DATABASE_HEADERS = ("environment", "database", "engine", "version", "edition", "service", "size",
                    "high availability", "encrypted by", "tls", "backup days", "point in time", "copied to",
                    "deletion protection", "endpoint", "credential role")
AREA = "Databases"
# what the target must keep as the source has it: (attribute, what losing it means, the value that has it)
KEPT = (("ciamDbHighAvailability", "no standby to fail over to when its zone fails", "zone-redundant"),
        ("ciamDbTlsRequired", "connections without TLS are accepted", "TRUE"),
        ("ciamDbPointInTime", "it can only be restored to a nightly backup, not to a point in time", "TRUE"),
        ("ciamDbDeletionProtection", "nothing stops it being deleted by mistake", "TRUE"))
_LABELS = {"ciamDbHighAvailability": "high availability", "ciamDbTlsRequired": "required TLS",
           "ciamDbPointInTime": "point-in-time restore", "ciamDbDeletionProtection": "deletion protection"}


def major_version(engine, version):
    """The major version of an engine version: what a move must keep (PostgreSQL 16.4 -> 16, MySQL 8.0.35 -> 8.0)."""
    parts = version.split(".")
    return ".".join(parts[:2]) if engine in ("mysql", "mariadb") else parts[0]


def database_port(b):
    """The port database binding b listens on: its ciamPort, else its engine's default (None for an engine without
    one)."""
    port = one(b, "ciamPort")
    return int(port) if port else DEFAULT_PORTS.get(one(b, "ciamDbEngine"))


# ------------------------------------------------------------------ report
def _yes(e, attr):
    return {"TRUE": "yes", "FALSE": "no"}.get(one(e, attr) or "", "")


def database_rows(d, dn=None):
    """One row per managed database of every environment."""
    def endpoint(e):
        host, port = one(e, "ciamFqdn"), one(e, "ciamPort")
        return f"{host}:{port}" if host and port else host or ""
    return sorted(((env_label(environment_of(e)), one(e, "ciamBindingRole"), one(e, "ciamDbEngine"),
                    one(e, "ciamDbEngineVersion") or "", one(e, "ciamDbEdition") or "", one(e, "ciamDbService") or "",
                    one(e, "ciamInstanceSize") or "",
                    one(e, "ciamDbHighAvailability") or "", one(e, "ciamEncryptedByRole") or "",
                    _yes(e, "ciamDbTlsRequired"), one(e, "ciamRetentionDays") or "", _yes(e, "ciamDbPointInTime"),
                    ", ".join(values(e, "ciamCopyRegion")), _yes(e, "ciamDbDeletionProtection"), endpoint(e),
                    one(e, "ciamDbCredentialRole") or "")
                   for e in subtree(d, branch("environments"), "ciamDatabase")), key=lambda row: row[:2])


# ------------------------------------------------------------------ check
def _carry(ctx, role, s, t, attrs, title, risks=()):
    """The fix giving the target's database the source's values of attrs."""
    return carry_fix(f"database:{role}:{attrs[0]}", AREA, title, s, t, attrs,
                     (f"Apply the rendered database in {ctx.dst.label} (its keeper's root when someone else "
                      "keeps it).",),
                     risks)


def _engine(ctx, role, s, t, owner):
    se, te = one(s, "ciamDbEngine"), one(t, "ciamDbEngine")
    if se != te:
        return findings(blockers=[(AREA, f"Database `{role}` runs {se} in {ctx.src.label} but {te} in "
                                  f"{ctx.dst.label}: moving it means converting the data, not a move. Record the "
                                  "target with the source's engine, or plan the conversion as its own change.",
                                  owner)],
                        fixes=[_carry(ctx, role, s, t, ("ciamDbEngine", "ciamDbEngineVersion"),
                                      f"Run `{role}` in {ctx.dst.label} on {se}, as {ctx.src.label} does")])
    edition = _edition(ctx, role, s, t, owner)
    sv, tv = one(s, "ciamDbEngineVersion"), one(t, "ciamDbEngineVersion")
    if not sv or not tv or sv == tv or _same_major(se, sv, tv):
        return edition
    fix = _carry(ctx, role, s, t, ("ciamDbEngineVersion",), f"Run `{role}` in {ctx.dst.label} on {se} {sv}, as "
                 f"{ctx.src.label} does", ("If the target's version is a planned upgrade, make it its own change "
                                          "after the move instead.",))
    if major_version(se, sv) != major_version(se, tv):
        return merge_findings([edition, findings(
            blockers=[(AREA, f"Database `{role}` runs {se} {sv} in {ctx.src.label} but {tv} in {ctx.dst.label}: a "
                       "move carries the major version unchanged; an upgrade is its own change.", owner)],
            fixes=[fix])])
    return merge_findings([edition, findings(
        actions=[(AREA, f"Database `{role}` runs {se} {sv} in {ctx.src.label} but {tv} in {ctx.dst.label}: the same "
                  "major version, but test the products against the target's.", owner, ctx.cutover)], fixes=[fix])])


def _same_major(engine, sv, tv):
    """Whether the target records only a major version, the source's: the service keeps the minor version current
    (Flexible Server, Cloud SQL), so there is no minor version to compare."""
    return tv == major_version(engine, tv) and major_version(engine, sv) == tv


def _edition(ctx, role, s, t, owner):
    se, te = one(s, "ciamDbEdition"), one(t, "ciamDbEdition")
    if not se or se == te:
        return findings()
    return findings(actions=[(AREA, f"Database `{role}` runs the {se} edition in {ctx.src.label} but "
                              f"{te or 'no edition recorded'} in {ctx.dst.label}: features and licensing differ.",
                              owner, ctx.cutover)],
                    fixes=[_carry(ctx, role, s, t, ("ciamDbEdition",), f"Run `{role}` in {ctx.dst.label} on the {se} "
                                  f"edition, as {ctx.src.label} does")])


def _kept(ctx, role, s, t, owner):
    lost = [(a, why) for a, why, has in KEPT if one(s, a) == has and one(t, a) != has]
    return findings(actions=[(AREA, f"Database `{role}` has {_LABELS[a]} in {ctx.src.label} but not in "
                              f"{ctx.dst.label}: {why}.", owner, ctx.cutover) for a, why in lost],
                    fixes=[_carry(ctx, role, s, t, (a,), f"Give `{role}` {_LABELS[a]} in {ctx.dst.label}, as "
                                  f"{ctx.src.label} has it") for a, _ in lost])


def _retention(ctx, role, s, t, owner):
    sd, td = one(s, "ciamRetentionDays"), one(t, "ciamRetentionDays")
    if not sd or (td and int(td) >= int(sd)):
        return findings()
    return findings(actions=[(AREA, f"Database `{role}` keeps backups {sd} days in {ctx.src.label} but "
                              f"{td or 'none recorded'} in {ctx.dst.label}: restores reach back less far.", owner,
                              ctx.cutover)],
                    fixes=[_carry(ctx, role, s, t, ("ciamRetentionDays",), f"Keep `{role}`'s backups {sd} days in "
                                  f"{ctx.dst.label}, as {ctx.src.label} does")])


def _copies(ctx, role, s, t, owner):
    """An action, with a fix, when the source copies the database's backups to another region and the target copies
    them nowhere: losing the target's region would lose its backups too."""
    regions = values(s, "ciamCopyRegion")
    if not regions or values(t, "ciamCopyRegion"):
        return findings()
    region = Input("ciamCopyRegion", f"the region {ctx.dst.label}'s backups of `{role}` are copied to", (), regions)
    return findings(actions=[(AREA, f"Database `{role}` copies its backups to {', '.join(regions)} in "
                              f"{ctx.src.label}; in {ctx.dst.label} they stay in its region: losing the region loses "
                              "them too, and point-in-time restore with it.", owner, ctx.cutover)],
                    fixes=[Fix(f"database:{role}:ciamCopyRegion", AREA, f"Copy `{role}`'s backups to another region in "
                               f"{ctx.dst.label}", (set_values(t, "ciamCopyRegion", (region,)),),
                               (f"Apply the rendered database in {ctx.dst.label} (its keeper's root when someone else "
                                "keeps it).",),
                               ("Where the cloud fixes the copy region (Azure copies to the region's pair), the "
                                "rendered database names the region it uses.",))])


def _encryption(ctx, role, s, t, owner):
    if not one(s, "ciamEncryptedByRole") or one(t, "ciamEncryptedByRole"):
        return findings()
    fix = key_choice_fix(ctx.dst, f"database:{role}:ciamEncryptedByRole", AREA, f"Encrypt `{role}` in "
                         f"{ctx.dst.label} with a key of its own", t,
                         (f"Apply the rendered database in {ctx.dst.label}: a database is encrypted when created, so "
                          "an existing one is copied to an encrypted one.",))
    return findings(actions=[(AREA, f"Database `{role}` is encrypted with key `{one(s, 'ciamEncryptedByRole')}` in "
                              f"{ctx.src.label}; in {ctx.dst.label} nothing names its key, so the provider's own "
                              "default key encrypts it, which nobody here controls or can revoke.", owner,
                              ctx.cutover)], fixes=[fix] if fix else [])


def _parameters(ctx, role, s, t, owner):
    def params(e):
        return dict(v.split("=", 1) for v in values(e, "ciamDbParameter") if "=" in v)
    src, dst = params(s), params(t)
    differ = sorted(n for n, v in src.items() if dst.get(n) != v)
    if not differ:
        return findings()
    merged = tuple(f"{n}={v}" for n, v in sorted({**dst, **src}.items()))
    there = [f"{n}={dst[n]}" for n in differ if n in dst]
    target = f"sets {', '.join(there)}" if there else "leaves them at the engine's defaults"
    return findings(actions=[(AREA, f"Database `{role}` sets {', '.join(f'{n}={src[n]}' for n in differ)} in "
                              f"{ctx.src.label}; {ctx.dst.label} {target}.", owner, ctx.cutover)],
                    fixes=[Fix(f"database:{role}:ciamDbParameter", AREA, f"Set `{role}`'s parameters in "
                               f"{ctx.dst.label} as {ctx.src.label} does",
                               (set_values(t, "ciamDbParameter", merged),),
                               (f"Apply the rendered database in {ctx.dst.label}; some parameters take effect only "
                                "after a restart.",),
                               ("Parameters only the target sets are kept.",))])


def _credentials(ctx, role, s, t, owner):
    credential = one(t, "ciamDbCredentialRole")
    unbound = bound_nowhere((credential,), ctx.dst)
    missing = one(s, "ciamDbCredentialRole") and not credential
    return findings(
        blockers=[(AREA, f"Database `{role}` keeps its credentials in role `{r}`, which {ctx.dst.label} doesn't "
                   "bind.", owner) for r in unbound],
        actions=[(AREA, f"Database `{role}` names no credential role in {ctx.dst.label}: nothing says which secret "
                  "holds its administrator credentials there.", owner, ctx.cutover)] if missing else [],
        fixes=[_carry(ctx, role, s, t, ("ciamDbCredentialRole",), f"Keep `{role}`'s credentials in role "
                      f"`{one(s, 'ciamDbCredentialRole')}` in {ctx.dst.label}, as {ctx.src.label} does")]
        if missing else [])


def check_databases(ctx):
    """Each managed database the source and the target both bind: engine and major version kept (blockers), the rest
    of what it had kept too, its backups' copy region included (actions), its credential role bound."""
    dst = {one(b, "ciamBindingRole"): b for b in of_class(ctx.dst, "ciamDatabase")}
    pairs = [(role, s, dst[role]) for role, s in sorted((one(b, "ciamBindingRole"), b)
                                                        for b in of_class(ctx.src, "ciamDatabase")) if role in dst]
    parts = merge_findings([f(ctx, role, s, t, responsible(ctx.d, t, ctx.dst.env)) for role, s, t in pairs
                            for f in (_engine, _kept, _retention, _copies, _encryption, _parameters, _credentials)])
    if pairs and not (parts.blockers or parts.actions):
        return parts._replace(ok=(*parts.ok, f"{len(pairs)} managed database(s) keep their engine, version, "
                                             f"availability, encryption and backups in {ctx.dst.label}."))
    return parts
