"""Migration plan: read the directory, compare two environments, list what's ready and what blocks cutover.

The claim being tested: if intent is environment-neutral and every environment binds the same roles,
a migration is "render the target from the same databases". Anything that makes that false shows up
here as a blocker with an owner.
"""
import datetime as dt
import ipaddress

from .render import render_env
from .render.model import EnvModel
from .reports import drift

TERMINAL = {"tested", "cutover"}


def _date(gt):
    return dt.datetime.strptime(gt[:8], "%Y%m%d").date()


def _covers(cidrs, addr):
    net = ipaddress.ip_network(addr, strict=False)
    return any(net.subnet_of(ipaddress.ip_network(c, strict=False)) for c in cidrs)


def _role_address(m, role):
    """The address of one of OUR roles in an environment, as external parties would allowlist it."""
    b = m.one_role(role)
    if not b:
        return None
    if b.is_a("ciamServiceName"):
        return b.one("ciamFrontendIp") + "/32"
    return b.one("ciamCidr")


def _owners(d, e):
    return ", ".join(d.get(o).name for o in e.all("ciamOwner")) or "**NO OWNER**"


def plan(d, src_spec, dst_spec, as_of):
    src, dst = EnvModel(d, src_spec), EnvModel(d, dst_spec)
    cutover = _date(dst.env.one("ciamPlannedCutover")) if dst.env.one("ciamPlannedCutover") else None
    blockers, actions, ok = [], [], []
    requests = {}

    # 1. environment-neutral outputs must be byte-identical
    _, fs = render_env(d, src_spec)
    _, fd = render_env(d, dst_spec)
    neutral = [p for p in fs if p.startswith(("ds/dsconfig", "ds/acis", "pingfederate/"))]
    same = [p for p in neutral if fs[p] == fd.get(p)]
    if len(same) == len(neutral):
        ok.append(f"All {len(neutral)} environment-neutral outputs render identically for both environments "
                  f"({', '.join(neutral)}). Intent moves as-is.")
    else:
        blockers.append(("Intent", "Environment-neutral outputs differ: "
                         + ", ".join(p for p in neutral if p not in same), "ciam-platform"))

    # 2. contracts: service names consumers and partners use must not change
    for svc in src.of_class("ciamServiceName"):
        role = svc.one("ciamBindingRole")
        t = dst.one_role(role)
        if not t:
            continue
        a, b = svc.one("ciamFqdn"), t.one("ciamFqdn")
        if a == b:
            ok.append(f"Contract kept: `{role}` is `{a}` in both environments.")
        else:
            users = [c.name for c in d.children("ou=consumers,dc=ciam-ops", "ciamConsumer")] \
                if svc.one("ciamTargetRole") == "ds" else ["every SSO application and partner"]
            certs = [c.name for c in d.children("ou=certificates,dc=ciam-ops", "ciamCertificate")
                     if a in c.all("ciamSubjectAltName") and b not in c.all("ciamSubjectAltName")]
            blockers.append(("Contract", f"`{role}` changes name `{a}` → `{b}`. Every consumer would have to "
                             f"reconfigure ({', '.join(users)}), and certificate(s) {', '.join(certs) or '-'} "
                             f"don't cover the new name. Fix: bind the stable name `{a}` in {dst.label}.",
                             _owners(d, t) if t.one("ciamOwner") else "ciam-platform"))

    # 3. every role bound in the source must be bound in the target
    src_roles = {b.one("ciamBindingRole") for b in src.bindings}
    dst_roles = {b.one("ciamBindingRole") for b in dst.bindings}
    for role in sorted(src_roles - dst_roles):
        b = src.one_role(role)
        consumer = d.ref(b, "ciamAllowsConsumer")
        if consumer:
            who = _owners(d, consumer)
            note = (f"Consumer `{consumer.name}` (status {consumer.one('ciamMigrationStatus')}) is allowed in "
                    f"{src.label} but has no firewall rule in {dst.label}.")
            if not consumer.one("ciamOwner"):
                note += " Nobody owns it: decide whether to migrate or retire it before cutover."
            blockers.append(("Binding", note, who))
        else:
            blockers.append(("Binding", f"Role `{role}` is bound in {src.label} but not in {dst.label}.",
                             "ciam-platform"))
    for role in sorted(dst_roles - src_roles):
        ok.append(f"New in {dst.label}: `{role}`.")

    # 4. replication continuity: target replicas must join the existing deployment
    if dst.joins and dst.joins.dn.lower() == src.dn.lower():
        ok.append(f"{dst.label} joins the DS replication deployment of {src.label} "
                  "(same deployment ID; keys and encrypted data stay readable).")
    else:
        blockers.append(("Replication", f"{dst.label} does not declare that it joins {src.label}'s deployment. "
                         "A fresh deployment can't decrypt existing encrypted data or backups.", "ciam-platform"))
    link = [ic for ic in dst.of_class("ciamInterconnect")
            if (d.ref(ic, "ciamPeerEnvironment").dn.lower() == src.dn.lower())]
    if link:
        ok.append(f"Interconnect `{link[0].name}` ({link[0].one('ciamInterconnectKind')}) links the environments.")
    else:
        blockers.append(("Replication", "No interconnect from the target to the source for replication traffic.",
                         "network-security"))
    repl_rules = [f for f in src.of_class("ciamFirewallRule") if "8989" in f.all("ciamPort")]
    for s in dst.servers_with_role("ds"):
        ip = s.one("ciamPrivateIp") + "/32"
        if not any(_covers(f.all("ciamSourceCidr"), ip) for f in repl_rules):
            blockers.append(("Replication", f"{src.label} doesn't admit {dst.label} replica {s.name} ({ip}) on "
                             "port 8989.", "network-security"))
    if all(any(_covers(f.all("ciamSourceCidr"), s.one("ciamPrivateIp") + "/32") for f in repl_rules)
           for s in dst.servers_with_role("ds")):
        ok.append(f"{src.label} already admits every {dst.label} replica on the replication port.")

    # 5. versions
    sv = {s.one("ciamProductVersion") for s in src.servers}
    dv = {s.one("ciamProductVersion") for s in dst.servers}
    if sv == dv:
        ok.append(f"Same product versions in both environments ({', '.join(sorted(sv))}): a re-host, not an upgrade.")
    else:
        actions.append(("Versions", f"Versions differ ({sorted(sv)} → {sorted(dv)}). Test compatibility separately "
                        "from the move.", "ciam-platform", None))

    # 6. consumers
    for c in d.children("ou=consumers,dc=ciam-ops", "ciamConsumer"):
        status = c.one("ciamMigrationStatus", "unknown")
        if status not in TERMINAL:
            detail = f"Consumer `{c.name}` ({c.one('ciamBindDn')}) is `{status}`, not tested against {dst.label}."
            if c.one("ciamTlsOnly") == "FALSE":
                detail += " It also binds without TLS."
            if int(c.one("ciamUnindexedSearchesPerDay", "0")) > 0:
                detail += f" {c.one('ciamUnindexedSearchesPerDay')} unindexed searches/day."
            blockers.append(("Consumer", detail, _owners(d, c)))

    # 7. external allowlists: other people's firewalls that contain our addresses
    for xa in d.children("ou=external-allowlists,dc=ciam-ops", "ciamExternalAllowlist"):
        role = xa.one("ciamRefersToRole")
        new = _role_address(dst, role)
        mgr = d.ref(xa, "ciamManagedBy")
        lead = int(xa.one("ciamLeadTimeDays", "0"))
        if new is None:
            blockers.append(("Allowlist", f"`{xa.name}` refers to role `{role}`, which {dst.label} doesn't bind.",
                             mgr.name))
        elif _covers(xa.all("ciamRecordedCidr"), new):
            ok.append(f"External allowlist `{xa.name}` ({mgr.name}) already covers {dst.label}'s `{role}` ({new}).")
        else:
            by = (cutover - dt.timedelta(days=lead + 14)) if cutover else None
            late = by is not None and by < as_of
            text = (f"`{xa.name}`: {mgr.name} must add `{new}` ({role} in {dst.label}) to "
                    f"\"{xa.one('ciamExternalSystem')}\". Lead time {lead} days → request by **{by}**"
                    + (" (**already late**)" if late else "") + ".")
            actions.append(("Allowlist", text, mgr.name, by))
            requests.setdefault(mgr, []).append((xa, new, role, by))

    # 8. certificates that expire before cutover (+30 days), or don't cover the target's names
    horizon = (cutover or as_of) + dt.timedelta(days=30)
    for c in d.children("ou=certificates,dc=ciam-ops", "ciamCertificate"):
        exp = _date(c.one("ciamNotAfter"))
        if exp <= horizon:
            partner = d.ref(c, "ciamPartnerContact")
            rb = d.ref(c, "ciamRotationRunbook")
            used = [u.name for _, u in d.referrers(c, "ciamUsesCertificate")]
            text = (f"Certificate `{c.name}` expires {exp} ({(exp - as_of).days} days), before cutover + 30 days. "
                    f"Used by: {', '.join(used) or 'LDAPS service'}."
                    + (f" Coordinate with partner {partner.name}." if partner else "")
                    + (f" Runbook {rb.name}." if rb else ""))
            actions.append(("Certificate", text, _owners(d, c), exp - dt.timedelta(days=30)))

    # 9. source hygiene: migrate the declared state, not accidents
    for server, kind, rel, detail in drift(d):
        actions.append(("Drift", f"{src.label} {server}: {kind}: `{rel}` {detail}".rstrip(), "ciam-platform", None))
    for aci in d.children("ou=acis,dc=ciam-ops", "ciamAci"):
        if not aci.one("ciamOwner") or not aci.one("ciamJustification"):
            actions.append(("Access", f"ACI `{aci.name}` has no owner/justification. Review before recreating it "
                            f"in {dst.label}.", "ciam-platform", None))

    return {"src": src, "dst": dst, "cutover": cutover, "as_of": as_of, "blockers": blockers,
            "actions": actions, "ok": ok, "requests": requests, "target_files": fd}


def to_markdown(p):
    src, dst = p["src"], p["dst"]
    verdict = "NOT READY" if p["blockers"] else "READY"
    L = [f"# Migration plan: {src.label} → {dst.label}", "",
         f"Generated by opsdir as of {p['as_of']}. Planned cutover: **{p['cutover'] or 'not set'}**.", "",
         f"## Verdict: {verdict} ({len(p['blockers'])} blockers, {len(p['actions'])} actions)", ""]
    if dst.unbound:
        L += [f"Target roles still unbound: {', '.join(f'`{r}`' for r in dst.unbound)}", ""]
    L += ["## Blockers", "", "| Area | Finding | Owner |", "|---|---|---|"]
    L += [f"| {a} | {t} | {o} |" for a, t, o in p["blockers"]] or ["| - | none | - |"]
    L += ["", "## Actions (dated)", "", "| Area | Action | Owner | Do by |", "|---|---|---|---|"]
    acts = sorted(p["actions"], key=lambda x: (x[3] is None, x[3] or dt.date.max, x[0]))
    L += [f"| {a} | {t} | {o} | {b or ''} |" for a, t, o, b in acts]
    L += ["", "## Already in place", ""] + [f"- {x}" for x in p["ok"]]
    L += ["", "## What the target renders to", "",
          f"`opsdir render {dst.label}` produces {len(p['target_files'])} files from the same databases: "
          "Terraform for the target cloud, per-server DS setup scripts that join the existing deployment, and the "
          "environment-neutral DS/PingFederate configuration.", ""]
    return "\n".join(L)


def request_drafts(p):
    """One change-request draft per external party whose allowlist must change."""
    out = {}
    for mgr, items in p["requests"].items():
        lines = [f"To: {mgr.name} <{mgr.one('mail', 'n/a')}>",
                 f"Subject: Allowlist update needed before {p['cutover']} (Example Aero identity platform move)", "",
                 "Hello,", "",
                 f"We are moving the Example Aero external identity platform to a new hosting environment. "
                 f"Planned cutover is {p['cutover']}. "
                 + ("Service names stay the same; some addresses change."
                    if not any(b[0] == "Contract" for b in p["blockers"])
                    else "Some addresses change (service names are still being confirmed)."), "",
                 "Please add the following to the systems you operate:", ""]
        for xa, new, role, by in items:
            lines.append(f"- **{xa.one('ciamExternalSystem')}**: add `{new}` "
                         f"(currently allowlisted: {', '.join(xa.all('ciamRecordedCidr'))}). Needed by {by}.")
        lines += ["", "Please keep the existing entries until we confirm cutover; we'll tell you when they can go.",
                  "", "Thank you,", "CIAM platform team", "",
                  f"_Generated from the operations directory; entries {', '.join(x[0].name for x in items)}._"]
        out[f"requests/{mgr.name}.md"] = "\n".join(lines) + "\n"
    return out
