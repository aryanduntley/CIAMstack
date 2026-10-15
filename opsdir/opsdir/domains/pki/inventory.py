"""Secret-store inventories reconciled with the record's references: pure functions of a snapshot.

An inventory (ciamSecretInventory under ou=<scheme>,ou=secret-inventory) is what one container of a store (a PAM safe,
a key/value mount) said it holds when its importer read it, metadata only: complete, incomplete (the listing may have
missed some) or denied, with the objects found as its children (ciamSecretObject). Which container and object a
reference points at is the adapter's to say (Adapter.inventory_locator: {scheme: rest -> (container, object)}), so the
core names no store.

Every secret reference (a ciamSecretRef's ciamRefUri, and each ciamCopyRef: another place the same material is kept)
whose scheme has a locator is in one state, kept apart because each asks something different of someone:

  present               the object is in the container's inventory
  deleted               it is, but deleted, scheduled for deletion or disabled: whatever reads it fails
  confirmed-missing     the container was listed completely and the object isn't in it
  inventory-incomplete  the listing may have missed it (truncated, pages unread)
  inaccessible          the store refused to list the container
  not-inventoried       no inventory of the container (or of the prefix the reference is under)

and every object an inventoried container holds that no reference in the record names is unreferenced. Rotation is
compared only with a timestamp that means rotation (the object's ciamLastRotated, which importers set only from one);
when a whole container's objects carry no rotation facts, its store's metadata can't show rotation, and the planner
says so once. Observations are never written onto the bindings: the reconciliation is computed here, each time.
"""
from typing import NamedTuple

from ...core.contract import CollectOption
from ...core.directory import children, date_of, get, is_a, make_entry, merged_attrs, one, rdn_value, subtree, values
from ...core.environment import environment_of
from ...core.findings import findings, merge_findings, responsible
from ...core.naming import branch, env_label
from .credentials import credential_for_role, rotate_by, split_ref
from .naming import SECRET_INVENTORY, inventory_dn

PRESENT, DELETED, MISSING, INCOMPLETE, INACCESSIBLE, NOT_INVENTORIED = (
    "present", "deleted", "confirmed-missing", "inventory-incomplete", "inaccessible", "not-inventoried")
UNREFERENCED = "unreferenced"
REF_ATTRS = ("ciamRefUri", "ciamCopyRef")      # a secret reference's own location, then its copies
GONE = ("deleted", "disabled")                 # object states nothing can read
ROTATION_FACTS = ("ciamLastRotated", "ciamRotationManaged", "ciamRotationStatus")
INVENTORY_CLASS, OBJECT_CLASS = "ciamSecretInventory", "ciamSecretObject"
CONTAINER_ATTRS = ("cn", "ciamInventoryAt", "ciamInventoryState", "ciamInventoryProblem", "ciamInventoryPrefix",
                   "ciamStoreEndpoint")
OBJECT_ATTRS = ("cn", "ciamObjectState", "ciamRotationManaged", "ciamRotationStatus", "ciamLastRotated",
                "ciamStoreModified", "ciamLastVerified", "ciamManualReason")
AREA = "Secrets"

# The containers `opsdir collect` inventories beyond those the record's references name; one declaration every
# inventory collector reuses (connectors.registry.collect_options refuses two different ones)
CONTAINER_OPTION = CollectOption("--inventory-container", "NAMES",
                                 "secret store containers to inventory beyond those the references name (comma-"
                                 "separated)", 60)

# A secret reference a locator places: the environment (DN) and binding holding it, the attribute (ciamRefUri, or
# ciamCopyRef for a copy), the reference, its scheme, and the container and object it points at.
Reference = NamedTuple("Reference", [("env", str), ("binding", object), ("attr", str), ("uri", str),
                                     ("scheme", str), ("container", str), ("name", str)])
# A reference reconciled with the inventories: its state, the container's inventory (None: none) and the object found
# (None: not found).
Reconciled = NamedTuple("Reconciled", [("ref", Reference), ("state", str), ("inventory", object), ("found", object)])


# ------------------------------------------------------------------ what importers write
def inventory_entry(d, scheme, container, at, state, problems=(), prefixes=(), endpoint=None):
    """One container's inventory entry (what the record adds to it, owners, kept): taken at `at` (GeneralizedTime),
    complete, incomplete or denied, with why, the prefixes it listed and the store's address."""
    dn = inventory_dn(scheme, container)
    owned = {"cn": (container,), "ciamInventoryAt": (at,), "ciamInventoryState": (state,),
             "ciamInventoryProblem": tuple(dict.fromkeys(problems)), "ciamInventoryPrefix": tuple(prefixes),
             "ciamStoreEndpoint": (endpoint,)}
    return make_entry(dn, ("top", "ciamObject", INVENTORY_CLASS), merged_attrs(get(d, dn), owned, CONTAINER_ATTRS))


def object_entry(d, scheme, container, name, facts):
    """An object a container's inventory found: facts {attribute of OBJECT_ATTRS: value or None} (None: the store
    didn't say); what the record adds to it kept."""
    dn = f"cn={name},{inventory_dn(scheme, container)}"
    owned = {"cn": (name,), **{k: (v,) for k, v in facts.items() if k in OBJECT_ATTRS and k != "cn"}}
    return make_entry(dn, ("top", "ciamObject", OBJECT_CLASS), merged_attrs(get(d, dn), owned, OBJECT_ATTRS))


def inventory_group(inventory, objects):
    """An Imported group: the container's subtree made exactly its inventory and the objects found (objects gone
    from the store leave the record)."""
    return inventory.dn, (inventory, *sorted(objects, key=lambda e: e.norm))


def wanted_containers(d, scheme, locate, option=None):
    """The containers to inventory for a scheme: those the record's secret references name (in every environment,
    by first mention), then the operator's comma-separated extra ones (CONTAINER_OPTION's value)."""
    named = (loc[0] for b in subtree(d, branch("environments"), "ciamSecretRef") for attr in REF_ATTRS
             for uri in values(b, attr) for s, rest in (split_ref(uri),) if s == scheme
             for loc in (locate(rest),) if loc)
    extra = (c.strip() for c in (option or "").split(",") if c.strip())
    return tuple(dict.fromkeys((*named, *extra)))


# ------------------------------------------------------------------ reconciling
def scheme_of(inventory):
    """The ref-uri scheme an inventory entry is filed under (ou=<scheme>)."""
    return inventory.dn.split(",")[1].split("=", 1)[1]


def inventories(d):
    """{(scheme, container): inventory entry} of every container inventory the record holds."""
    return {(scheme_of(e), rdn_value(e)): e for e in subtree(d, SECRET_INVENTORY, INVENTORY_CLASS)}


def objects_of(d, inventory):
    """The objects a container's inventory found."""
    return children(d, inventory.dn, OBJECT_CLASS)


def references(pairs, locators):
    """The References of (environment DN, binding) pairs: every secret reference's own location and copies whose
    scheme has a locator that places them."""
    def placed(scheme, rest):
        locate = (locators or {}).get(scheme)
        return locate(rest) if locate else None
    return tuple(Reference(env, b, attr, uri, scheme, *loc) for env, b in pairs if is_a(b, "ciamSecretRef")
                 for attr in REF_ATTRS for uri in values(b, attr) for scheme, rest in (split_ref(uri),)
                 for loc in (placed(scheme, rest),) if loc)


def record_references(d, locators):
    """The References of every environment's own secret bindings."""
    return references(((environment_of(b), b) for b in subtree(d, branch("environments"), "ciamSecretRef")), locators)


def _listed(inventory, name):
    prefixes = values(inventory, "ciamInventoryPrefix")
    return not prefixes or any(name.startswith(p) for p in prefixes)


def reconcile(d, ref, held):
    """A Reference's Reconciled state against the inventories held ({(scheme, container): entry})."""
    inv = held.get((ref.scheme, ref.container))
    if inv is None or not _listed(inv, ref.name):
        return Reconciled(ref, NOT_INVENTORIED, inv, None)
    if one(inv, "ciamInventoryState") == "denied":
        return Reconciled(ref, INACCESSIBLE, inv, None)
    found = get(d, f"cn={ref.name},{inv.dn}")
    if found is not None:
        return Reconciled(ref, DELETED if one(found, "ciamObjectState") in GONE else PRESENT, inv, found)
    return Reconciled(ref, MISSING if one(inv, "ciamInventoryState") == "complete" else INCOMPLETE, inv, None)


def unreferenced(d, refs, held, containers=None):
    """((scheme, container, object entry), ...): the objects inventoried containers hold that none of refs names, in
    the containers given ((scheme, container) pairs; None: every one)."""
    named = {(r.scheme, r.container, r.name) for r in refs}
    return tuple((s, c, o) for (s, c), inv in held.items() if containers is None or (s, c) in containers
                 for o in objects_of(d, inv) if (s, c, rdn_value(o)) not in named)


def rotation_blind(d, inventory):
    """Whether a container's inventory says nothing of rotation about any object it found (its store's metadata can't
    show rotation)."""
    found = objects_of(d, inventory)
    return bool(found) and not any(one(o, a) for o in found for a in ROTATION_FACTS)


def rotation_problems(d, r, as_of):
    """What is wrong with how a present reference's object rotates, in words: overdue against its credential's
    ciamRotationDays (only from a timestamp meaning rotation), the store's last rotation failing, and a binding saying
    its store rotates it (ciamAutoRotate) while the store doesn't manage it. Only a reference's own location (copies
    follow it)."""
    if r.state != PRESENT or r.ref.attr != "ciamRefUri":
        return ()
    b, o = r.ref.binding, r.found
    cred = credential_for_role(d, one(b, "ciamBindingRole"))
    due = rotate_by(cred, o)
    reason = one(o, "ciamManualReason")
    return (*((f"rotation overdue: last rotated {date_of(o, 'ciamLastRotated')}, due {due} "
               f"(every {one(cred, 'ciamRotationDays')} days)",) if due and due < as_of else ()),
            *(("the store's last rotation failed",) if one(o, "ciamRotationStatus") == "failure" else ()),
            *((f"the binding says its store rotates it, but the store doesn't manage it"
               + (f" ({reason})" if reason else ""),)
              if one(b, "ciamAutoRotate") == "TRUE" and one(o, "ciamRotationManaged") == "FALSE" else ()))


# ------------------------------------------------------------------ the planner's findings
def _where(r):
    copy = "a copy at " if r.ref.attr == "ciamCopyRef" else ""
    return f"`{one(r.ref.binding, 'ciamBindingRole')}` ({copy}{r.ref.uri})"


def _inventoried(r):
    return f"{r.ref.container}'s inventory of {date_of(r.inventory, 'ciamInventoryAt')}"


def _why(r):
    problems = values(r.inventory, "ciamInventoryProblem")
    return f" ({'; '.join(problems)})" if problems else ""


def _state_finding(r, label, owner):
    """(kind, finding) of a reference in a state that needs someone, or None."""
    where = _where(r)
    fails = ("the copy rotating the material must update isn't there" if r.ref.attr == "ciamCopyRef" else
             "whatever reads it fails")
    if r.state == MISSING:
        return "blocker", (AREA, f"{label} references {where}, but {_inventoried(r)} is complete and holds no "
                                 f"`{r.ref.name}`: {fails}. Create it in the store, or correct the reference.", owner)
    if r.state == DELETED:
        return "blocker", (AREA, f"{label} references {where}, but {_inventoried(r)} holds `{r.ref.name}` as "
                                 f"{one(r.found, 'ciamObjectState')}: {fails}. Restore it, or correct the "
                                 "reference.", owner)
    text = (f"the store refused to list {r.ref.container}{_why(r)}: grant the inventory's reader list access to it "
            "and collect again" if r.state == INACCESSIBLE else
            f"{_inventoried(r)} is incomplete{_why(r)} and doesn't list `{r.ref.name}`: collect it again completely"
            if r.state == INCOMPLETE else
            f"{r.ref.container} isn't inventoried" + (" under the prefixes listed" if r.inventory is not None else "")
            + ": collect its inventory (`opsdir collect`, --inventory-container), or record why not"
            if r.state == NOT_INVENTORIED else None)
    return ("action", (AREA, f"{label} references {where}, whose existence can't be confirmed: {text}.", owner,
                       None)) if text else None


def inventory_findings(ctx, locators):
    """The target's secret references against the inventories the record holds (nothing when it holds none of their
    schemes): a reference confirmed missing from its store, or deleted there, is a blocker; one that can't be confirmed
    (store refused, listing incomplete, container not inventoried) an action; so is a reference's rotation overdue,
    failed, or not managed although its binding says the store rotates it; and so are the objects in the containers
    the target uses that nothing references (one action per container). Present references are counted, and a
    container whose inventory can't show rotation is said once."""
    held = inventories(ctx.d)
    schemes = {s for s, _ in held}
    refs = tuple(r for r in references(((ctx.dst.dn, b) for b in ctx.dst.bindings), locators) if r.scheme in schemes)
    if not refs:
        return findings()
    done = tuple(reconcile(ctx.d, r, held) for r in refs)
    owner = lambda r: responsible(ctx.d, r.ref.binding, ctx.dst.env)      # noqa: E731
    states = tuple(f for r in done for f in (_state_finding(r, ctx.dst.label, owner(r)),) if f)
    rotation = tuple((AREA, f"{ctx.dst.label}: {_where(r)}: {p}.", owner(r), None)
                     for r in done for p in rotation_problems(ctx.d, r, ctx.as_of))
    used = tuple(dict.fromkeys((r.ref.scheme, r.ref.container) for r in done if r.inventory is not None))
    stray = unreferenced(ctx.d, record_references(ctx.d, locators), held, used)
    strays = tuple((AREA, f"{c} ({s}) holds {len(objs)} object(s) no reference in the record names: "
                          f"{', '.join(f'`{rdn_value(o)}`' for o in objs)}. Reference what is in use, or remove the "
                          "rest from the store.", responsible(ctx.d, ctx.dst.env), None)
                   for s, c in used for objs in ([o for x, y, o in stray if (x, y) == (s, c)],) if objs)
    present = sum(1 for r in done if r.state == PRESENT)
    blind = tuple(f"Rotation in {c} ({s}) isn't observable from its inventory: the store's metadata doesn't say when "
                  "material rotated." for s, c in used if rotation_blind(ctx.d, held[(s, c)]))
    return merge_findings([findings(blockers=[f for k, f in states if k == "blocker"],
                                    actions=[f for k, f in states if k == "action"]),
                           findings(actions=[*rotation, *strays],
                                    ok=[*((f"{present} secret reference(s) of {ctx.dst.label} found in their stores' "
                                           "inventories.",) if present else ()), *blind])])


# ------------------------------------------------------------------ the report
INVENTORY_HEADERS = ("environment", "role", "reference", "container", "state", "inventoried", "last rotated",
                     "rotate by", "rotation", "problem")


def _rotation(o):
    if o is None:
        return ""
    managed = {"TRUE": "managed", "FALSE": "manual"}.get(one(o, "ciamRotationManaged"), "")
    status = one(o, "ciamRotationStatus") or ""
    reason = one(o, "ciamManualReason")
    return ", ".join(x for x in (managed, status, f"reason: {reason}" if reason else "") if x)


def _row(d, r, as_of):
    cred = credential_for_role(d, one(r.ref.binding, "ciamBindingRole"))
    due = rotate_by(cred, r.found) if r.found is not None else None
    return (env_label(r.ref.env), one(r.ref.binding, "ciamBindingRole"),
            r.ref.uri + (" (copy)" if r.ref.attr == "ciamCopyRef" else ""), f"{r.ref.scheme}: {r.ref.container}",
            r.state, str(date_of(r.inventory, "ciamInventoryAt") or "") if r.inventory is not None else "",
            str(date_of(r.found, "ciamLastRotated") or "") if r.found is not None else "", str(due or ""),
            _rotation(r.found), "; ".join((*values(r.inventory, "ciamInventoryProblem"),
                                           *rotation_problems(d, r, as_of)) if r.inventory is not None else ()))


def inventory_rows(d, locators, as_of):
    """One row per secret reference a locator places (every environment's, in record order): where it points, its
    state, when its container was inventoried, rotation (last rotated, due by its credential's ciamRotationDays, what
    the store says) and problems; then one row per unreferenced object of an inventoried container."""
    held = inventories(d)
    refs = record_references(d, locators)
    rows = [_row(d, reconcile(d, r, held), as_of) for r in refs]
    strays = [("", "", rdn_value(o), f"{s}: {c}", UNREFERENCED, str(date_of(held[(s, c)], "ciamInventoryAt")),
               str(date_of(o, "ciamLastRotated") or ""), "", _rotation(o), "")
              for s, c, o in unreferenced(d, refs, held)]
    return rows + strays
