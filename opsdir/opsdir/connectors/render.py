"""Render a complete, working configuration set for one environment: the applicable adapters' outputs, each in a
format the adapter declares and some installed package registers, the captured config files the environment
receives, plus the MANIFEST (R10) and the render's notes (NOTES.md, NOTES.json: what it could not do, or leaves to a
person, core.notes)."""
from ..core.environment import as_seen
from ..core.formats import format_of
from ..core.manifest import manifest
from ..core.notes import collected, notes_json, notes_markdown, ordered, with_owners
from ..domains.observability.canaries import unrun_notes
from ..core.profiles import profile_tree
from ..domains.governance.keepers import check_scope
from .capture import RenderedConfig, rendered_config
from .registry import ADAPTERS, FORMATS, environment, services


# what a render scoped to a slice receives of the captured config files: none (they are the environment's)
_NO_CONFIG = RenderedConfig({}, {}, {}, ())


def stack_targets(stack):
    """{adapter name: the render targets its components in an environment's stack declare (ciamRenderTarget)}, for
    the adapters whose components declare any."""
    return {c.adapter: tuple(dict.fromkeys(t for s in stack if s.adapter == c.adapter for t in s.targets))
            for c in stack if c.targets}


def _refuse_undeclared(chosen, declared, where):
    """Refuses a choice ({adapter: (target, ...)}) naming an adapter that declares no targets or a target it doesn't
    declare, naming those it does; where says whose choice it is."""
    unknown = sorted(name for name in chosen if name not in declared)
    if unknown:
        raise SystemExit(f"no render targets to choose for {', '.join(unknown)} {where} (adapters with targets: "
                         f"{', '.join(sorted(declared)) or 'none'})")
    wrong = sorted(f"{name}={t} (it renders: {', '.join(declared[name])})" for name, ts in chosen.items()
                   for t in ts if t not in declared[name])
    if wrong:
        raise SystemExit(f"unknown render targets{'' if where == 'here' else f' {where}'}: {', '.join(wrong)}")


def chosen_targets(adapters, wanted=None, stack=()):
    """{adapter name: the render targets chosen} for the adapters that declare targets. The form a render writes is
    the user's choice (wanted: {adapter: (names, ...)}, the render's own), else the adapter's targets not marked
    only-when-asked; unless the environment holds a form (its stack's ciamRenderTarget for the adapter): then that
    binds, and a render may choose among the forms it holds, never another. Refused for an adapter that declares none
    here, a target it doesn't declare (naming those it does), or a form the environment doesn't hold (naming those it
    does)."""
    wanted, declared_by_stack = wanted or {}, stack_targets(stack)
    declared = {a.name: tuple(t[0] for t in a.render_targets) for a in adapters if a.render_targets}
    defaults = {a.name: tuple(t[0] for t in a.render_targets if len(t) < 3 or t[2]) for a in adapters
                if a.render_targets}
    _refuse_undeclared(declared_by_stack, declared, "in the environment's stack (run `opsdir check`)")
    _refuse_undeclared(wanted, declared, "here")
    unheld = sorted(f"{name}={t}" for name, ts in wanted.items() if name in declared_by_stack
                    for t in ts if t not in declared_by_stack[name])
    if unheld:
        held = "; ".join(f"{name}: {', '.join(declared_by_stack[name])}" for name in sorted(declared_by_stack)
                         if any(u.startswith(f"{name}=") for u in unheld))
        raise SystemExit(f"the environment holds its render form ({held}; its stack's ciamRenderTarget): it can't be "
                         f"rendered as {', '.join(unheld)} (change its ciamRenderTarget, under an approved change, "
                         "to render it otherwise)")
    chosen = {**defaults, **declared_by_stack, **wanted}
    return {name: tuple(t for t in names if t in chosen[name]) for name, names in declared.items()}


def _env_files(a, m, found, targets):
    return a.render_env(m, found, targets[a.name]) if a.name in targets else a.render_env(m, found)


def _kit_profiles(m, adapters, neutral, specific, targets):
    """The deployment kits' renders of the products' profiles (Adapter.render_profiles): every product adapter's
    instance files (core.profiles.profile_tree) of what the environment renders, captured files included."""
    kits = [a for a in adapters if a.render_profiles]
    if not kits:
        return {}
    files = {**neutral, **specific, **rendered_config(m.d, m).files}
    profiles = {a.profile.product: profile_tree(a.profile, files) for a in adapters if a.profile}
    return {p: text for a in kits for p, text in a.render_profiles(m, profiles, targets.get(a.name, ())).items()}


def render_parts(d, spec, installed=ADAPTERS, wanted=None, scope=None):
    """(EnvModel as the environment sees the record (its overrides applied), applicable adapters,
    environment-neutral files, environment-specific files, the render targets chosen); wanted: {adapter: (target,
    ...)} (default: those its stack declares, else each adapter's defaults). No provider adapter is needed: an
    environment whose infrastructure no installed adapter renders (a Kubernetes cluster on the operator's own
    hardware) still gets what its other adapters render; one that no installed adapter renders anything for is
    refused. scope (core.environment.Scope, 5.7): a keeper, class or bindings scope renders the infrastructure of that
    slice only (the provider adapters' files, placed by governance.keepers), refused when it selects nothing."""
    shared, adapters = environment(d, spec, installed)
    m = as_seen(shared)._replace(scope=scope)
    check_scope(m)
    sliced = scope is not None and scope.kind != "environment"
    adapters = tuple(a for a in adapters if a.kind == "provider") if sliced else adapters
    if not any(a.render_neutral or a.render_env for a in adapters):
        raise SystemExit(f"nothing renders {m.label}: no installed adapter that renders applies to it (provider "
                         f"{m.provider})")
    targets = chosen_targets(adapters, wanted, m.stack)
    neutral = {p: text for a in adapters if a.render_neutral for p, text in a.render_neutral(m.d).items()}
    found = services(installed, targets)
    specific = {p: text for a in adapters if a.render_env for p, text in _env_files(a, m, found, targets).items()}
    specific = {**specific, **_kit_profiles(m, adapters, neutral, specific, targets)} if not sliced else specific
    if sliced and not specific:
        raise SystemExit(f"nothing of {m.label} is rendered for {scope.kind} {', '.join(scope.value)}: a render places "
                         "by entry what someone else may keep (network plumbing, the landing zone, databases, object "
                         "stores, volumes, backups, audit trails, monitors, security services, budgets)")
    return m, adapters, ({} if sliced else neutral), specific, targets


def _declared(adapters, path):
    """(adapter, format name) of the first applicable adapter that declares a format for the path."""
    return next(((a, name) for a in adapters for name in (format_of(path, a.formats),) if name), (None, None))


def file_formats(adapters, paths, formats=FORMATS):
    """{path: format name} for every rendered file; refused when no adapter declares a file's format, or the format it
    declares is not registered (the file would be in a language nothing describes)."""
    registered = {f.name for f in formats}
    found = {p: _declared(adapters, p) for p in paths}
    undeclared = sorted(p for p, (a, _) in found.items() if a is None)
    if undeclared:
        raise SystemExit(f"no adapter declares the format of: {', '.join(undeclared)}")
    unknown = sorted(f"{p} ({name}, declared by {a.name})" for p, (a, name) in found.items() if name not in registered)
    if unknown:
        raise SystemExit(f"rendered files are in formats no installed package registers: {', '.join(unknown)}")
    return {p: name for p, (_, name) in found.items()}


def adapter_notes(m, adapters, installed=ADAPTERS, targets=None):
    """The RenderNotes of environment m's render: those the adapters rendering it return (Adapter.notes, with the
    Services of the installed adapters and the render targets chosen, as their render_env gets them), then the core's
    own: its canaries none of them renders (observability unrun_notes, naming the installed adapters that render
    synthetic checks)."""
    found = services(installed, targets)
    return (*(n for a in adapters if a.notes for n in a.notes(m, found)),
            *unrun_notes(m, adapters, found.endpoints, tuple(a.name for a in installed if a.renders_synthetic_checks)))


def environment_notes(d, spec, installed=ADAPTERS):
    """(EnvModel as the environment sees the record, its render's RenderNotes with owners, no places) without
    rendering it: what `opsdir check` lists."""
    shared, adapters = environment(d, spec, installed)
    m = as_seen(shared)
    return m, ordered(with_owners(m.d, m.env, adapter_notes(m, adapters, installed,
                                                         chosen_targets(adapters, None, m.stack))))


def assemble(m, adapters, neutral, specific, targets=None, requester=None, installed=ADAPTERS):
    """The environment's files: the adapters' outputs, the captured config files it receives (all of the environment
    only), the MANIFEST (with the render targets chosen, and the scope and requester of a requested render), and the
    render's notes, NOTES.md and NOTES.json (the adapters' notes located in the files, the files' other NOTE comments
    to review, core.notes.collected; always written: none says nothing needs handling)."""
    config = rendered_config(m.d, m) if m.scope is None or m.scope.kind == "environment" else _NO_CONFIG
    clash = sorted(set(config.files) & {*neutral, *specific})
    if clash:
        raise SystemExit(f"captured files and rendered files share paths: {', '.join(clash)}")
    formats = {**file_formats(adapters, (*neutral, *specific)), **config.formats}
    files = {**neutral, **specific, **config.files}
    notes = collected(m, adapter_notes(m, adapters, installed, targets), files)
    return {**files,
            "MANIFEST.json": manifest(m, neutral, specific, formats, config.files, config.scopes, config.not_rendered,
                                      targets, requester),
            "NOTES.md": notes_markdown(m, notes), "NOTES.json": notes_json(m, notes)}


def render_env(d, spec, installed=ADAPTERS, wanted=None, scope=None, requester=None):
    """(EnvModel, {path: text}) of a render of environment spec: render_parts, assembled with its MANIFEST."""
    m, adapters, neutral, specific, targets = render_parts(d, spec, installed, wanted, scope)
    return m, assemble(m, adapters, neutral, specific, targets, requester, installed)
