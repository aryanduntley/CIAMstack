"""Configuration planner checks: every captured config file the target receives can be rendered there."""
from ...core.directory import one
from ...core.findings import findings, merge_findings, responsible
from .record import deployed_files, render_problems


def _config_file(ctx, f):
    name, why = one(f, "cn"), render_problems(ctx.d, f, ctx.dst)
    if one(f, "ciamCaptureLevel") == "reference":
        return findings(actions=[("Config file", f"`{name}` is held only as a reference: deploy it to {ctx.dst.label} "
                                  f"from {one(f, 'ciamRepoPath')} ({one(f, 'ciamCaptureProblem')}).",
                                  responsible(ctx.d, f), None)])
    if why:
        return findings(blockers=[("Config file", f"`{name}` can't be rendered for {ctx.dst.label}: {'; '.join(why)}.",
                                   responsible(ctx.d, f, ctx.dst.env))])
    return findings(ok=[f"Config file `{name}` renders for {ctx.dst.label} ({one(f, 'ciamRepoPath')})."])


def check_config_files(ctx):
    """Every captured file the target receives renders there: links resolve, withheld values have a secret
    reference; files held only as references are actions (deployed from their repo)."""
    return merge_findings([_config_file(ctx, f) for f in deployed_files(ctx.d, ctx.dst)])
