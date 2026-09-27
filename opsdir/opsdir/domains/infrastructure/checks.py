"""Infrastructure planner checks."""
from ...core.directory import one
from ...core.findings import findings, responsible


def check_versions(ctx):
    """Same product versions in both environments is a re-host; a difference is an upgrade to test separately."""
    sv = {one(s, "ciamProductVersion") for s in ctx.src.servers}
    dv = {one(s, "ciamProductVersion") for s in ctx.dst.servers}
    if sv == dv:
        return findings(ok=[f"Same product versions in both environments ({', '.join(sorted(sv))}): "
                            "a re-host, not an upgrade."])
    return findings(actions=[("Versions", f"Versions differ ({sorted(sv)} → {sorted(dv)}). Test compatibility "
                              "separately from the move.", responsible(ctx.d, ctx.dst.env), None)])
