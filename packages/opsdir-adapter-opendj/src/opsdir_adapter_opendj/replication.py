"""OpenDJ replication: a migration joins the existing replication topology (dsreplication through a source
replica), so data and the changelog carry over, over the lineage's replication path."""
from opsdir.core.findings import merge_findings
from opsdir_base_ds.replication import check_joins, check_replication_path


def _check_topology(ctx):
    return check_joins(ctx.d, ctx.src, ctx.dst,
                       f"{ctx.dst.label} joins the DS replication topology of {ctx.src.label} "
                       "(replicas join through a source replica; data and changelog carry over).",
                       f"{ctx.dst.label} does not declare that it joins {ctx.src.label}'s replication topology. A "
                       "separate topology needs a full export and import, and loses the changelog.")


def check_replication(ctx):
    """Replication continuity: target replicas must join the existing topology over a routed, open path."""
    return merge_findings([_check_topology(ctx), check_replication_path(ctx)])
