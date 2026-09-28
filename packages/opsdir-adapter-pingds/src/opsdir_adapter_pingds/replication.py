"""PingDS replication: a migration stays inside the existing replication deployment (same deployment ID, so
encrypted data and backups stay readable), over the lineage's replication path."""
from opsdir.core.findings import merge_findings
from opsdir_base_ds.replication import check_joins, check_replication_path


def _check_deployment(ctx):
    return check_joins(ctx.d, ctx.src, ctx.dst,
                       f"{ctx.dst.label} joins the DS replication deployment of {ctx.src.label} "
                       "(same deployment ID; keys and encrypted data stay readable).",
                       f"{ctx.dst.label} does not declare that it joins {ctx.src.label}'s deployment. A fresh "
                       "deployment can't decrypt existing encrypted data or backups.")


def check_replication(ctx):
    """Replication continuity: target replicas must join the existing deployment over a routed, open path."""
    return merge_findings([_check_deployment(ctx), check_replication_path(ctx)])
