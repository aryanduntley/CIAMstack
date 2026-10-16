"""How long an Elastic data stream keeps logs, as Elasticsearch takes it (decision on task 552): an index lifecycle
(ILM) policy per data stream the environment keeps, attached through its dataset's component template, and when it
keeps them longer in all than searchable, a snapshot lifecycle (SLM) policy archiving them. Pure: the API documents,
as the APIs answer a GET of them (what the importer reads back).

The ILM policy opsdir-<stream>: the hot phase rolls the backing index over every day or at 50 GB a primary shard
(Elasticsearch counts a phase's age from rollover, so the days stay within a day of the record's); the delete phase
deletes a backing index ciamRetentionDays after its rollover (none: kept indefinitely); its _meta names the stream.
The component template <type>-<dataset>@custom sets index.lifecycle.name to it: the hook Elastic documents for one
dataset's own lifecycle, composed by the dataset's integration template (Fleet's), for every namespace of the dataset.

The archive: Elasticsearch keeps what it must restore before searching as snapshots in a repository (the destination's
ciamArchiveRef). The SLM policy opsdir-<stream> snapshots the stream every day into it and expires a snapshot
(ciamTotalRetentionDays - ciamRetentionDays) days after it is taken; the ILM delete phase waits for that policy's next
snapshot (wait_for_snapshot), so the last snapshot holding a backing index is taken as it is deleted and the logs are
kept that much longer in all.

Named instead (lifecycle_notes): a stream recording no retention (nothing rendered), streams sharing a dataset (its
component template attaches one policy to all of them), when the policy takes effect (backing indices created from the
next rollover, through templates composing the hook) and an archive the record keeps no place for.
"""
from opsdir.core.directory import one, rdn_value
from opsdir.core.notes import RECORD, note
from opsdir.domains.observability.retention import INDEFINITE, retention_days
from .naming import custom_template, kept_streams, policy_name, stream_name

ROLLOVER = {"max_age": "1d", "max_primary_shard_size": "50gb"}
SNAPSHOT_SCHEDULE = "0 30 1 * * ?"          # every day at 01:30 (Elasticsearch's cron, seconds first)
MANAGED = "opsdir"                          # _meta.managed_by of what the render writes


def total_days(b):
    """Days destination b keeps logs in all (ciamTotalRetentionDays), or None when it records none."""
    v = one(b, "ciamTotalRetentionDays")
    return int(v) if v is not None else None


def archive_days(b):
    """How many days destination b keeps its logs past its searchable days, restore needed (total minus searchable;
    INDEFINITE when kept forever in all), or None when it keeps nothing past them."""
    days, total = retention_days(b), total_days(b)
    if days in (None, INDEFINITE) or total is None:
        return None
    return INDEFINITE if total == INDEFINITE else total - days if total > days else None


def snapshotted(b):
    """Whether destination b's archive is rendered: it keeps logs past its searchable days and records where
    (ciamArchiveRef)."""
    return archive_days(b) is not None and bool(one(b, "ciamArchiveRef"))


def ilm_policy(b):
    """(policy name, the ILM policy as GET _ilm/policy answers it) of data stream destination b; None when it records
    no retention."""
    days, stream = retention_days(b), stream_name(b)
    if days is None:
        return None
    name = policy_name(stream)
    phases = {"hot": {"min_age": "0ms", "actions": {"rollover": dict(ROLLOVER)}},
              **({"delete": {"min_age": f"{days}d", "actions": {
                  **({"wait_for_snapshot": {"policy": name}} if snapshotted(b) else {}),
                  "delete": {"delete_searchable_snapshot": True}}}} if days != INDEFINITE else {})}
    return name, {"policy": {"phases": phases, "_meta": {"managed_by": MANAGED, "data_stream": stream}}}


def slm_policy(b):
    """(policy name, the SLM policy as GET _slm/policy answers it) archiving data stream destination b, or None when
    nothing of it is archived (snapshotted)."""
    if not snapshotted(b):
        return None
    stream, days = stream_name(b), archive_days(b)
    return policy_name(stream), {"policy": {
        "name": f"<{policy_name(stream)}-{{now/d}}>", "schedule": SNAPSHOT_SCHEDULE,
        "repository": one(b, "ciamArchiveRef"),
        "config": {"indices": [stream], "include_global_state": False},
        **({"retention": {"expire_after": f"{days}d"}} if days != INDEFINITE else {})}}


def _attached(m):
    """{component template: the first kept stream of its dataset recording a retention}: what each dataset's hook
    attaches."""
    found = tuple(b for b in kept_streams(m) if retention_days(b) is not None)
    return {t: next(b for b in found if custom_template(stream_name(b)) == t)
            for t in dict.fromkeys(custom_template(stream_name(b)) for b in found)}


def rendered_streams(m):
    """Environment m's kept data streams whose policies render: each dataset's first recording a retention."""
    return tuple(_attached(m).values())


def component_template(b):
    """(component template name, the component template as GET _component_template answers it) attaching data stream
    destination b's ILM policy to its dataset."""
    return custom_template(stream_name(b)), {"template": {"settings": {"index": {"lifecycle": {
        "name": policy_name(stream_name(b))}}}}, "_meta": {"managed_by": MANAGED}}


def _kept_as(b):
    return retention_days(b), total_days(b), one(b, "ciamArchiveRef")


def _shared_notes(m):
    attached = _attached(m)
    later = tuple(b for b in kept_streams(m) if retention_days(b) is not None
                  and attached[custom_template(stream_name(b))] is not b)

    def of(b):
        first = attached[custom_template(stream_name(b))]
        template, same = custom_template(stream_name(b)), _kept_as(b) == _kept_as(first)
        if same:
            return note("Logs", "note", f"Elastic data stream {stream_name(b)}",
                        f"kept by {policy_name(stream_name(first))}: its dataset's component template {template} "
                        f"attaches one policy to every namespace, and {stream_name(first)} keeps logs as long", (),
                        b.dn, m.label)
        return note("Logs", "blocker", f"Elastic data stream {stream_name(b)}", f"its retention isn't rendered: its "
                    f"dataset's component template {template} attaches one policy to every namespace, "
                    f"{policy_name(stream_name(first))} (of {stream_name(first)}, which keeps logs differently)",
                    ("Name the streams with different datasets, or keep them as long", "Or clone the dataset's "
                     "integration template for one namespace (Elastic's per-namespace procedure) by hand"),
                    b.dn, m.label)
    return tuple(of(b) for b in later)


def lifecycle_notes(m):
    """The render notes of environment m's data streams' retention: none recorded (a note), streams sharing a dataset
    (a note when they keep logs as long, else a blocker), when each policy takes effect (an action) and an archive
    with no place recorded (an action)."""
    return (
        *(note("Logs", "note", f"Elastic data stream {stream_name(b)}", "records no retention (ciamRetentionDays): no "
               "lifecycle policy rendered, so the stream keeps what its index template says",
               ("Read what Elastic keeps into the record (elastic/elasticsearch), or record the retention the "
                "obligations need",), b.dn, m.label)
          for b in kept_streams(m) if retention_days(b) is None),
        *_shared_notes(m),
        *(note("Logs", "action", f"Elastic data stream {stream_name(b)}", f"{policy_name(stream_name(b))} is attached "
               f"through the component template {custom_template(stream_name(b))}, which takes effect for the "
               "backing indices created from the next rollover, and only where the stream's index template composes "
               "it (Fleet integration templates do; the built-in logs template doesn't)",
               (f"Switch the existing backing indices: remove their policy, then PUT {stream_name(b)}/_settings with "
                f"index.lifecycle.name {policy_name(stream_name(b))}",
                f"Confirm the stream's index template composes {custom_template(stream_name(b))}, and that nothing "
                "else the Elastic team keeps in that component template is lost (opsdir writes all of it)"),
               b.dn, m.label)
          for b in rendered_streams(m)),
        *(note("Logs", "action", f"Elastic data stream {stream_name(b)}", f"keeps logs {retention_days(b)} days "
               f"searchable and {one(b, 'ciamTotalRetentionDays')} in all, but records no archive (ciamArchiveRef: "
               "the snapshot repository): no snapshot policy rendered, so they are deleted after "
               f"{retention_days(b)} days",
               (f"Record the snapshot repository keeping {rdn_value(b)}'s archive in ciamArchiveRef, {RECORD}",),
               b.dn, m.label)
          for b in rendered_streams(m) if archive_days(b) is not None and not one(b, "ciamArchiveRef")))

