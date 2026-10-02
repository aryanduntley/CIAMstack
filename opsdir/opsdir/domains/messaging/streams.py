"""Event streams: identity events the platform publishes to queues, topics and buses. The report and the planner's
check. Pure. A stream is intent; the queue or bus that carries it in each environment is a binding (ciamStreamRole):
a stream whose carrier neither environment binds is a blocker (the core role check covers one the source binds)."""
from ...core.directory import children, one, rdn_value, values
from ...core.environment import bound_nowhere
from ...core.findings import findings, merge_findings, responsible
from .naming import EVENT_STREAMS

STREAM_HEADERS = ("stream", "kind", "events", "published by", "carried by", "consumed by")


def event_streams(d):
    return children(d, EVENT_STREAMS, "ciamEventStream")


def stream_rows(d, dn=None):
    """One row per event stream."""
    return [(rdn_value(s), one(s, "ciamStreamKind"), ", ".join(values(s, "ciamEventType")),
             ", ".join(values(s, "ciamPublishedBy")), one(s, "ciamStreamRole") or "",
             ", ".join(values(s, "ciamConsumedBy")))
            for s in event_streams(d)]


def _stream(ctx, s):
    role = one(s, "ciamStreamRole")
    nobody = bound_nowhere((role,), ctx.src, ctx.dst)
    return findings(blockers=((("Stream", f"Event stream `{rdn_value(s)}` is carried by role `{role}`, which neither "
                                f"{ctx.src.label} nor {ctx.dst.label} binds: record each environment's queue or bus.",
                                responsible(ctx.d, s, ctx.dst.env)),) if nobody else ()),
                    actions=((("Stream", f"Event stream `{rdn_value(s)}` records nobody who reads it: events nobody "
                               "consumes after a move go unnoticed. Record its consumers.",
                               responsible(ctx.d, s, ctx.dst.env), None),) if not values(s, "ciamConsumedBy") else ()))


def check_streams(ctx):
    """Streams whose carrier neither environment binds are blockers; streams nobody reads are actions."""
    held = event_streams(ctx.d)
    return merge_findings([_stream(ctx, s) for s in held]) if held else findings()
