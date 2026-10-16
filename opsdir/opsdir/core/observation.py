"""Observations: what an endpoint answered to an observing Request (core.contract Request with observe), or why it
answered nothing, as the text a collection keeps in its export (JSON: observedAt, status, contentType, body as base64
so a binary answer such as a DER CRL is kept, error), and read back by importers. Pure: the runner (live.py) makes the
request and dates it."""
import base64
import binascii
import datetime as dt
import json
from typing import NamedTuple


# An endpoint's answer as an observing Request recorded it: when (an aware UTC datetime), the HTTP status (None: no
# answer), its content type, its body (bytes, or None) and why there was no answer (None: there was one).
Observation = NamedTuple("Observation", [("at", object), ("status", object), ("content_type", object),
                                         ("body", object), ("error", object)])


def observation(at, status, content_type, body, error):
    """An observing Request's output text: JSON {observedAt (ISO 8601 UTC, Z), status, contentType, body (base64, so
    a binary answer is kept), error}."""
    return json.dumps({"observedAt": at.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), "status": status,
                       "contentType": content_type,
                       "body": base64.b64encode(body).decode("ascii") if body is not None else None,
                       "error": error}, indent=1) + "\n"


def read_observation(text):
    """(Observation, problem): an observing Request's output read back; (None, why) when it isn't one."""
    try:
        doc = json.loads(text)
        at = dt.datetime.strptime(doc["observedAt"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
        body = base64.b64decode(doc["body"], validate=True) if doc.get("body") is not None else None
    except (ValueError, TypeError, KeyError, binascii.Error) as e:
        return None, f"not an observation ({type(e).__name__}: {e})"
    status = doc.get("status")
    if status is not None and (not isinstance(status, int) or isinstance(status, bool)):
        return None, f"not an observation (status {status!r})"
    return Observation(at, status, doc.get("contentType"), body, doc.get("error")), None
