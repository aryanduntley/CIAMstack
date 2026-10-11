"""Messaging domain vocabulary: where external services, mail senders and event streams live."""
from ...core.naming import branch

EXTERNAL_SERVICES = branch("external-services")
MAIL_SENDERS = branch("mail-senders")
EVENT_STREAMS = branch("event-streams")
SERVICE_KINDS = ("smtp-relay", "email-api", "sms", "voice", "mfa", "captcha", "push", "other")
# how the platform signs in to an SMTP relay: none, a password (basic), or an OAuth 2.0 bearer token it obtains with
# the client credentials grant, authenticating by a client secret or a private-key JWT
SMTP_AUTH = ("none", "basic", "oauth-client-credentials", "oauth-private-key-jwt")
STREAM_KINDS = ("queue", "topic", "bus", "event-hub", "webhook", "log-stream", "other")
DMARC_STRENGTH = ("none", "quarantine", "reject")      # weakest first


def service_dn(name):
    return f"cn={name},{EXTERNAL_SERVICES}"


def sender_dn(name):
    return f"cn={name},{MAIL_SENDERS}"


def stream_dn(name):
    return f"cn={name},{EVENT_STREAMS}"
