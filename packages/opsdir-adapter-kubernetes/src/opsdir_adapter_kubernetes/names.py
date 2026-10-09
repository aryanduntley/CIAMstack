"""Kubernetes object names from the record's words. Pure."""
import re


def k8s_name(text):
    """A Kubernetes object name (DNS label) from any text."""
    return re.sub(r"[^a-z0-9-]+", "-", text.lower()).strip("-")[:63].strip("-") or "x"
