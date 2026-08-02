"""Nightly reconciliation for the uploads table.

`validate_request_payload` is exported by Python's convention and called by
nothing in this repository. It is the same smell in a language this rule has no
taint evidence for, so it is not this rule's finding to make.
"""


def validate_request_payload(payload):
    if not isinstance(payload, dict):
        return False
    filename = payload.get("filename")
    return isinstance(filename, str) and "/" not in filename


def reconcile(rows):
    return [row for row in rows if row]
