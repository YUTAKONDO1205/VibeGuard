# E6 fixture — CONTROL for the test-path case.
# A real production HTTP client that disables TLS verification. Lives on a
# normal source path, so item ① must keep VG-AUTH-004 at its default (high).
import requests


def fetch_report():
    return requests.get("https://reports.internal.acme.corp", verify=False)
