# E6 fixture — TREATMENT for the test-path case.
# Identical `verify=False` to tls_client.py, but on a *.test.py path. Disabling
# TLS verification in a test against a local server is routine and low-stakes,
# so item ① should drop the confidence one step (high -> medium) — still
# reported, just de-prioritised relative to the production occurrence.
import requests


def test_fetch_report():
    # exercising the endpoint against a local self-signed server
    return requests.get("https://localhost:8443/health", verify=False)
