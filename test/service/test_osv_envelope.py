"""Regression tests for OSV response envelopes using synthetic responses."""

from unittest.mock import Mock

import pytest

from pip_audit._service.interface import ServiceError
from pip_audit._service.osv import OsvService, _parse_response


@pytest.mark.parametrize(
    "payload",
    [
        None,
        False,
        0,
        "",
        [],
        "invalid",
        [1],
        {"vulns": None},
        {"vulns": {}},
        {"vulns": "invalid"},
        {"vulns": [None]},
        {"error": "synthetic"},
    ],
)
def test_osv_rejects_malformed_envelope(payload):
    response = Mock()
    response.json.return_value = payload
    with pytest.raises(ServiceError):
        _parse_response(response)


@pytest.mark.parametrize(
    "payload", [{}, {"next_page_token": ""}, {"vulns": []}, {"vulns": [], "next_page_token": ""}]
)
def test_osv_complete_empty_envelope(payload):
    response = Mock()
    response.json.return_value = payload
    assert _parse_response(response) == []


@pytest.mark.parametrize(
    "payload",
    [{"next_page_token": "synthetic-next"}, {"vulns": [], "next_page_token": "synthetic-next"}],
)
def test_osv_incomplete_page_is_not_clean(payload):
    response = Mock()
    response.json.return_value = payload
    with pytest.raises(ServiceError, match="incomplete"):
        _parse_response(response)


@pytest.mark.parametrize("payload", [None, False, [], {"next_page_token": "synthetic-next"}])
def test_osv_query_uses_envelope_guard(payload):
    # Bypass only session construction; query executes its production code.
    service = object.__new__(OsvService)
    service.session = Mock()
    service.session.post.return_value.json.return_value = payload
    service.timeout = 3
    service.osv_url = "https://example.invalid/query"
    dependency = Mock()
    dependency.is_skipped.return_value = False
    dependency.canonical_name = "synthetic-package"
    dependency.version = "1.0"
    with pytest.raises(ServiceError):
        service.query(dependency)
    assert service.session.post.call_count == 1


@pytest.mark.parametrize("token", [None, 0, [], {}])
def test_osv_rejects_malformed_page_token(token):
    response = Mock()
    response.json.return_value = {"vulns": [], "next_page_token": token}
    with pytest.raises(ServiceError, match="must be a string"):
        _parse_response(response)


def test_osv_json_error_does_not_echo_body():
    response = Mock()
    response.json.side_effect = ValueError("synthetic body must not appear")
    with pytest.raises(ServiceError, match="invalid JSON") as exc:
        _parse_response(response)
    assert "synthetic body" not in str(exc.value)
    assert exc.value.__suppress_context__ is True


def test_osv_preserves_records_and_extension_fields():
    records = [{"id": "SYNTHETIC-0", "extensions": {"synthetic": True}}]
    response = Mock()
    response.json.return_value = {"vulns": records, "unknown_metadata": "accepted"}
    assert _parse_response(response) is records
