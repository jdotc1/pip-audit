"""Exercise CLI failure propagation with synthetic OSV responses."""

from unittest.mock import Mock

import pytest

from pip_audit import _cli
from pip_audit._service.interface import ServiceError
from pip_audit._service.osv import OsvService


@pytest.mark.parametrize("payload", [None, {"next_page_token": "synthetic-next"}])
def test_cli_osv_envelope_error_is_not_a_clean_audit(monkeypatch, capsys, dep_source, payload):
    service = object.__new__(OsvService)
    service.session = Mock()
    service.session.post.return_value.json.return_value = payload
    service.timeout = 3
    service.osv_url = "https://example.invalid/query"
    parser = _cli._parser()
    monkeypatch.setattr(_cli, "_parser", lambda: parser)
    monkeypatch.setattr(_cli, "OsvService", lambda **kwargs: service)
    monkeypatch.setattr(_cli, "PipSource", lambda **kwargs: dep_source())
    monkeypatch.setattr(
        _cli,
        "_parse_args",
        lambda parser: parser.parse_args(["-s", "osv", "--progress-spinner=off"]),
    )

    # Generic ServiceError currently propagates from the CLI entrypoint.
    # Preserve that existing policy while preventing a clean-audit summary.
    with pytest.raises(ServiceError):
        _cli.audit()
    captured = capsys.readouterr()
    assert "No known vulnerabilities found" not in captured.out + captured.err
    service.session.post.assert_called_once()
