import socket
from unittest.mock import MagicMock, patch

from foxyvpn.proxy.resolver import (
    disable_secure_dns,
    doh_resolve_sync,
    enable_secure_dns,
    secure_getaddrinfo,
)


def test_doh_resolve_sync_mock():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "Answer": [{"type": 1, "data": "1.2.3.4", "TTL": 300}]
    }

    with patch("httpx.get", return_value=mock_resp):
        ip = doh_resolve_sync("test.mozilla.org")
        assert ip == "1.2.3.4"


def test_secure_getaddrinfo_intercepts_mozilla():
    with patch("foxyvpn.proxy.resolver.doh_resolve_sync", return_value="151.101.1.91"):
        res = secure_getaddrinfo("vpn.mozilla.org", 443)
        assert res is not None
        assert any(sockaddr[0] == "151.101.1.91" for *_, sockaddr in res)


def test_secure_getaddrinfo_detects_poisoned_dns():
    def side_effect(host, port, *args, **kwargs):
        if host == "1.2.3.4":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.64.0.1", port))]

    with patch("foxyvpn.proxy.resolver._orig_getaddrinfo", side_effect=side_effect):
        with patch("foxyvpn.proxy.resolver.doh_resolve_sync", return_value="1.2.3.4"):
            res = secure_getaddrinfo("blocked.example.com", 443)
            assert any(sockaddr[0] == "1.2.3.4" for *_, sockaddr in res)


def test_enable_disable_lifecycle():
    disable_secure_dns()
    assert socket.getaddrinfo != secure_getaddrinfo
    enable_secure_dns()
    assert socket.getaddrinfo == secure_getaddrinfo
