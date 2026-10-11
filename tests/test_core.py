"""Unit tests for FoxyVPN core models, configuration, and persistent storage."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from foxyvpn.core.config import (
    DOH_PROVIDERS,
    DOH_SERVERS,
    UPSTREAM_PROXY_TYPES,
    Settings,
    get_config_dir,
    get_default_config_path,
    load_settings,
    save_settings,
)
from foxyvpn.core.models import (
    ConnectionState,
    Entitlement,
    ProxyCandidate,
    ProxyPass,
    RuntimeAuth,
    UpstreamProxyConfig,
    VpnCity,
    VpnCountry,
    VpnProtocol,
    VpnServerNode,
    from_dict,
    to_dict,
)
from foxyvpn.core.store import SettingsStore, TokenStore


class TestRuntimeAuth:
    def test_creation_and_defaults(self):
        auth = RuntimeAuth(
            access_token="acc_123",
            refresh_token="ref_456",
            expires_at_epoch_seconds=1800000000,
        )
        assert auth.access_token == "acc_123"
        assert auth.refresh_token == "ref_456"
        assert auth.expires_at_epoch_seconds == 1800000000
        assert auth.email is None

        auth_with_email = RuntimeAuth(
            access_token="acc_123",
            refresh_token=None,
            expires_at_epoch_seconds=1800000000,
            email="test@mozilla.com",
        )
        assert auth_with_email.email == "test@mozilla.com"
        assert auth_with_email.refresh_token is None

    def test_serialization_roundtrip(self):
        auth = RuntimeAuth("token", "refresh", 1700000000, "user@example.com")
        d = auth.to_dict()
        assert d == {
            "access_token": "token",
            "refresh_token": "refresh",
            "expires_at_epoch_seconds": 1700000000,
            "email": "user@example.com",
        }
        restored = RuntimeAuth.from_dict(d)
        assert restored == auth

    def test_from_dict_camel_case(self):
        d = {
            "accessToken": "tok_camel",
            "refreshToken": "ref_camel",
            "expiresAtEpochSeconds": 1750000000,
            "email": "camel@example.com",
        }
        auth = RuntimeAuth.from_dict(d)
        assert auth.access_token == "tok_camel"
        assert auth.refresh_token == "ref_camel"
        assert auth.expires_at_epoch_seconds == 1750000000
        assert auth.email == "camel@example.com"


class TestProxyPass:
    def test_creation_and_defaults(self):
        pass_data = ProxyPass(token="proxy_tok")
        assert pass_data.token == "proxy_tok"
        assert pass_data.expires_at_epoch_seconds is None
        assert pass_data.quota_max is None
        assert pass_data.quota_remaining is None
        assert pass_data.quota_reset is None

    def test_serialization_roundtrip(self):
        pass_data = ProxyPass(
            token="token_xyz",
            expires_at_epoch_seconds=1720000000,
            quota_max=10000,
            quota_remaining=5000,
            quota_reset=1730000000,
        )
        d = pass_data.to_dict()
        restored = ProxyPass.from_dict(d)
        assert restored == pass_data

    def test_from_dict_camel_case(self):
        d = {
            "token": "tok_1",
            "expiresAtEpochSeconds": 1700000,
            "quotaMax": 100,
            "quotaRemaining": 50,
            "quotaReset": 1800000,
        }
        res = ProxyPass.from_dict(d)
        assert res.token == "tok_1"
        assert res.expires_at_epoch_seconds == 1700000
        assert res.quota_max == 100
        assert res.quota_remaining == 50
        assert res.quota_reset == 1800000


class TestEntitlement:
    def test_creation_and_serialization(self):
        ent = Entitlement(
            subscribed=True,
            uid="uid_123",
            max_bytes=1073741824,
            limited_bandwidth=False,
            quota_remaining=536870912,
        )
        assert ent.subscribed is True
        assert ent.uid == "uid_123"
        assert ent.max_bytes == 1073741824
        assert ent.limited_bandwidth is False
        assert ent.quota_remaining == 536870912

        d = ent.to_dict()
        restored = Entitlement.from_dict(d)
        assert restored == ent

    def test_from_dict_camel_case(self):
        d = {
            "subscribed": True,
            "uid": "user_456",
            "maxBytes": 2048,
            "limitedBandwidth": True,
            "quotaRemaining": 1024,
        }
        ent = Entitlement.from_dict(d)
        assert ent.subscribed is True
        assert ent.uid == "user_456"
        assert ent.max_bytes == 2048
        assert ent.limited_bandwidth is True
        assert ent.quota_remaining == 1024


class TestVpnHierarchyModels:
    def test_vpn_protocol(self):
        proto = VpnProtocol(
            name="wireguard",
            host="wg.vpn.com",
            port=51820,
            scheme="udp",
            template_string="vpn://template",
        )
        d = proto.to_dict()
        restored = VpnProtocol.from_dict(d)
        assert restored == proto

        camel_proto = VpnProtocol.from_dict({
            "name": "socks5",
            "host": "s.vpn.com",
            "port": 1080,
            "scheme": "tcp",
            "templateString": "tmpl",
        })
        assert camel_proto.template_string == "tmpl"

    def test_vpn_hierarchy_full_tree(self):
        proto1 = VpnProtocol(name="http2", host="node1.net", port=443, scheme="tls")
        proto2 = VpnProtocol(name="wireguard", host="node1.net", port=51820, scheme="udp")
        node1 = VpnServerNode(hostname="node1.net", port=443, quarantined=False, protocols=[proto1, proto2])
        node2 = VpnServerNode(hostname="node2.net", port=443, quarantined=True, protocols=[])

        city1 = VpnCity(name="Frankfurt", code="FRA", servers=[node1, node2])
        country1 = VpnCountry(name="Germany", code="DE", cities=[city1])

        serialized = country1.to_dict()
        assert serialized["name"] == "Germany"
        assert serialized["code"] == "DE"
        assert len(serialized["cities"]) == 1
        assert serialized["cities"][0]["code"] == "FRA"
        assert len(serialized["cities"][0]["servers"]) == 2
        assert serialized["cities"][0]["servers"][0]["protocols"][0]["name"] == "http2"

        # JSON string roundtrip
        json_str = json.dumps(serialized)
        restored_dict = json.loads(json_str)
        restored_country = VpnCountry.from_dict(restored_dict)
        assert restored_country == country1


class TestProxyCandidate:
    def test_proxy_candidate_authority(self):
        cand = ProxyCandidate(
            host="192.168.1.1",
            port=8080,
            country_code="US",
            country_name="United States",
            city_code="NYC",
            ping_ms=25.4,
        )
        assert cand.authority == "192.168.1.1:8080"
        d = cand.to_dict()
        assert d["host"] == "192.168.1.1"
        assert d["ping_ms"] == 25.4

        camel = ProxyCandidate.from_dict({
            "host": "10.0.0.1",
            "port": 443,
            "countryCode": "FR",
            "countryName": "France",
            "cityCode": "PAR",
            "pingMs": 15.2,
        })
        assert camel.country_code == "FR"
        assert camel.city_code == "PAR"
        assert camel.ping_ms == 15.2
        assert camel.authority == "10.0.0.1:443"


class TestUpstreamProxyConfig:
    def test_upstream_proxy_config(self):
        cfg = UpstreamProxyConfig(
            type="socks5",
            host="proxy.corp.net",
            port=1080,
            username="user1",
            password="pwd",
        )
        d = cfg.to_dict()
        restored = UpstreamProxyConfig.from_dict(d)
        assert restored == cfg


class TestConnectionState:
    def test_connection_state_defaults_and_roundtrip(self):
        state = ConnectionState(status="connecting")
        assert state.status == "connecting"
        assert state.socks_port == 10808
        assert state.bytes_sent == 0
        assert state.bytes_received == 0
        assert state.start_time is None

        full_state = ConnectionState(
            status="connected",
            location="Frankfurt, Germany",
            edge_ip="1.2.3.4",
            server_hostname="edge-fra-1.foxyvpn.com",
            socks_port=10808,
            bytes_sent=1024,
            bytes_received=2048,
            start_time=1700000000.5,
        )
        d = full_state.to_dict()
        restored = ConnectionState.from_dict(d)
        assert restored == full_state

    def test_connection_state_camel_case(self):
        d = {
            "status": "connected",
            "location": "Paris",
            "edgeIp": "5.6.7.8",
            "serverHostname": "edge-par.com",
            "socksPort": 9050,
            "bytesSent": 500,
            "bytesReceived": 1500,
            "startTime": 1711111111.0,
        }
        state = ConnectionState.from_dict(d)
        assert state.edge_ip == "5.6.7.8"
        assert state.server_hostname == "edge-par.com"
        assert state.socks_port == 9050
        assert state.bytes_sent == 500
        assert state.bytes_received == 1500
        assert state.start_time == 1711111111.0


class TestGenericSerializationHelpers:
    def test_to_dict_and_from_dict(self):
        auth = RuntimeAuth("t1", "r1", 100)
        d = to_dict(auth)
        assert isinstance(d, dict)
        assert d["access_token"] == "t1"

        obj_list = [auth, RuntimeAuth("t2", "r2", 200)]
        d_list = to_dict(obj_list)
        assert len(d_list) == 2
        assert d_list[1]["access_token"] == "t2"

        reconstructed = from_dict(RuntimeAuth, d)
        assert reconstructed == auth


class TestConfigAndSettings:
    def test_settings_defaults(self):
        s = Settings()
        assert s.socks_host == "127.0.0.1"
        assert s.socks_port == 10808
        assert s.doh_provider == "automatic"
        assert s.custom_dns == ""
        assert s.exit_check is True
        assert s.system_proxy is False
        assert s.custom_edge == ""
        assert s.upstream_proxy_enabled is False
        assert s.upstream_proxy_type == "socks5"
        assert s.upstream_proxy_host == ""
        assert s.upstream_proxy_port == 1080
        assert s.upstream_proxy_user == ""
        assert s.upstream_proxy_pass == ""
        assert s.default_country == "REC"
        assert s.default_city == ""

    def test_settings_constants(self):
        assert "automatic" in DOH_PROVIDERS
        assert "cloudflare" in DOH_PROVIDERS
        assert "google" in DOH_PROVIDERS
        assert "quad9" in DOH_PROVIDERS
        assert "off" in DOH_PROVIDERS
        assert "socks5" in UPSTREAM_PROXY_TYPES
        assert "http" in UPSTREAM_PROXY_TYPES

    def test_effective_doh_servers(self):
        s = Settings(doh_provider="cloudflare")
        assert s.effective_doh_servers == DOH_SERVERS["cloudflare"]
        s_off = Settings(doh_provider="off")
        assert s_off.effective_doh_servers == []

    def test_settings_from_dict_and_camel_case(self):
        data = {
            "socksHost": "0.0.0.0",
            "socksPort": 9999,
            "dohProvider": "google",
            "customDns": "1.1.1.1",
            "exitCheck": False,
            "systemProxy": True,
            "customEdge": "edge.vpn",
            "upstreamProxyEnabled": True,
            "upstreamProxyType": "http",
            "upstreamProxyHost": "10.0.0.2",
            "upstreamProxyPort": 8080,
            "upstreamProxyUser": "admin",
            "upstreamProxyPass": "secret",
            "defaultCountry": "DE",
            "defaultCity": "FRA",
        }
        s = Settings.from_dict(data)
        assert s.socks_host == "0.0.0.0"
        assert s.socks_port == 9999
        assert s.doh_provider == "google"
        assert s.custom_dns == "1.1.1.1"
        assert s.exit_check is False
        assert s.system_proxy is True
        assert s.custom_edge == "edge.vpn"
        assert s.upstream_proxy_enabled is True
        assert s.upstream_proxy_type == "http"
        assert s.upstream_proxy_host == "10.0.0.2"
        assert s.upstream_proxy_port == 8080
        assert s.upstream_proxy_user == "admin"
        assert s.upstream_proxy_pass == "secret"
        assert s.default_country == "DE"
        assert s.default_city == "FRA"

    def test_get_config_dir_env_override(self, tmp_path):
        custom_dir = tmp_path / "custom_config_dir"
        with patch.dict(os.environ, {"FOXYVPN_CONFIG_DIR": str(custom_dir)}):
            resolved = get_config_dir()
            assert resolved == custom_dir

    def test_get_config_dir_linux_mac(self):
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": "/tmp/xdg_test"}, clear=False):
            if "FOXYVPN_CONFIG_DIR" in os.environ:
                del os.environ["FOXYVPN_CONFIG_DIR"]
            with patch("sys.platform", "linux"):
                resolved = get_config_dir()
                assert resolved == Path("/tmp/xdg_test/foxyvpn")

    def test_get_config_dir_windows(self):
        fake_appdata = "C:\\Users\\Test\\AppData\\Roaming"
        with patch.dict(os.environ, {"APPDATA": fake_appdata}, clear=False):
            if "FOXYVPN_CONFIG_DIR" in os.environ:
                del os.environ["FOXYVPN_CONFIG_DIR"]
            with patch("sys.platform", "win32"):
                resolved = get_config_dir()
                assert resolved == Path(fake_appdata) / "foxyvpn"

    def test_load_and_save_settings(self, tmp_path):
        config_file = tmp_path / "sub" / "settings.json"
        # Non-existent file returns defaults
        s = load_settings(config_file)
        assert s == Settings()

        # Save customized settings
        s.socks_port = 10999
        s.default_country = "US"
        save_settings(s, config_file)

        assert config_file.exists()
        loaded = load_settings(config_file)
        assert loaded.socks_port == 10999
        assert loaded.default_country == "US"

    def test_corrupted_config_returns_defaults(self, tmp_path):
        corrupted_file = tmp_path / "corrupted.json"
        corrupted_file.write_text("{ this is not valid json", encoding="utf-8")
        s = load_settings(corrupted_file)
        assert s == Settings()


class TestTokenStore:
    def test_save_and_load_auth(self, tmp_path):
        token_path = tmp_path / "tokens.json"
        store = TokenStore(token_path)

        assert store.load_auth() is None
        assert store.has_stored_session() is False
        assert store.has_refresh_token() is False

        auth = RuntimeAuth(
            access_token="test_access",
            refresh_token="test_refresh",
            expires_at_epoch_seconds=int(time.time()) + 3600,
            email="user@test.org",
        )
        store.save_auth(auth)

        assert token_path.exists()
        loaded = store.load_auth()
        assert loaded is not None
        assert loaded.access_token == "test_access"
        assert loaded.refresh_token == "test_refresh"
        assert loaded.expires_at_epoch_seconds == auth.expires_at_epoch_seconds
        assert loaded.email == "user@test.org"

        assert store.has_stored_session() is True
        assert store.has_refresh_token() is True

    def test_clear_auth(self, tmp_path):
        token_path = tmp_path / "tokens.json"
        store = TokenStore(token_path)
        store.save_auth(RuntimeAuth("a", "b", 1000))
        assert store.load_auth() is not None

        store.clear()
        assert store.load_auth() is None

    def test_has_valid_access_token_expiration_logic(self, tmp_path):
        token_path = tmp_path / "tokens.json"
        store = TokenStore(token_path)

        # 1. No auth stored
        assert store.has_valid_access_token() is False

        # 2. Empty access token
        store.save_auth(RuntimeAuth("", "ref", int(time.time()) + 3600))
        assert store.has_valid_access_token() is False

        # 3. Token expired in the past
        now = int(time.time())
        store.save_auth(RuntimeAuth("tok", "ref", now - 60))
        assert store.has_valid_access_token() is False

        # 4. Token expiring in 15 seconds (within 30s safety margin -> must be False)
        store.save_auth(RuntimeAuth("tok", "ref", now + 15))
        assert store.has_valid_access_token() is False

        # 5. Token expiring in 29 seconds (within 30s safety margin -> must be False)
        store.save_auth(RuntimeAuth("tok", "ref", now + 29))
        assert store.has_valid_access_token() is False

        # 6. Token expiring in 30 seconds exactly (margin boundary -> False)
        store.save_auth(RuntimeAuth("tok", "ref", now + 30))
        assert store.has_valid_access_token() is False

        # 7. Token expiring in 35 seconds (outside margin -> True)
        store.save_auth(RuntimeAuth("tok", "ref", now + 35))
        assert store.has_valid_access_token() is True

        # 8. Token expiring far in the future
        store.save_auth(RuntimeAuth("tok", "ref", now + 3600))
        assert store.has_valid_access_token() is True

        # 9. Invalid epoch seconds (0 or negative)
        store.save_auth(RuntimeAuth("tok", "ref", 0))
        assert store.has_valid_access_token() is False

    def test_proxy_pass_persistence(self, tmp_path):
        token_path = tmp_path / "tokens.json"
        store = TokenStore(token_path)

        assert store.load_proxy_pass() is None

        pp = ProxyPass(
            token="guardian_token",
            expires_at_epoch_seconds=1750000000,
            quota_max=5000,
            quota_remaining=2500,
        )
        store.save_proxy_pass(pp)

        loaded_pp = store.load_proxy_pass()
        assert loaded_pp is not None
        assert loaded_pp.token == "guardian_token"
        assert loaded_pp.quota_remaining == 2500

        store.clear_proxy_pass()
        assert store.load_proxy_pass() is None


class TestSettingsStore:
    def test_settings_store_lifecycle(self, tmp_path):
        settings_path = tmp_path / "settings.json"
        store = SettingsStore(settings_path)

        # Loading from non-existent file returns default settings
        initial = store.load()
        assert initial.socks_port == 10808
        assert initial.doh_provider == "automatic"

        # get() with default fallback
        assert store.get("socks_port") == 10808
        assert store.get("non_existent_key", "default_val") == "default_val"

        # set() updates value and persists
        store.set("socks_port", 9050)
        assert store.get("socks_port") == 9050

        # Reload through a separate store instance pointing to same file
        store2 = SettingsStore(settings_path)
        assert store2.get("socks_port") == 9050
        loaded = store2.load()
        assert loaded.socks_port == 9050

    def test_settings_store_save_dict_and_object(self, tmp_path):
        settings_path = tmp_path / "settings.json"
        store = SettingsStore(settings_path)

        # Save with dictionary
        store.save({"socks_port": 10809, "exit_check": False})
        loaded = store.load()
        assert loaded.socks_port == 10809
        assert loaded.exit_check is False

        # Save with Settings instance
        s = Settings(socks_port=12000, system_proxy=True)
        store.save(s)
        loaded2 = store.load()
        assert loaded2.socks_port == 12000
        assert loaded2.system_proxy is True

    def test_multi_account_lifecycle(self, tmp_path):
        token_path = tmp_path / "tokens.json"
        store = TokenStore(token_path)

        # 1. Initially empty
        assert store.list_accounts() == []

        # 2. Add first account
        auth1 = RuntimeAuth("tok1", "ref1", 2000000000, email="first@test.org")
        store.save_auth(auth1)
        accounts = store.list_accounts()
        assert len(accounts) == 1
        assert accounts[0]["email"] == "first@test.org"
        assert accounts[0]["is_active"] is True
        assert store.load_auth().email == "first@test.org"

        # 3. Add second account
        auth2 = RuntimeAuth("tok2", "ref2", 2000000000, email="second@test.org")
        store.save_auth(auth2)
        accounts2 = store.list_accounts()
        assert len(accounts2) == 2
        assert store.load_auth().email == "second@test.org"

        # 4. Switch back to first account
        switched = store.switch_account("first@test.org")
        assert switched is True
        assert store.load_auth().email == "first@test.org"
        assert store.load_auth().access_token == "tok1"

        # 5. Switch to non-existent account returns False
        assert store.switch_account("nonexistent@test.org") is False

        # 6. Remove second account
        removed = store.remove_account("second@test.org")
        assert removed is True
        assert len(store.list_accounts()) == 1
        assert store.load_auth().email == "first@test.org"

        # 7. Remove active account (auto-clears session)
        removed_active = store.remove_account("first@test.org")
        assert removed_active is True
        assert len(store.list_accounts()) == 0
        assert store.load_auth() is None
