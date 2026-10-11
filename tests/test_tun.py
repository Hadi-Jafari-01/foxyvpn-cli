from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from foxyvpn.cli import cli
from foxyvpn.core.models import ConnectionState
from foxyvpn.system.tun import TunManager


def test_tun_manager_init():
    mgr = TunManager(tun_name="testtun0", tun_ip="10.8.0.2")
    assert mgr.tun_name == "testtun0"
    assert mgr.tun_ip == "10.8.0.2"
    assert not mgr.is_tun_active()


def test_tun_binary_path_detection():
    mgr = TunManager()
    bin_path = mgr.get_binary_path()
    assert bin_path is not None
    assert bin_path.exists()


def test_tun_is_admin_check():
    # Should return a boolean without raising errors
    res = TunManager.is_admin()
    assert isinstance(res, bool)


def test_tun_gateway_detection():
    mgr = TunManager()
    gw, iface = mgr.get_default_gateway()
    # On connected system should return string or None
    assert gw is None or isinstance(gw, str)


def test_tun_lifecycle_mock():
    mgr = TunManager()
    mock_proc = MagicMock()
    mock_proc.pid = 99999
    mock_proc.poll.return_value = None

    with patch("foxyvpn.system.tun.TunManager.is_admin", return_value=True):
        with patch("subprocess.Popen", return_value=mock_proc):
            with patch.object(mgr, "_configure_network"):
                with patch.object(mgr, "get_default_gateway", return_value=("192.168.1.1", "192.168.1.50")):
                    started = mgr.start_tun(socks_port=10808)
                    assert started is True
                    assert mgr.is_tun_active() is True

                    with patch.object(mgr, "_restore_network"):
                        stopped = mgr.stop_tun()
                        assert stopped is True
                        assert mgr.is_tun_active() is False


def test_connection_state_tun_mode():
    state = ConnectionState(
        status="CONNECTED",
        socks_port=10808,
        tun_mode=True,
    )
    d = state.to_dict()
    assert d["tun_mode"] is True
    restored = ConnectionState.from_dict(d)
    assert restored.tun_mode is True


def test_cli_connect_tun_option():
    runner = CliRunner()
    res = runner.invoke(cli, ["connect", "--help"])
    assert res.exit_code == 0
    assert "--tun" in res.output or "-t" in res.output
