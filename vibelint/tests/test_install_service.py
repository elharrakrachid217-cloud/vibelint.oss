"""
tests/test_install_service.py
=============================
Tests for install_service.py and uninstall_service.py.

All OS detection and subprocess calls are mocked — no real services
are registered or removed during testing.
"""

import subprocess as sp
from unittest.mock import MagicMock, patch

import pytest

import install_service
import uninstall_service


# ─── Helpers ─────────────────────────────────────────────────────────

def _proc(returncode=0, stdout="", stderr=""):
    """Build a mock subprocess.CompletedProcess."""
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


# ═════════════════════════════════════════════════════════════════════
# OS routing — install
# ═════════════════════════════════════════════════════════════════════

class TestInstallOSRouting:

    @patch("install_service._install_windows")
    @patch("install_service.platform.system", return_value="Windows")
    def test_routes_to_windows(self, _os, mock_fn):
        with pytest.raises(SystemExit) as exc_info:
            install_service.main()
        assert exc_info.value.code == 0
        mock_fn.assert_called_once()

    @patch("install_service._install_mac")
    @patch("install_service.platform.system", return_value="Darwin")
    def test_routes_to_mac(self, _os, mock_fn):
        with pytest.raises(SystemExit) as exc_info:
            install_service.main()
        assert exc_info.value.code == 0
        mock_fn.assert_called_once()

    @patch("install_service._install_linux")
    @patch("install_service.platform.system", return_value="Linux")
    def test_routes_to_linux(self, _os, mock_fn):
        with pytest.raises(SystemExit) as exc_info:
            install_service.main()
        assert exc_info.value.code == 0
        mock_fn.assert_called_once()

    @patch("install_service.platform.system", return_value="FreeBSD")
    def test_unsupported_os_exits(self, _os):
        with pytest.raises(SystemExit):
            install_service.main()


# ═════════════════════════════════════════════════════════════════════
# OS routing — uninstall
# ═════════════════════════════════════════════════════════════════════

class TestUninstallOSRouting:

    @patch("uninstall_service._uninstall_windows")
    @patch("uninstall_service.platform.system", return_value="Windows")
    def test_routes_to_windows(self, _os, mock_fn):
        uninstall_service.main()
        mock_fn.assert_called_once()

    @patch("uninstall_service._uninstall_mac")
    @patch("uninstall_service.platform.system", return_value="Darwin")
    def test_routes_to_mac(self, _os, mock_fn):
        uninstall_service.main()
        mock_fn.assert_called_once()

    @patch("uninstall_service._uninstall_linux")
    @patch("uninstall_service.platform.system", return_value="Linux")
    def test_routes_to_linux(self, _os, mock_fn):
        uninstall_service.main()
        mock_fn.assert_called_once()

    @patch("uninstall_service.platform.system", return_value="FreeBSD")
    def test_unsupported_os_exits(self, _os):
        with pytest.raises(SystemExit):
            uninstall_service.main()


# ═════════════════════════════════════════════════════════════════════
# Windows — install
# ═════════════════════════════════════════════════════════════════════

class TestWindowsInstall:

    @patch("install_service._is_registered_windows", return_value=True)
    def test_already_registered(self, _reg, capsys):
        install_service._install_windows()
        assert "already registered" in capsys.readouterr().out

    @patch("install_service.RUNNER_BAT")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_windows", return_value=False)
    @patch("install_service.subprocess.run")
    def test_fresh_install_succeeds(self, mock_run, _reg, _log, _bat, capsys):
        mock_run.return_value = _proc(0)
        install_service._install_windows()
        out = capsys.readouterr().out
        assert "registered" in out.lower()
        assert mock_run.call_count == 2

    @patch("install_service.RUNNER_BAT")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_windows", return_value=False)
    @patch("install_service.subprocess.run")
    def test_permission_denied(self, mock_run, _reg, _log, _bat, capsys):
        mock_run.return_value = _proc(1, stderr="Access is denied")
        install_service._install_windows()
        out = capsys.readouterr().out
        assert "Permission denied" in out or "Administrator" in out

    @patch("install_service.RUNNER_BAT")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_windows", return_value=False)
    @patch("install_service.subprocess.run", side_effect=FileNotFoundError)
    def test_schtasks_not_found(self, _run, _reg, _log, _bat, capsys):
        install_service._install_windows()
        assert "not found" in capsys.readouterr().out.lower()

    @patch("install_service.RUNNER_BAT")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_windows", return_value=False)
    @patch("install_service.subprocess.run")
    def test_create_ok_but_run_fails(self, mock_run, _reg, _log, _bat, capsys):
        mock_run.side_effect = [
            _proc(0),                        # schtasks /Create OK
            _proc(1, stderr="not running"),   # schtasks /Run fails
        ]
        install_service._install_windows()
        out = capsys.readouterr().out
        assert "registered" in out.lower()
        assert "could not start" in out.lower() or "⚠" in out


# ═════════════════════════════════════════════════════════════════════
# macOS — install
# ═════════════════════════════════════════════════════════════════════

class TestMacInstall:

    @patch("install_service._is_registered_mac", return_value=True)
    def test_already_registered(self, _reg, capsys):
        install_service._install_mac()
        assert "already exists" in capsys.readouterr().out.lower()

    @patch("install_service.PLIST_PATH")
    @patch("install_service._make_executable")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_mac", return_value=False)
    @patch("install_service.subprocess.run")
    def test_fresh_install_succeeds(self, mock_run, _reg, _log, _exec, mock_plist, capsys):
        mock_plist.parent = MagicMock()
        mock_run.return_value = _proc(0)
        install_service._install_mac()
        mock_plist.write_text.assert_called_once()
        out = capsys.readouterr().out
        assert "running" in out.lower() or "loaded" in out.lower()

    @patch("install_service.PLIST_PATH")
    @patch("install_service._make_executable")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_mac", return_value=False)
    def test_permission_denied_writing_plist(self, _reg, _log, _exec, mock_plist, capsys):
        mock_plist.parent = MagicMock()
        mock_plist.write_text.side_effect = PermissionError
        install_service._install_mac()
        assert "Permission denied" in capsys.readouterr().out

    @patch("install_service.PLIST_PATH")
    @patch("install_service._make_executable")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_mac", return_value=False)
    @patch("install_service.subprocess.run", side_effect=FileNotFoundError)
    def test_launchctl_not_found(self, _run, _reg, _log, _exec, mock_plist, capsys):
        mock_plist.parent = MagicMock()
        install_service._install_mac()
        assert "not found" in capsys.readouterr().out.lower()


# ═════════════════════════════════════════════════════════════════════
# Linux — install
# ═════════════════════════════════════════════════════════════════════

class TestLinuxInstall:

    @patch("install_service._is_registered_linux", return_value=True)
    def test_already_registered(self, _reg, capsys):
        install_service._install_linux()
        assert "already exists" in capsys.readouterr().out.lower()

    @patch("install_service.SYSTEMD_PATH")
    @patch("install_service.SYSTEMD_DIR")
    @patch("install_service._make_executable")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_linux", return_value=False)
    @patch("install_service.subprocess.run")
    def test_fresh_install_succeeds(self, mock_run, _reg, _log, _exec, _dir, mock_path, capsys):
        mock_run.return_value = _proc(0)
        install_service._install_linux()
        mock_path.write_text.assert_called_once()
        out = capsys.readouterr().out
        assert "running" in out.lower() or "started" in out.lower()

    @patch("install_service.SYSTEMD_PATH")
    @patch("install_service.SYSTEMD_DIR")
    @patch("install_service._make_executable")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_linux", return_value=False)
    def test_permission_denied_writing_unit(self, _reg, _log, _exec, _dir, mock_path, capsys):
        mock_path.write_text.side_effect = PermissionError
        install_service._install_linux()
        assert "Permission denied" in capsys.readouterr().out

    @patch("install_service.SYSTEMD_PATH")
    @patch("install_service.SYSTEMD_DIR")
    @patch("install_service._make_executable")
    @patch("install_service._ensure_log_dir")
    @patch("install_service._is_registered_linux", return_value=False)
    @patch("install_service.subprocess.run", side_effect=FileNotFoundError)
    def test_systemctl_not_found(self, _run, _reg, _log, _exec, _dir, mock_path, capsys):
        install_service._install_linux()
        assert "not found" in capsys.readouterr().out.lower()


# ═════════════════════════════════════════════════════════════════════
# Windows — uninstall
# ═════════════════════════════════════════════════════════════════════

class TestWindowsUninstall:

    @patch("uninstall_service.subprocess.run")
    def test_not_registered(self, mock_run, capsys):
        mock_run.return_value = _proc(1)
        uninstall_service._uninstall_windows()
        assert "not registered" in capsys.readouterr().out.lower()

    @patch("uninstall_service.RUNNER_BAT")
    @patch("uninstall_service.subprocess.run")
    def test_uninstalls_successfully(self, mock_run, mock_bat, capsys):
        mock_run.return_value = _proc(0)
        mock_bat.exists.return_value = True
        uninstall_service._uninstall_windows()
        out = capsys.readouterr().out
        assert "removed" in out.lower()
        mock_bat.unlink.assert_called_once()

    @patch("uninstall_service.subprocess.run", side_effect=FileNotFoundError)
    def test_schtasks_not_found(self, _run, capsys):
        uninstall_service._uninstall_windows()
        assert "not found" in capsys.readouterr().out.lower()

    @patch("uninstall_service.RUNNER_BAT")
    @patch("uninstall_service.subprocess.run")
    def test_permission_denied_on_delete(self, mock_run, mock_bat, capsys):
        mock_run.side_effect = [
            _proc(0),                                   # Query OK
            _proc(0),                                   # End OK
            _proc(1, stderr="Access is denied"),         # Delete fails
        ]
        uninstall_service._uninstall_windows()
        out = capsys.readouterr().out
        assert "Permission denied" in out or "Administrator" in out


# ═════════════════════════════════════════════════════════════════════
# macOS — uninstall
# ═════════════════════════════════════════════════════════════════════

class TestMacUninstall:

    @patch("uninstall_service.PLIST_PATH")
    def test_not_registered(self, mock_plist, capsys):
        mock_plist.exists.return_value = False
        uninstall_service._uninstall_mac()
        assert "not installed" in capsys.readouterr().out.lower()

    @patch("uninstall_service.PLIST_PATH")
    @patch("uninstall_service.subprocess.run")
    def test_uninstalls_successfully(self, mock_run, mock_plist, capsys):
        mock_plist.exists.return_value = True
        mock_run.return_value = _proc(0)
        uninstall_service._uninstall_mac()
        mock_plist.unlink.assert_called_once()
        assert "removed" in capsys.readouterr().out.lower()

    @patch("uninstall_service.PLIST_PATH")
    @patch("uninstall_service.subprocess.run")
    def test_permission_denied_removing_plist(self, mock_run, mock_plist, capsys):
        mock_plist.exists.return_value = True
        mock_run.return_value = _proc(0)
        mock_plist.unlink.side_effect = PermissionError
        uninstall_service._uninstall_mac()
        assert "Permission denied" in capsys.readouterr().out


# ═════════════════════════════════════════════════════════════════════
# Linux — uninstall
# ═════════════════════════════════════════════════════════════════════

class TestLinuxUninstall:

    @patch("uninstall_service.SYSTEMD_PATH")
    def test_not_registered(self, mock_path, capsys):
        mock_path.exists.return_value = False
        uninstall_service._uninstall_linux()
        assert "not installed" in capsys.readouterr().out.lower()

    @patch("uninstall_service.SYSTEMD_PATH")
    @patch("uninstall_service.subprocess.run")
    def test_uninstalls_successfully(self, mock_run, mock_path, capsys):
        mock_path.exists.return_value = True
        mock_run.return_value = _proc(0)
        uninstall_service._uninstall_linux()
        mock_path.unlink.assert_called_once()
        assert "removed" in capsys.readouterr().out.lower()

    @patch("uninstall_service.SYSTEMD_PATH")
    @patch("uninstall_service.subprocess.run", side_effect=FileNotFoundError)
    def test_systemctl_not_found(self, _run, mock_path, capsys):
        mock_path.exists.return_value = True
        uninstall_service._uninstall_linux()
        assert "not found" in capsys.readouterr().out.lower()
