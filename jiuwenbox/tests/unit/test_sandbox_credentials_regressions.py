# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Access/logon-policy failures must not be mistaken for a bad password."""
# pylint: disable=protected-access
# Fault injection replaces private Win32 boundaries; no privileged setup runs.
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from jiuwenbox.supervisor import win_constants as const
from jiuwenbox.supervisor import win_setup as setup


def _existing_account(monkeypatch, winerror, *, native_logon=False):
    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, '_is_admin', lambda: True)
    monkeypatch.setattr(setup, '_sandbox_user_exists', lambda: True)
    monkeypatch.setattr(setup, 'get_sandbox_user_password', lambda: 'cached-password')
    if not native_logon:
        monkeypatch.setattr(setup, '_logon_sandbox_user', Mock(return_value=False))
        monkeypatch.setattr(setup, '_logon_sandbox_user_result', Mock(return_value=(False, winerror)), raising=False)
    monkeypatch.setattr(setup.ctypes, 'get_last_error', lambda: winerror, raising=False)
    monkeypatch.setattr(setup, 'reg_get_str', lambda key: '1' if key == const.REG_VALUE_INSTALLED else None)
    monkeypatch.setattr(setup, 'get_preinstalled_read_paths', lambda: set())
    monkeypatch.setattr(setup, '_proxy_ports_ready', Mock(return_value=True), raising=False)


@pytest.mark.parametrize('winerror', [5, 1380, 1385, 1331])
def test_logon_policy_failure_does_not_trigger_setup_or_password_repair(monkeypatch, winerror):
    _existing_account(monkeypatch, winerror)
    install = Mock()
    monkeypatch.setattr(setup, 'install', install)
    with pytest.raises(RuntimeError, match=str(winerror)):
        setup.ensure_windows_setup()
    install.assert_not_called()


@pytest.mark.parametrize('winerror,reset_expected', [
    (5, False), (1385, False), (1326, True), (1330, True), (1907, True),
])
def test_existing_account_password_changes_only_for_credential_errors(monkeypatch, winerror, reset_expected):
    _existing_account(monkeypatch, winerror)
    monkeypatch.setattr(setup, '_generate_password', lambda: 'new-password')
    monkeypatch.setattr(setup, '_create_sandbox_user', Mock(return_value=False))
    reset = Mock()
    monkeypatch.setattr(setup, '_set_user_password', reset)
    monkeypatch.setattr(setup, '_install_rollback', Mock())
    # Stop before group/ACL/WFP changes, even on the unpatched implementation.
    monkeypatch.setattr(setup, '_add_user_to_group', Mock(side_effect=RuntimeError('stop after credential selection')))
    with pytest.raises(RuntimeError):
        setup.install(force=True)
    assert reset.called is reset_expected
    if reset_expected:
        reset.assert_called_once_with(const.SANDBOX_USER_NAME, 'new-password')


def _logon_sequence(monkeypatch, network_error, interactive_error):
    state = {'error': 0, 'calls': []}

    def logon(_user, _domain, _password, kind, _provider, _token):
        state['calls'].append(kind)
        state['error'] = network_error if kind == 3 else interactive_error
        return state['error'] == 0

    close = Mock()
    dlls = {'advapi32': SimpleNamespace(LogonUserW=logon), 'kernel32': SimpleNamespace(CloseHandle=close)}

    def load_dll(name, **_kwargs):
        dll = dlls.get(name)
        assert dll is not None, f'Unexpected DLL requested: {name}'
        return dll

    monkeypatch.setattr(setup.ctypes, 'WinDLL', load_dll, raising=False)
    monkeypatch.setattr(setup.ctypes, 'get_last_error', lambda: state['error'], raising=False)
    monkeypatch.setattr(setup.ctypes, 'set_last_error', lambda value: state.update(error=value), raising=False)
    return state, close


_MIXED_ERRORS = [(first, second, first) for first in [1326, 1330, 1907] for second in [5, 1385, 1331]]


@pytest.mark.parametrize('first,second,expected', _MIXED_ERRORS + [
    (5, 1326, 1326), (1385, 5, 5), (1326, 0, 0), (0, 1385, 0),
])
def test_boolean_logon_contract_preserves_credential_error_across_fallback(monkeypatch, first, second, expected):
    state, close = _logon_sequence(monkeypatch, first, second)
    assert setup._logon_sandbox_user('not-a-real-password') is (expected == 0)
    if expected:
        assert state['error'] == expected
    assert state['calls'] == ([3] if first == 0 else [3, 2])
    assert close.call_count == (expected == 0)


@pytest.mark.parametrize('credential_error', [1326, 1330, 1907])
@pytest.mark.parametrize('policy_error', [5, 1385])
def test_install_preserves_network_credential_failure_when_interactive_logon_is_denied(
    monkeypatch, credential_error, policy_error,
):
    _existing_account(monkeypatch, policy_error, native_logon=True)
    state, _ = _logon_sequence(monkeypatch, credential_error, policy_error)
    monkeypatch.setattr(setup, '_generate_password', lambda: 'new-password')
    monkeypatch.setattr(setup, '_create_sandbox_user', Mock(return_value=False))
    reset = Mock()
    monkeypatch.setattr(setup, '_set_user_password', reset)
    monkeypatch.setattr(setup, '_install_rollback', Mock())
    monkeypatch.setattr(setup, '_add_user_to_group', Mock(side_effect=RuntimeError('stop after credential selection')))
    with pytest.raises(RuntimeError):
        setup.install(force=True)
    assert state['calls'] == [3, 2]
    reset.assert_called_once_with(const.SANDBOX_USER_NAME, 'new-password')


@pytest.mark.parametrize('winerror', [None, 1326, 1330, 1907])
def test_password_reset_log_distinguishes_missing_saved_password_from_logon_error(monkeypatch, winerror, caplog):
    _existing_account(monkeypatch, winerror or 1326)
    if winerror is None:
        monkeypatch.setattr(setup, 'get_sandbox_user_password', lambda: '')
    monkeypatch.setattr(setup, '_generate_password', lambda: 'new-password')
    monkeypatch.setattr(setup, '_create_sandbox_user', Mock(return_value=False))
    monkeypatch.setattr(setup, '_set_user_password', Mock())
    monkeypatch.setattr(setup, '_install_rollback', Mock())
    monkeypatch.setattr(setup, '_add_user_to_group', Mock(side_effect=RuntimeError('stop')))
    with caplog.at_level('INFO'), pytest.raises(RuntimeError):
        setup.install(force=True)
    assert 'new-password' not in caplog.text
    if winerror is None:
        assert 'DPAPI' in caplog.text
    else:
        assert f'WinError {winerror}' in caplog.text
        assert 'DPAPI 无旧密码' not in caplog.text
