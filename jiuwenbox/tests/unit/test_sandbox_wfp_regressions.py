# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Exercise the real ctypes pointer contract without changing host filters."""
# pylint: disable=protected-access
# Exercise private ABI seams against allocated ctypes data, never host WFP.
import ctypes
import json
from ctypes import wintypes
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from jiuwenbox.supervisor import win_constants as const
from jiuwenbox.supervisor import win_wfp as wfp


def test_wfp_enumeration_declares_the_native_five_argument_contract(monkeypatch):
    dll = Mock()
    monkeypatch.setattr(wfp, '_fwpuclnt', None)
    monkeypatch.setattr(wfp.ctypes, 'WinDLL', Mock(return_value=dll), raising=False)
    assert wfp._get_fwpuclnt().FwpmFilterEnum0.argtypes == [
        wintypes.HANDLE, wintypes.HANDLE, wintypes.UINT,
        ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(wfp.FwpmFilter0))),
        ctypes.POINTER(wintypes.UINT),
    ]


def test_wfp_enumeration_reads_filter_pointers_frees_batches_and_keeps_other_sublayers(monkeypatch):
    own = wfp.FwpmFilter0()
    own.sub_layer_key = wfp._guid_from_str(const.JBX_SUBLAYER_KEY)
    own.filter_key = wfp._guid_from_str(const.JBX_FILTER_BLOCK_KEY_V4)
    other = wfp.FwpmFilter0()
    other.sub_layer_key = wfp._guid_from_str('11111111-1111-1111-1111-111111111111')
    array = (ctypes.POINTER(wfp.FwpmFilter0) * 2)(ctypes.pointer(own), ctypes.pointer(other))
    calls = []

    def enum(_engine, _handle, requested, output, returned):
        assert requested == 1024
        ctypes.cast(returned, ctypes.POINTER(wintypes.UINT))[0] = 0 if calls else 2
        if not calls:
            ctypes.cast(output, ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(wfp.FwpmFilter0))))[0] = array
        calls.append(True)
        return 0

    free = Mock()
    destroy = Mock()
    dll = SimpleNamespace(FwpmFilterCreateEnumHandle0=Mock(return_value=0), FwpmFilterEnum0=enum,
                          FwpmFreeMemory0=free, FwpmFilterDestroyEnumHandle0=destroy)
    monkeypatch.setattr(wfp, '_get_fwpuclnt', lambda: dll)
    assert wfp._enumerate_sublayer_filters(1) == [const.JBX_FILTER_BLOCK_KEY_V4.lower()]
    free.assert_called_once()
    destroy.assert_called_once()
    freed = ctypes.cast(free.call_args.args[0], ctypes.POINTER(ctypes.c_void_p))[0]
    assert freed == ctypes.addressof(array)


@pytest.mark.parametrize('failure', ['create', 'enum'])
def test_wfp_enumeration_failure_cannot_be_used_as_an_empty_success(monkeypatch, failure):
    dll = Mock()
    dll.FwpmFilterCreateEnumHandle0.return_value = 5 if failure == 'create' else 0
    dll.FwpmFilterEnum0.return_value = 5
    monkeypatch.setattr(wfp, '_get_fwpuclnt', lambda: dll)
    with pytest.raises(OSError):
        wfp._enumerate_sublayer_filters(1, strict=True)
    assert dll.FwpmFilterDestroyEnumHandle0.call_count == (failure == 'enum')


def test_legacy_uninstall_keeps_best_effort_enumeration(monkeypatch):
    dll = Mock()
    dll.FwpmFilterCreateEnumHandle0.return_value = 5
    monkeypatch.setattr(wfp, '_get_fwpuclnt', lambda: dll)
    assert wfp._enumerate_sublayer_filters(1) == []


@pytest.mark.parametrize('missing', [None, 'v4', 'v6', 'block'])
def test_port_readiness_requires_both_ip_families_and_default_block(monkeypatch, missing):
    keys = {
        wfp._permit_filter_guid_str(base, port)
        for base in (const.JBX_FILTER_PERMIT_KEY_V4, const.JBX_FILTER_PERMIT_KEY_V6)
        for port in range(61100, 61103)
    } | {const.JBX_FILTER_BLOCK_KEY_V4, const.JBX_FILTER_BLOCK_KEY_V6}
    if missing in {'v4', 'v6'}:
        base = const.JBX_FILTER_PERMIT_KEY_V4 if missing == 'v4' else const.JBX_FILTER_PERMIT_KEY_V6
        keys.remove(wfp._permit_filter_guid_str(base, 61102))
    elif missing == 'block':
        keys.remove(const.JBX_FILTER_BLOCK_KEY_V4)
    query = Mock(return_value=list(keys))
    close = Mock()
    monkeypatch.setattr(wfp, '_require_windows', Mock())
    monkeypatch.setattr(wfp, '_open_engine', lambda: 123)
    monkeypatch.setattr(wfp, '_enumerate_sublayer_filters', query)
    monkeypatch.setattr(wfp, '_get_fwpuclnt', lambda: SimpleNamespace(FwpmEngineClose0=close))
    assert wfp.proxy_permits_installed(61100, 61102) is (missing is None)
    query.assert_called_once_with(123, strict=True)
    close.assert_called_once_with(123)


@pytest.mark.parametrize('failure', ['none', 'delete', 'replace'])
def test_existing_filter_key_is_replaced_with_current_conditions(monkeypatch, failure):
    key = const.JBX_FILTER_BLOCK_KEY_V4
    store = {key.lower(): 1, 'unrelated-live-port': 123}
    calls = []

    def add(_engine, pointer, _sd, _fid):
        flt = ctypes.cast(pointer, ctypes.POINTER(wfp.FwpmFilter0)).contents
        name = wfp._guid_to_str(flt.filter_key).lower()
        calls.append('add')
        if name in store:
            return const.FWP_E_ALREADY_EXISTS
        if failure == 'replace':
            return 5
        store[name] = flt.filter_condition[0].conditionValue.value.uint16
        return 0

    def delete(_engine, pointer):
        calls.append('delete')
        if failure == 'delete':
            return 5
        name = wfp._guid_to_str(ctypes.cast(pointer, ctypes.POINTER(wfp.Guid)).contents).lower()
        del store[name]
        return 0
    dll = SimpleNamespace(FwpmFilterAdd0=add, FwpmFilterDeleteByKey0=delete)
    monkeypatch.setattr(wfp, '_get_fwpuclnt', lambda: dll)

    def install():
        wfp._add_filter(1, key, const.FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                        wfp._guid_from_str(const.JBX_SUBLAYER_KEY), [wfp._build_port_eq_condition(61100)],
                        const.FWP_ACTION_BLOCK, const.FWP_WEIGHT_BLOCK, 'test-current-condition')
    if failure == 'none':
        install()
        assert store[key.lower()] == 61100
    else:
        with pytest.raises(OSError):
            install()
    assert calls == (['add', 'delete'] if failure == 'delete' else ['add', 'delete', 'add'])
    assert store['unrelated-live-port'] == 123


@pytest.mark.parametrize('failure', ['begin', 'commit'])
def test_failed_wfp_transaction_cannot_report_success(monkeypatch, failure):
    dll = Mock()
    dll.FwpmTransactionBegin0.return_value = 5 if failure == 'begin' else 0
    dll.FwpmTransactionCommit0.return_value = 5
    monkeypatch.setattr(wfp, '_require_windows', Mock())
    monkeypatch.setattr(wfp, '_get_fwpuclnt', lambda: dll)
    monkeypatch.setattr(wfp, '_open_engine', lambda: 123)
    monkeypatch.setattr(wfp, '_add_sublayer', Mock())
    for name in ['_build_ale_user_condition', 'build_loopback_v4_condition', '_build_loopback_v6_condition']:
        monkeypatch.setattr(wfp, name, Mock(return_value=(wfp.FwpmFilterCondition0(), None)))
    add = Mock()
    monkeypatch.setattr(wfp, '_add_filter', add)
    with pytest.raises(OSError):
        wfp.install_wfp_filters('S-current', 61100, 61100)
    assert add.call_count == (0 if failure == 'begin' else 6)
    assert dll.FwpmTransactionAbort0.call_count == (failure == 'commit')
    dll.FwpmEngineClose0.assert_called_once_with(123)


def test_wfp_error_keeps_native_code_for_permission_classification():
    error = wfp._wfp_error(5, 'enumeration')
    assert isinstance(error, OSError)
    assert error.winerror == 5


def _live_firewall_snapshot():
    common = {'enabled': True, 'direction': 'Outbound', 'profile': 'Any',
              'local_user': 'D:(A;;CC;;;S-test)', 'local_addresses': ['Any'], 'local_ports': ['Any']}
    return {'profiles_enabled': True, 'rules': [
        dict(common, name='JiuwenBox-Block-Sandbox-Egress', action='Block', protocol='Any',
             remote_addresses=['Any'], remote_ports=['Any']),
        dict(common, name='JiuwenBox-Permit-Loopback', action='Allow', protocol='TCP',
             remote_addresses=['127.0.0.1'], remote_ports=['61100-61102']),
    ]}


@pytest.mark.parametrize('index,field,value', [
    (0, 'enabled', False), (1, 'enabled', False), (0, 'action', 'Allow'),
    (0, 'direction', 'Inbound'), (1, 'profile', 'Private'),
    (0, 'local_user', 'D:(A;;CC;;;S-old)'), (1, 'local_user', 'Any'),
    (0, 'protocol', 'TCP'), (0, 'remote_ports', ['80']),
    (0, 'remote_addresses', ['127.0.0.1']), (0, 'local_addresses', ['127.0.0.1']),
    (1, 'protocol', 'UDP'), (1, 'remote_addresses', ['Any']),
    (1, 'remote_ports', ['61100-61101']), (1, 'remote_ports', ['Any']),
])
def test_live_firewall_rule_must_keep_the_installed_sid_scope_and_complete_proxy_range(index, field, value):
    snapshot = _live_firewall_snapshot()
    snapshot.get('rules')[index][field] = value
    assert not wfp._firewall_snapshot_ready(snapshot, 'S-test', 61100, 61102)


@pytest.mark.parametrize('missing', ['block', 'permit', 'both', 'profiles'])
def test_firewall_receipt_cannot_replace_missing_or_disabled_live_protection(missing):
    snapshot = _live_firewall_snapshot()
    if missing == 'profiles':
        snapshot['profiles_enabled'] = False
    else:
        rules = snapshot.get('rules')
        snapshot['rules'] = rules[1:] if missing == 'block' else rules[:1]
        if missing == 'both':
            snapshot['rules'] = []
    assert not wfp._firewall_snapshot_ready(snapshot, 'S-test', 61100, 61102)


@pytest.mark.parametrize('ports,first,last,expected', [
    (['61100-61102'], 61100, 61102, True), (['61100'], 61100, 61100, True),
    (['61000-62000'], 61100, 61102, True), (['61100-'], 61100, 61100, False),
    (['61102-61100'], 61100, 61102, False), (None, 61100, 61102, False),
])
def test_live_firewall_port_ranges_are_parsed_without_accepting_partial_or_malformed_coverage(
    ports, first, last, expected,
):
    assert wfp._firewall_remote_ports_cover(ports, first, last) is expected


def test_firewall_readback_uses_only_effective_read_queries_and_checks_the_result(monkeypatch):
    monkeypatch.setattr(wfp, '_require_windows', Mock())
    monkeypatch.setattr(wfp, '_get_powershell', lambda: 'powershell-test')
    run = Mock(return_value=SimpleNamespace(stdout=json.dumps(_live_firewall_snapshot())))
    monkeypatch.setattr(wfp.subprocess, 'run', run)
    assert wfp.firewall_permits_installed('S-test', 61100, 61102)
    assert not wfp.firewall_permits_installed('S-old', 61100, 61102)
    query = run.call_args.args[0][-1]
    assert '-PolicyStore ActiveStore' in query
    assert 'Get-NetFirewallSecurityFilter' in query
    assert 'S-test' not in query
    assert 'New-NetFirewallRule' not in query and 'Remove-NetFirewallRule' not in query
    assert run.call_args.kwargs['check'] is True
    assert run.call_args.kwargs['timeout'] == 30


@pytest.mark.parametrize('failure', ['permission', 'timeout', 'malformed', 'missing_rule'])
def test_live_firewall_query_failure_cannot_report_ready(monkeypatch, failure):
    monkeypatch.setattr(wfp, '_require_windows', Mock())
    monkeypatch.setattr(wfp, '_get_powershell', lambda: 'powershell-test')
    if failure == 'malformed':
        run = Mock(return_value=SimpleNamespace(stdout='not-json'))
    elif failure == 'missing_rule':
        run = Mock(side_effect=wfp.subprocess.CalledProcessError(1, 'query'))
    else:
        error = OSError('permission denied') if failure == 'permission' else wfp.subprocess.TimeoutExpired('query', 30)
        run = Mock(side_effect=error)
    monkeypatch.setattr(wfp.subprocess, 'run', run)
    with pytest.raises((OSError, RuntimeError)):
        wfp.firewall_permits_installed('S-test', 61100, 61102)
