# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Changing a configured proxy range must preserve existing instances' permits."""
# pylint: disable=protected-access
# Private setup seams isolate registry and firewall effects from the host.
import json
from unittest.mock import MagicMock, Mock

import pytest

from jiuwenbox.supervisor import win_constants as const
from jiuwenbox.supervisor import win_setup as setup
from jiuwenbox.supervisor import win_wfp as wfp


@pytest.fixture(autouse=True)
def _mock_firewall_migration(monkeypatch):
    monkeypatch.setattr(wfp, 'remove_legacy_dns_firewall_rules', Mock())
    monkeypatch.setattr(wfp, 'verify_legacy_dns_permits_absent', Mock())


def _prepared(monkeypatch):
    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, 'reg_get_str', lambda key: '1' if key == const.REG_VALUE_INSTALLED else None)
    monkeypatch.setattr(setup, '_verify_or_reset_sandbox_user_password', Mock())
    monkeypatch.setattr(setup, 'get_preinstalled_read_paths', lambda: set())
    monkeypatch.setattr(setup, '_is_admin', lambda: False)


def test_existing_install_with_missing_custom_ports_requests_only_incremental_authorization(monkeypatch):
    _prepared(monkeypatch)
    monkeypatch.setattr(setup, '_proxy_ports_ready', Mock(side_effect=[False, True]), raising=False)
    install = Mock()
    monkeypatch.setattr(setup, 'install', install)
    setup.ensure_windows_setup(proxy_port_start=61100, proxy_port_end=61102)
    install.assert_called_once()
    assert install.call_args.kwargs['authorize_only'] is True
    assert install.call_args.kwargs['proxy_port_start'] == 61100
    assert install.call_args.kwargs['proxy_port_end'] == 61102
    assert 'recreate_user' not in install.call_args.kwargs


def test_missing_ports_never_elevate_inside_service_validation(monkeypatch):
    _prepared(monkeypatch)
    monkeypatch.setattr(setup, '_proxy_ports_ready', Mock(return_value=False), raising=False)
    install = Mock()
    monkeypatch.setattr(setup, 'install', install)
    with pytest.raises(RuntimeError):
        setup.ensure_windows_setup(proxy_port_start=61100, proxy_port_end=61102, allow_elevation=False)
    install.assert_not_called()


def test_incomplete_port_repair_cannot_report_setup_success(monkeypatch):
    _prepared(monkeypatch)
    monkeypatch.setattr(setup, '_proxy_ports_ready', Mock(return_value=False), raising=False)
    monkeypatch.setattr(setup, 'install', Mock())
    with pytest.raises(RuntimeError, match='61100'):
        setup.ensure_windows_setup(proxy_port_start=61100, proxy_port_end=61102)


def test_ready_proxy_ports_do_not_reinstall_or_recreate_accounts(monkeypatch):
    _prepared(monkeypatch)
    monkeypatch.setattr(setup, '_proxy_ports_ready', Mock(return_value=True), raising=False)
    install = Mock()
    monkeypatch.setattr(setup, 'install', install)
    setup.ensure_windows_setup(allow_elevation=False)
    install.assert_not_called()


def test_port_repair_never_uninstalls_another_instances_filters(monkeypatch):
    monkeypatch.setattr(setup, 'get_sandbox_user_sid', lambda: 'S-test')
    monkeypatch.setattr(setup, '_reg_set_str', Mock())
    monkeypatch.setattr(setup, 'reg_get_str', lambda _key: None)
    install = Mock()
    uninstall = Mock(side_effect=AssertionError('must not remove live permits'))
    monkeypatch.setattr(wfp, 'install_wfp_filters', install)
    monkeypatch.setattr(wfp, 'uninstall_wfp_filters', uninstall)
    setup._repair_proxy_permits(61100, 61102)
    install.assert_called_once_with('S-test', 61100, 61102, preserve_ranges=None)
    uninstall.assert_not_called()


@pytest.mark.parametrize('install_ok,live_ok', [(False, False), (True, False), (True, True)])
def test_port_repair_records_fallback_only_after_live_verification(monkeypatch, install_ok, live_ok):
    values = _registry(monkeypatch, {'sid': 'S-test', 'firewall_ranges': [[61000, 61002]]})
    previous = values[setup._PROXY_PERMIT_RECORD]
    wfp_error = OSError('WFP unavailable')
    monkeypatch.setattr(wfp, 'install_wfp_filters', Mock(side_effect=wfp_error))
    monkeypatch.setattr(wfp, 'proxy_permits_installed',
                        Mock(side_effect=AssertionError('fallback must read legacy keys directly')))
    fallback = Mock(return_value=install_ok)
    live = Mock(return_value=live_ok)
    monkeypatch.setattr(wfp, 'install_firewall_rule_fallback', fallback)
    monkeypatch.setattr(wfp, 'firewall_permits_installed', live)
    if live_ok:
        setup._repair_proxy_permits(61100, 61102)
        record = json.loads(values[setup._PROXY_PERMIT_RECORD])
        assert record['sid'] == 'S-test'
        assert record['firewall_ranges'] == [[61000, 61002], [61100, 61102]]
        assert record['firewall_legacy_dns_verified'] is True
    else:
        with pytest.raises(RuntimeError, match='网络隔离不可用') as caught:
            setup._repair_proxy_permits(61100, 61102)
        assert caught.value.__cause__ is wfp_error
        assert values[setup._PROXY_PERMIT_RECORD] == previous
    wfp.verify_legacy_dns_permits_absent.assert_called_once_with()
    fallback.assert_called_once_with(const.SANDBOX_USER_NAME, 61100, 61102, sandbox_user_sid='S-test')
    if install_ok:
        live.assert_called_once_with('S-test', 61100, 61102)
    else:
        live.assert_not_called()


@pytest.mark.parametrize('failure', [wfp.LegacyDnsPermitError('legacy present'), OSError('BFE unavailable')])
def test_port_repair_rejects_present_or_unreadable_legacy_wfp_permits(monkeypatch, failure):
    values = _registry(monkeypatch)
    monkeypatch.setattr(wfp, 'install_wfp_filters', Mock(side_effect=OSError('WFP install failed')))
    wfp.verify_legacy_dns_permits_absent.side_effect = failure
    fallback = Mock()
    monkeypatch.setattr(wfp, 'install_firewall_rule_fallback', fallback)
    with pytest.raises(type(failure)) as caught:
        setup._repair_proxy_permits(61100, 61102)
    assert caught.value is failure
    fallback.assert_not_called()
    assert setup._PROXY_PERMIT_RECORD not in values


@pytest.mark.parametrize('record,expected', [
    ({'sid': 'S-test', 'firewall_ranges': [[61000, 62000]]}, True),
    ({'sid': 'S-other', 'firewall_ranges': [[61000, 62000]]}, False),
    ({'sid': 'S-test', 'firewall_ranges': [[61000, 61100]]}, False),
    ({'sid': 'S-test', 'firewall_ranges': 'bad'}, False),
])
def test_firewall_port_evidence_is_bound_to_sid_and_complete_range(monkeypatch, record, expected):
    monkeypatch.setattr(setup, 'get_sandbox_user_sid', lambda: 'S-test')
    monkeypatch.setattr(setup, '_lookup_user_sid', lambda _user: 'S-test')
    monkeypatch.setattr(setup, 'reg_get_str', lambda _key: json.dumps({'network_policy_version': 2, **record}))
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(side_effect=OSError()), raising=False)
    live = Mock(return_value=True)
    monkeypatch.setattr(wfp, 'firewall_permits_installed', live, raising=False)
    assert setup._proxy_ports_ready(61100, 61102) is expected
    assert live.called is expected


def test_legacy_install_without_sid_evidence_requires_preparation(monkeypatch):
    monkeypatch.setattr(setup, 'get_sandbox_user_sid', lambda: 'S-test')
    monkeypatch.setattr(setup, 'reg_get_str', lambda key: '1' if key == const.REG_VALUE_INSTALLED else None)
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(side_effect=OSError()), raising=False)
    assert not setup._proxy_ports_ready(const.DEFAULT_PROXY_PORT_RANGE_START, const.DEFAULT_PROXY_PORT_RANGE_END)
    assert not setup._proxy_ports_ready(61100, 61102)


@pytest.mark.parametrize('operation', ['rollback', 'uninstall'])
def test_filter_removal_invalidates_firewall_range_evidence(monkeypatch, operation):
    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, '_is_admin', lambda: True)
    monkeypatch.setattr(wfp, 'uninstall_wfp_filters', Mock())
    monkeypatch.setattr(wfp, 'uninstall_firewall_rule_fallback', Mock())
    monkeypatch.setattr(setup, '_remove_sandbox_user_and_profile', Mock())
    write = Mock()
    monkeypatch.setattr(setup, '_reg_set_str', write)
    if operation == 'rollback':
        setup._install_rollback({'wfp'})
    else:
        setup.uninstall()
    write.assert_any_call(setup._PROXY_PERMIT_RECORD, '')


@pytest.fixture(autouse=True)
def _no_native_account_lookup(monkeypatch):
    monkeypatch.setattr(setup, '_lookup_user_sid', lambda _user: 'S-test')


def _registry(monkeypatch, record=None, *, version=2):
    values = {const.REG_VALUE_INSTALLED: '1'}
    if record is not None:
        values[setup._PROXY_PERMIT_RECORD] = json.dumps({'network_policy_version': version, **record})
    monkeypatch.setattr(setup, 'reg_get_str', values.get)
    monkeypatch.setattr(setup, '_reg_set_str', values.__setitem__)
    monkeypatch.setattr(setup, 'get_sandbox_user_sid', lambda: 'S-test')
    return values


def test_nonadmin_custom_range_stays_ready_after_successful_privileged_repair(monkeypatch):
    _prepared(monkeypatch)
    values = _registry(monkeypatch)
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(side_effect=PermissionError(13, 'enumeration denied')))
    monkeypatch.setattr(wfp, 'install_wfp_filters', Mock())
    # Simulate the elevated child's SDK operation, then recheck in the parent.
    install = Mock(side_effect=lambda **kw: setup._repair_proxy_permits(kw['proxy_port_start'], kw['proxy_port_end']))
    monkeypatch.setattr(setup, 'install', install)
    setup.ensure_windows_setup(proxy_port_start=61100, proxy_port_end=61102)
    record = json.loads(values[setup._PROXY_PERMIT_RECORD])
    assert record['sid'] == 'S-test'
    assert record['wfp_ranges'] == [[61100, 61102]]
    assert record['wfp_content_verified'] is True
    setup.ensure_windows_setup(proxy_port_start=61100, proxy_port_end=61102, allow_elevation=False)
    install.assert_called_once()


def test_old_receipt_cannot_certify_dns_rule_migration(monkeypatch):
    _registry(monkeypatch, {'sid': 'S-test', 'wfp_ranges': [[61100, 61102]]}, version=1)
    live = Mock(return_value=True)
    monkeypatch.setattr(wfp, 'proxy_permits_installed', live)
    assert not setup._proxy_ports_ready(61100, 61102)
    live.assert_not_called()


@pytest.mark.parametrize('query', [True, False, PermissionError(13, 'denied'), OSError('BFE unavailable')])
@pytest.mark.parametrize('sid', ['S-test', 'S-old'])
@pytest.mark.parametrize('verified', [False, True])
def test_wfp_evidence_requires_sid_range_and_no_authoritative_negative(monkeypatch, query, sid, verified):
    _registry(monkeypatch, {'sid': sid, 'wfp_ranges': [[61100, 61102]], 'wfp_content_verified': verified})
    mock = Mock(side_effect=query) if isinstance(query, Exception) else Mock(return_value=query)
    monkeypatch.setattr(wfp, 'proxy_permits_installed', mock)
    assert setup._proxy_ports_ready(61100, 61102) is (
        sid == 'S-test' and (query is True or (verified and isinstance(query, PermissionError))))
    assert not setup._proxy_ports_ready(61100, 61103)


def test_filter_keys_without_current_sid_evidence_cannot_report_ready(monkeypatch):
    _registry(monkeypatch)
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(return_value=True))
    assert not setup._proxy_ports_ready(61100, 61102)


def test_manual_account_recreation_invalidates_registry_sid_evidence(monkeypatch):
    _registry(monkeypatch, {'sid': 'S-test', 'wfp_ranges': [[61100, 61102]]})
    monkeypatch.setattr(setup, '_lookup_user_sid', lambda _user: 'S-recreated')
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(return_value=True))
    assert not setup._proxy_ports_ready(61100, 61102)


def test_wfp_success_preserves_wfp_ranges_but_invalidates_firewall_evidence(monkeypatch):
    values = _registry(monkeypatch, {'sid': 'S-test', 'firewall_ranges': [[61000, 61001]],
                                    'wfp_ranges': [[61100, 61102]]})
    monkeypatch.setattr(wfp, 'install_wfp_filters', Mock())
    setup._repair_proxy_permits(61200, 61201)
    record = json.loads(values[setup._PROXY_PERMIT_RECORD])
    assert record['firewall_ranges'] == []
    assert record['wfp_ranges'] == [[61100, 61102], [61200, 61201]]
    monkeypatch.setattr(setup, 'get_sandbox_user_sid', lambda: 'S-new')
    setup._repair_proxy_permits(61300, 61301)
    record = json.loads(values[setup._PROXY_PERMIT_RECORD])
    assert record['sid'] == 'S-new'
    assert record['wfp_ranges'] == [[61300, 61301]]
    assert record['firewall_ranges'] == []


def test_failed_wfp_integrity_check_invalidates_cached_proof_without_claiming_fallback(monkeypatch):
    values = _registry(monkeypatch, {'sid': 'S-test', 'wfp_ranges': [[61100, 61102]],
                                   'wfp_content_verified': True})
    install = Mock(side_effect=wfp.NetworkRuleVerificationError('wrong SID'))
    fallback = Mock()
    monkeypatch.setattr(wfp, 'install_wfp_filters', install)
    monkeypatch.setattr(wfp, 'install_firewall_rule_fallback', fallback)
    with pytest.raises(wfp.NetworkRuleVerificationError, match='wrong SID'):
        setup._repair_proxy_permits(61200, 61201)
    install.assert_called_once_with('S-test', 61200, 61201, preserve_ranges=[[61100, 61102]])
    fallback.assert_not_called()
    record = json.loads(values[setup._PROXY_PERMIT_RECORD])
    assert record['wfp_ranges'] == [[61100, 61102]]
    assert 'wfp_content_verified' not in record


@pytest.mark.parametrize('exists', [False, True])
def test_recreation_invalidates_receipt_before_any_account_or_filter_changes(monkeypatch, exists):
    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, '_is_admin', lambda: True)
    monkeypatch.setattr(setup, '_sandbox_user_exists', lambda: exists)
    values = _registry(monkeypatch, {'sid': 'S-old', 'wfp_ranges': [[61100, 61102]]})

    def stop(*_args, **_kwargs):
        assert values[setup._PROXY_PERMIT_RECORD] == ''
        raise RuntimeError('stop before native changes')
    monkeypatch.setattr(wfp, 'uninstall_wfp_filters', stop)
    monkeypatch.setattr(setup, '_remove_sandbox_user_and_profile', stop)
    monkeypatch.setattr(setup, '_generate_password', stop)
    monkeypatch.setattr(setup, '_install_rollback', Mock())
    with pytest.raises(RuntimeError, match='stop before native changes'):
        setup.install(force=True, recreate_user=True)


def test_failed_receipt_invalidation_stops_recreation_before_destructive_steps(monkeypatch):
    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, '_is_admin', lambda: True)
    monkeypatch.setattr(setup, '_reg_set_str', Mock(side_effect=OSError('cannot invalidate')))
    monkeypatch.setattr(setup, '_install_rollback', Mock())
    exists = Mock(side_effect=AssertionError('must not proceed'))
    monkeypatch.setattr(setup, '_sandbox_user_exists', exists)
    with pytest.raises(OSError, match='cannot invalidate'):
        setup.install(force=True, recreate_user=True)
    exists.assert_not_called()


@pytest.mark.parametrize('backend', ['wfp', 'firewall'])
def test_full_install_records_network_success_before_later_setup_steps(monkeypatch, backend):
    from jiuwenbox.supervisor import win_acl

    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, '_is_admin', lambda: True)
    values = _registry(monkeypatch)
    monkeypatch.setattr(setup, '_generate_password', lambda: 'not-a-real-password')
    monkeypatch.setattr(setup, '_create_sandbox_user', Mock(return_value=True))
    for name in ['_add_user_to_group', '_reg_set_dword_under', '_save_sandbox_user_password',
                 '_grant_interactive_logon_right', '_install_rollback']:
        monkeypatch.setattr(setup, name, Mock())
    monkeypatch.setattr(win_acl, 'get_synthetic_write_sid', lambda: 'S-synthetic')
    wfp_failure = OSError('WFP install failed') if backend == 'firewall' else None
    monkeypatch.setattr(wfp, 'install_wfp_filters', Mock(side_effect=wfp_failure))
    monkeypatch.setattr(wfp, 'install_firewall_rule_fallback', Mock(return_value=True))
    live = Mock(return_value=True)
    monkeypatch.setattr(wfp, 'firewall_permits_installed', live)

    def stop():
        assert json.loads(values[setup._PROXY_PERMIT_RECORD])[f'{backend}_ranges'] == [[61100, 61102]]
        raise RuntimeError('stop after receipt')

    # Stop before any filesystem ACL operation, after completing network setup.
    paths = MagicMock()
    paths.__iter__.side_effect = stop
    with pytest.raises(RuntimeError, match='stop after receipt'):
        setup.install(force=True, proxy_port_start=61100, proxy_port_end=61102,
                      preinstall_paths=paths)
    paths.__iter__.assert_called_once()
    assert live.called is (backend == 'firewall')


@pytest.mark.parametrize('query', [False, PermissionError(13, 'denied'), OSError('BFE unavailable')])
@pytest.mark.parametrize('live', [False, True, OSError('firewall unavailable')])
def test_firewall_receipt_requires_live_rules_and_cannot_skip_the_wfp_query(monkeypatch, query, live):
    _registry(monkeypatch, {'sid': 'S-test', 'firewall_ranges': [[61100, 61102]]})
    wfp_query = Mock(side_effect=query) if isinstance(query, Exception) else Mock(return_value=query)
    firewall = Mock(side_effect=live) if isinstance(live, Exception) else Mock(return_value=live)
    monkeypatch.setattr(wfp, 'proxy_permits_installed', wfp_query)
    monkeypatch.setattr(wfp, 'firewall_permits_installed', firewall, raising=False)
    assert setup._proxy_ports_ready(61100, 61102) is (live is True)
    wfp_query.assert_called_once_with(61100, 61102, sandbox_user_sid='S-test')
    firewall.assert_called_once_with('S-test', 61100, 61102)


@pytest.mark.parametrize('verified,failure,ready', [
    (False, PermissionError(13, 'denied'), False),
    (True, PermissionError(13, 'denied'), True),
    (True, OSError('BFE unavailable'), False),
    (True, wfp.LegacyDnsPermitError('legacy present'), False),
])
def test_firewall_readiness_accepts_proof_on_access_denial_only(monkeypatch, verified, failure, ready):
    _registry(monkeypatch, {'sid': 'S-test', 'firewall_ranges': [[61100, 61102]],
                          'firewall_legacy_dns_verified': verified})
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(side_effect=PermissionError(13, 'denied')))
    wfp.verify_legacy_dns_permits_absent.side_effect = failure
    live = Mock(return_value=True)
    monkeypatch.setattr(wfp, 'firewall_permits_installed', live)
    assert setup._proxy_ports_ready(61100, 61102) is ready
    assert live.called is ready


@pytest.mark.parametrize('operation', ['rollback', 'uninstall'])
def test_receipt_clear_failure_stops_removal_before_network_protection_is_deleted(monkeypatch, operation):
    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, '_is_admin', lambda: True)
    monkeypatch.setattr(setup, '_reg_set_str', Mock(side_effect=OSError('receipt is not writable')))
    remove_wfp, remove_firewall, remove_user = Mock(), Mock(), Mock()
    monkeypatch.setattr(wfp, 'uninstall_wfp_filters', remove_wfp)
    monkeypatch.setattr(wfp, 'uninstall_firewall_rule_fallback', remove_firewall)
    monkeypatch.setattr(setup, '_remove_sandbox_user_and_profile', remove_user)
    with pytest.raises(OSError, match='receipt is not writable'):
        if operation == 'rollback':
            setup._install_rollback({'wfp', 'user_existed'})
        else:
            setup.uninstall()
    remove_wfp.assert_not_called()
    remove_firewall.assert_not_called()
    remove_user.assert_not_called()


@pytest.mark.parametrize('operation', ['rollback', 'uninstall'])
def test_removal_invalidates_both_receipts_before_calling_either_network_backend(monkeypatch, operation):
    monkeypatch.setattr(setup, '_require_windows', Mock())
    monkeypatch.setattr(setup, '_is_admin', lambda: True)
    values = _registry(monkeypatch, {'sid': 'S-test', 'wfp_ranges': [[61100, 61102]],
                                    'firewall_ranges': [[61100, 61102]]})
    observed = []

    def verify_cleared():
        observed.append(values[setup._PROXY_PERMIT_RECORD])

    monkeypatch.setattr(wfp, 'uninstall_wfp_filters', verify_cleared)
    monkeypatch.setattr(wfp, 'uninstall_firewall_rule_fallback', verify_cleared)
    monkeypatch.setattr(setup, '_remove_sandbox_user_and_profile', Mock())
    if operation == 'rollback':
        setup._install_rollback({'wfp', 'user_existed'})
    else:
        setup.uninstall()
    assert observed == ['', '']


@pytest.mark.parametrize('query', [False, PermissionError(13, 'denied')])
def test_unverified_network_state_and_missing_firewall_rules_reject_both_old_receipts(monkeypatch, query):
    _registry(monkeypatch, {'sid': 'S-test', 'wfp_ranges': [[61100, 61102]],
                          'firewall_ranges': [[61100, 61102]]})
    native = Mock(side_effect=query) if isinstance(query, Exception) else Mock(return_value=query)
    monkeypatch.setattr(wfp, 'proxy_permits_installed', native)
    live = Mock(return_value=False)
    monkeypatch.setattr(wfp, 'firewall_permits_installed', live, raising=False)
    assert not setup._proxy_ports_ready(61100, 61102)
    live.assert_called_once_with('S-test', 61100, 61102)


def test_nonadmin_service_rejects_a_firewall_receipt_when_actual_rules_are_gone(monkeypatch):
    _prepared(monkeypatch)
    _registry(monkeypatch, {'sid': 'S-test', 'firewall_ranges': [[61100, 61102]]})
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(side_effect=PermissionError(13, 'denied')))
    monkeypatch.setattr(wfp, 'firewall_permits_installed', Mock(return_value=False), raising=False)
    install = Mock()
    monkeypatch.setattr(setup, 'install', install)
    with pytest.raises(RuntimeError, match='UAC'):
        setup.ensure_windows_setup(proxy_port_start=61100, proxy_port_end=61102, allow_elevation=False)
    install.assert_not_called()


def test_nonoverlapping_firewall_range_does_not_invalidate_other_wfp_instances(monkeypatch):
    _registry(monkeypatch, {'sid': 'S-test', 'wfp_ranges': [[61100, 61102]],
                          'wfp_content_verified': True,
                          'firewall_ranges': [[61200, 61202]]})
    monkeypatch.setattr(wfp, 'proxy_permits_installed', Mock(side_effect=PermissionError(13, 'denied')))
    live = Mock(return_value=False)
    monkeypatch.setattr(wfp, 'firewall_permits_installed', live, raising=False)
    assert setup._proxy_ports_ready(61100, 61102)
    live.assert_not_called()
