# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""A failed optional path must not discard successful Landlock rules."""
# pylint: disable=protected-access
# These tests replace private syscall boundaries; no process is restricted here.
import logging
import sys
from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Linux Landlock launcher')


def _launcher(monkeypatch):
    from jiuwenbox.supervisor import landlock_launcher as launcher
    monkeypatch.setattr(launcher, '_detect_abi', lambda: 3)
    monkeypatch.setattr(launcher, 'prctl', Mock(return_value=0))
    syscall = Mock(side_effect=lambda nr, *_args: 123 if nr == launcher.LANDLOCK_CREATE_RULESET else 0)
    monkeypatch.setattr(launcher, '_syscall', syscall)
    close = Mock()
    monkeypatch.setattr(launcher.os, 'close', close)
    return launcher, syscall, close


@pytest.mark.parametrize('failed_axis', ['read_only', 'read_write'])
def test_best_effort_skips_only_the_failed_path_and_restricts_remaining_rules(monkeypatch, caplog, failed_axis):
    launcher, syscall, close = _launcher(monkeypatch)

    def add_rule(_fd, path, _access):
        if path == '/failed':
            raise OSError('path rule failed')

    add = Mock(side_effect=add_rule)
    monkeypatch.setattr(launcher, '_add_rule', add)
    payload = {'compatibility': 'best_effort', 'read_only': ['/ro'], 'read_write': ['/rw']}
    failed_paths = payload.get(failed_axis)
    assert isinstance(failed_paths, list), f'Unexpected filesystem axis: {failed_axis}'
    failed_paths.insert(0, '/failed')
    with caplog.at_level(logging.WARNING, logger=launcher.logger.name):
        launcher.apply_landlock(payload)
    assert {call.args[1] for call in add.call_args_list} == {'/failed', '/ro', '/rw'}
    assert syscall.call_args.args == (launcher.LANDLOCK_RESTRICT_SELF, 123, 0)
    assert '/failed' in caplog.text and 'path rule failed' in caplog.text
    close.assert_called_once_with(123)


def test_best_effort_all_failed_paths_still_apply_an_empty_ruleset(monkeypatch):
    launcher, syscall, close = _launcher(monkeypatch)
    monkeypatch.setattr(launcher, '_add_rule', Mock(side_effect=FileNotFoundError('raced away')))
    launcher.apply_landlock({'compatibility': 'best_effort', 'read_only': ['/gone'], 'read_write': []})
    assert syscall.call_args.args == (launcher.LANDLOCK_RESTRICT_SELF, 123, 0)
    close.assert_called_once_with(123)


def test_hard_requirement_still_stops_on_the_first_failed_path(monkeypatch):
    launcher, syscall, close = _launcher(monkeypatch)
    monkeypatch.setattr(launcher, '_add_rule', Mock(side_effect=OSError('required path failed')))
    with pytest.raises(launcher.LandlockHardRequirementError):
        launcher.apply_landlock({'compatibility': 'hard_requirement', 'read_only': ['/bad'], 'read_write': ['/rw']})
    assert not any(call.args[0] == launcher.LANDLOCK_RESTRICT_SELF for call in syscall.call_args_list)
    close.assert_called_once_with(123)


def test_disabled_landlock_keeps_its_existing_no_syscall_behavior(monkeypatch):
    launcher, syscall, _ = _launcher(monkeypatch)
    launcher.apply_landlock({'compatibility': 'disabled', 'read_only': ['/bad'], 'read_write': []})
    syscall.assert_not_called()


def test_best_effort_global_unavailability_is_logged(monkeypatch, caplog):
    launcher, syscall, _ = _launcher(monkeypatch)
    monkeypatch.setattr(launcher, '_detect_abi', lambda: 0)
    with caplog.at_level(logging.WARNING, logger=launcher.logger.name):
        launcher.apply_landlock({'compatibility': 'best_effort', 'read_only': [], 'read_write': []})
    syscall.assert_not_called()
    assert 'Landlock is not supported' in caplog.text
