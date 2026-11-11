# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""A configured syscall denial cannot silently disappear on filter failure."""
# pylint: disable=protected-access
# Fault injection targets private filter/launch seams without spawning a sandbox.
import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from jiuwenbox.models.policy import SecurityPolicy, SyscallPolicy
from jiuwenbox.supervisor import seccomp


def test_unknown_configured_syscall_is_rejected_instead_of_silently_omitted(monkeypatch):
    monkeypatch.setattr(seccomp, '_machine', lambda: 'x86_64')
    monkeypatch.setattr(seccomp, '_get_syscall_numbers', lambda: {'getpid': 39})
    policy = SyscallPolicy.model_validate({'x86_64': {'blocked': ['misspelled_syscall']}})
    with pytest.raises(ValueError, match='misspelled_syscall'):
        seccomp.build_seccomp_filter(policy)


def test_syscall_filter_keeps_the_requested_deny_and_architecture_guard(monkeypatch):
    monkeypatch.setattr(seccomp, '_machine', lambda: 'x86_64')
    monkeypatch.setattr(seccomp, '_get_syscall_numbers', lambda: {'getpid': 39})
    policy = SyscallPolicy.model_validate({'x86_64': {'blocked': ['getpid']}})
    assert seccomp.build_seccomp_filter(policy) == seccomp._assemble_bpf([39])


@pytest.mark.skipif(sys.platform == 'win32', reason='Linux-only runtime; tested on Linux separately')
def test_seccomp_setup_failure_closes_listener_cleans_state_and_never_spawns(tmp_path, monkeypatch):
    from jiuwenbox.server.runtime.process import ProcessRuntime

    runtime = ProcessRuntime()
    policy = SecurityPolicy()
    listener = SimpleNamespace(fileno=lambda: 12, close=Mock())
    for name, result in [('_load_policy', policy), ('_ensure_named_netns', None),
                         ('_policy_binds_for_sandbox', None), ('_install_sandbox_host_firewall_rules', None),
                         ('_ensure_launcher_dir', None), ('_ensure_landlock_payload', None),
                         ('_create_daemon_listener', listener), ('_ensure_seccomp_bpf', b'filter')]:
        monkeypatch.setattr(runtime, name, Mock(return_value=result))
    monkeypatch.setattr(runtime, '_open_seccomp_fd_from_bytes', Mock(side_effect=OSError('seccomp unavailable')))
    spawn = Mock(side_effect=AssertionError('must not spawn an unfiltered daemon'))
    monkeypatch.setattr(runtime, '_build_sandbox_bwrap_args', spawn)
    cleanup = Mock()
    monkeypatch.setattr(runtime, '_cleanup_sandbox_artifacts', cleanup)
    with pytest.raises(RuntimeError, match='seccomp'):
        asyncio.run(runtime.create('sandbox', tmp_path / 'policy.yaml'))
    listener.close.assert_called_once()
    cleanup.assert_called_once_with('sandbox', None)
    spawn.assert_not_called()


@pytest.mark.parametrize('machine,nr', [('x86_64', 257), ('amd64', 257), ('aarch64', 56), ('arm64', 56)])
def test_native_syscall_resolves_without_host_headers(monkeypatch, machine, nr):
    monkeypatch.setattr(seccomp, '_machine', lambda: machine)
    monkeypatch.setattr(seccomp.Path, 'exists', lambda _self: False)
    seccomp._get_syscall_numbers.cache_clear()
    try:
        assert seccomp._get_syscall_numbers()['openat'] == nr
        policy_key = 'arm64' if machine in {'arm64', 'aarch64'} else 'x86_64'
        policy = SyscallPolicy.model_validate({policy_key: {'blocked': ['openat']}})
        assert seccomp.build_seccomp_filter(policy) == seccomp._assemble_bpf([nr])
    finally:
        seccomp._get_syscall_numbers.cache_clear()


def test_partial_header_extends_the_native_table_without_overriding_known_numbers(monkeypatch):
    monkeypatch.setattr(seccomp, '_machine', lambda: 'x86_64')
    monkeypatch.setattr(seccomp.Path, 'exists', lambda _self: True)
    monkeypatch.setattr(seccomp.Path, 'read_text', lambda _self:
                        '#define __NR_future_call 900\n#define __NR_openat 56\n#define __NR_syscalls 901')
    seccomp._get_syscall_numbers.cache_clear()
    try:
        table = seccomp._get_syscall_numbers()
        assert table['openat'] == 257
        assert table['gettid'] == 186
        assert table['future_call'] == 900
        assert 'syscalls' not in table
    finally:
        seccomp._get_syscall_numbers.cache_clear()


def test_x86_does_not_use_the_generic_arm_syscall_header(monkeypatch):
    monkeypatch.setattr(seccomp, '_machine', lambda: 'x86_64')
    monkeypatch.setattr(seccomp.Path, 'exists', lambda path: 'asm-generic' in str(path))
    read = Mock(return_value='#define __NR_getpid 172\n#define __NR_openat 56')
    monkeypatch.setattr(seccomp.Path, 'read_text', read)
    seccomp._get_syscall_numbers.cache_clear()
    try:
        assert seccomp._get_syscall_numbers()['getpid'] == 39
        assert seccomp._get_syscall_numbers()['openat'] == 257
        read.assert_not_called()
    finally:
        seccomp._get_syscall_numbers.cache_clear()
