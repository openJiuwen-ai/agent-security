# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Apply kernel restrictions only inside disposable, unprivileged test children."""
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import jiuwenbox

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='Native Linux isolation')


def _child(code, *args):
    root = str(Path(jiuwenbox.__file__).resolve().parents[1])
    result = subprocess.run([sys.executable, '-B', '-c', code, root, *args],
                            capture_output=True, text=True, timeout=15, check=False)
    if result.returncode == 77:
        pytest.skip(result.stderr.strip())
    assert result.returncode == 0, result.stdout + result.stderr


def test_native_seccomp_denies_configured_syscall_and_leaves_ordinary_calls_usable():
    _child('''
import ctypes, errno, os, sys
sys.path.insert(0, sys.argv[1])
from jiuwenbox.models.policy import SyscallPolicy
from jiuwenbox.supervisor import seccomp
class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
class Program(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
libc = ctypes.CDLL(None, use_errno=True)
nr = seccomp._get_syscall_numbers()['getppid']
assert libc.syscall(nr) > 0
policy = SyscallPolicy.model_validate({seccomp._arch_aliases()[0]: {'blocked': ['getppid']}})
raw = seccomp.build_seccomp_filter(policy)
array = (Filter * (len(raw) // ctypes.sizeof(Filter))).from_buffer_copy(raw)
program = Program(len(array), array)
if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
    print('Kernel disallows seccomp filter setup: ' + str(ctypes.get_errno()), file=sys.stderr)
    sys.exit(77)
ctypes.set_errno(0)
assert libc.syscall(nr) == -1 and ctypes.get_errno() == errno.EPERM
assert os.getpid() > 0
''')


def test_native_seccomp_denies_syscall_resolved_without_headers():
    _child('''
import ctypes, errno, os, sys
sys.path.insert(0, sys.argv[1])
from jiuwenbox.models.policy import SyscallPolicy
from jiuwenbox.supervisor import seccomp
class Filter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]
class Program(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]
original_exists = seccomp.Path.exists
seccomp.Path.exists = lambda _self: False
try:
    seccomp._get_syscall_numbers.cache_clear()
    nr = seccomp._get_syscall_numbers()['gettid']
    policy = SyscallPolicy.model_validate({seccomp._arch_aliases()[0]: {'blocked': ['gettid']}})
    raw = seccomp.build_seccomp_filter(policy)
finally:
    seccomp.Path.exists = original_exists
libc = ctypes.CDLL(None, use_errno=True)
assert libc.syscall(nr) > 0
array = (Filter * (len(raw) // ctypes.sizeof(Filter))).from_buffer_copy(raw)
program = Program(len(array), array)
if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(program), 0, 0) != 0:
    print('Kernel disallows seccomp filter setup: ' + str(ctypes.get_errno()), file=sys.stderr)
    sys.exit(77)
ctypes.set_errno(0)
assert libc.syscall(nr) == -1 and ctypes.get_errno() == errno.EPERM
assert os.getpid() > 0
''')


def test_native_landlock_keeps_allowed_directory_readable_and_denies_other_directory():
    # WSL's /mnt drive bridge is not a native Linux filesystem. Exercise
    # kernel inode restrictions on Linux tmpfs/ext4 rather than DrvFS.
    with tempfile.TemporaryDirectory(prefix='jiuwenbox-landlock-', dir='/tmp') as directory:
        root = Path(directory)
        allowed, denied = root / 'allowed', root / 'denied'
        allowed.mkdir()
        denied.mkdir()
        (allowed / 'probe').write_bytes(b'allowed')
        (denied / 'probe').write_bytes(b'denied')
        _check_landlock(allowed, denied)


def _check_landlock(allowed, denied):
    _child('''
import errno, os, sys
sys.path.insert(0, sys.argv[1])
from jiuwenbox.supervisor import landlock_launcher as launcher
if launcher._detect_abi() <= 0:
    print('Kernel does not support Landlock', file=sys.stderr)
    sys.exit(77)
launcher.apply_landlock({'compatibility': 'hard_requirement', 'read_only': [sys.argv[2]], 'read_write': []})
fd = os.open(sys.argv[2] + '/probe', os.O_RDONLY)
assert os.read(fd, 20) == b'allowed'
os.close(fd)
try:
    fd = os.open(sys.argv[3] + '/probe', os.O_RDONLY)
except OSError as exc:
    assert exc.errno in (errno.EACCES, errno.EPERM)
else:
    os.close(fd)
    raise AssertionError('Landlock did not deny the undeclared directory')
''', str(allowed), str(denied))


@pytest.mark.parametrize('axis', ['read_only', 'read_write'])
def test_native_landlock_file_rule_does_not_grant_access_to_its_siblings(axis):
    with tempfile.TemporaryDirectory(prefix='jiuwenbox-landlock-file-', dir='/tmp') as directory:
        root = Path(directory)
        (root / 'allowed').write_bytes(b'allowed')
        (root / 'sibling').write_bytes(b'secret')
        _child('''
import errno, os, sys
sys.path.insert(0, sys.argv[1])
from jiuwenbox.supervisor import landlock_launcher as launcher
if launcher._detect_abi() <= 0:
    print('Kernel does not support Landlock', file=sys.stderr)
    sys.exit(77)
allowed, sibling, axis = sys.argv[2:]
payload = {'compatibility': 'hard_requirement', 'read_only': [], 'read_write': []}
payload[axis] = [allowed]
launcher.apply_landlock(payload)
fd = os.open(allowed, os.O_RDONLY)
assert os.read(fd, 20) == b'allowed'
os.close(fd)
if axis == 'read_write':
    fd = os.open(allowed, os.O_WRONLY | os.O_TRUNC)
    os.write(fd, b'updated')
    os.close(fd)
try:
    fd = os.open(sibling, os.O_RDONLY)
except OSError as exc:
    assert exc.errno in (errno.EACCES, errno.EPERM)
else:
    os.close(fd)
    raise AssertionError('A file rule granted access to an undeclared sibling')
''', str(root / 'allowed'), str(root / 'sibling'), axis)


@pytest.mark.parametrize('failure', ['open', 'add_rule'])
@pytest.mark.parametrize('mode', ['best_effort', 'hard_requirement'])
def test_native_landlock_path_failure_does_not_remove_other_path_restrictions(failure, mode):
    with tempfile.TemporaryDirectory(prefix='jiuwenbox-landlock-partial-', dir='/tmp') as directory:
        root = Path(directory)
        for name in ['ro', 'rw', 'broken', 'outside']:
            (root / name).mkdir()
            (root / name / 'probe').write_bytes(name.encode())
        _child('''
import ctypes, errno, os, sys
sys.path.insert(0, sys.argv[1])
from jiuwenbox.supervisor import landlock_launcher as launcher
if launcher._detect_abi() <= 0:
    print('Kernel does not support Landlock', file=sys.stderr)
    sys.exit(77)
root, failure, mode = sys.argv[2:]
broken = root + '/broken/probe'
original_open, original_syscall = os.open, launcher._syscall
restricted = []
def open_path(path, *args, **kwargs):
    if failure == 'open' and path == broken:
        raise FileNotFoundError(errno.ENOENT, 'removed after exists check', path)
    return original_open(path, *args, **kwargs)
def syscall(nr, *args):
    if nr == launcher.LANDLOCK_RESTRICT_SELF:
        restricted.append(True)
    if failure == 'add_rule' and nr == launcher.LANDLOCK_ADD_RULE:
        rule = ctypes.cast(args[2], ctypes.POINTER(launcher.LandlockPathBeneathAttr)).contents
        if os.readlink('/proc/self/fd/' + str(rule.parent_fd)) == broken:
            ctypes.set_errno(errno.EINVAL)
            return -1
    return original_syscall(nr, *args)
launcher.os.open, launcher._syscall = open_path, syscall
payload = {'compatibility': mode, 'read_only': [root + '/ro', broken], 'read_write': [root + '/rw']}
try:
    launcher.apply_landlock(payload)
except launcher.LandlockHardRequirementError:
    assert mode == 'hard_requirement' and not restricted
    sys.exit(0)
finally:
    launcher.os.open = original_open
assert mode == 'best_effort' and restricted
fd = os.open(root + '/ro/probe', os.O_RDONLY)
assert os.read(fd, 20) == b'ro'
os.close(fd)
fd = os.open(root + '/rw/probe', os.O_WRONLY | os.O_TRUNC)
os.write(fd, b'updated')
os.close(fd)
for path in [broken, root + '/outside/probe']:
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        assert exc.errno in (errno.EACCES, errno.EPERM)
    else:
        os.close(fd)
        raise AssertionError('A failed rule removed the remaining Landlock restrictions')
''', str(root), failure, mode)
