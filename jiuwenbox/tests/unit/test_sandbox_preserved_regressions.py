# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Already implemented ACL, soft-delete and opt-in auth boundaries stay intact."""
# pylint: disable=protected-access
# The bounded walker is tested without invoking DACL mutation entrypoints.
import sys
from unittest.mock import Mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from jiuwenbox.server.auth import BearerTokenAuthMiddleware
from jiuwenbox.supervisor import win_acl, win_setup, win_softdelete


def test_unlistable_acl_child_does_not_abort_sibling_processing(tmp_path, monkeypatch):
    blocked = tmp_path / 'blocked'
    blocked.mkdir()
    sibling = tmp_path / 'sibling'
    sibling.write_text('ordinary file', encoding='utf-8')
    scan = win_acl.os.scandir

    def scandir(path):
        if str(path) == str(blocked):
            raise PermissionError('cannot enumerate sandbox-owned directory')
        return scan(path)

    monkeypatch.setattr(win_acl.os, 'scandir', scandir)
    paths = set(win_acl._walk_acl_objects(str(tmp_path)))
    assert paths == {str(tmp_path), str(blocked), str(sibling)}


def test_acl_walk_does_not_follow_linked_subtrees(tmp_path, monkeypatch):
    linked = tmp_path / 'linked'
    linked.mkdir()
    (linked / 'secret').write_text('not walked', encoding='utf-8')
    monkeypatch.setattr(win_acl.os.path, 'islink', lambda path: str(path) == str(linked))
    assert list(win_acl._walk_acl_objects(str(tmp_path))) == [str(tmp_path)]


@pytest.mark.skipif(sys.platform != 'win32', reason='Windows soft-delete preparation')
def test_readable_program_files_dll_does_not_require_rewriting_its_dacl(tmp_path, monkeypatch):
    dll = tmp_path / 'Program Files' / 'softdelete.dll'
    dll.parent.mkdir()
    dll.write_bytes(b'not loaded by this test')
    monkeypatch.setattr(win_softdelete, 'dll_path', lambda: dll)
    monkeypatch.setattr(win_setup, 'get_sandbox_user_sid', lambda: 'S-test')
    monkeypatch.setattr(win_softdelete, 'sandbox_can_load_dll', lambda *_args: True)
    traverse = Mock()
    monkeypatch.setattr(win_acl, 'grant_parent_traverse', traverse)
    mutate = Mock(side_effect=AssertionError('already readable, do not rewrite DACL'))
    monkeypatch.setattr(win_acl, 'grant_ace', mutate)
    assert win_softdelete.prepare_dll_for_sandbox_user() == dll
    traverse.assert_called_once_with(str(dll), 'S-test')
    mutate.assert_not_called()


@pytest.mark.parametrize('expected_token,provided,status', [
    (None, None, 200), ('', None, 200), ('secret', None, 401),
    ('secret', 'Bearer wrong', 401), ('secret', 'Bearer secret', 200),
])
def test_box_http_auth_remains_opt_in(monkeypatch, expected_token, provided, status):
    if expected_token is None:
        monkeypatch.delenv('JIUWENBOX_API_TOKEN', raising=False)
    else:
        monkeypatch.setenv('JIUWENBOX_API_TOKEN', expected_token)
    app = FastAPI()
    app.add_middleware(BearerTokenAuthMiddleware)

    @app.get('/probe')
    def probe():
        return {'ok': True}

    with TestClient(app) as client:
        response = client.get('/probe', headers={'Authorization': provided} if provided else {})
    assert response.status_code == status
