# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""cgroup v2 根控制器使能的 EBUSY 容忍分支单元测试。

子系统已含 EBUSY 时,内核对 subtree_control 的重复写入返回 EBUSY;
该场景按注释语义应当容忍(控制器已处于目标状态),其余错误照常抛
CgroupSetupError。系统测试(test_cgroup_limits.py)需要真实 cgroup v2
主机,本文件用 monkeypatch 锁定这个分支判定本身。

用例通过公开入口 setup() 驱动(不直接访问受保护的内部函数):
detect_backend 打桩为 V2,_write_file 只在 jiuwenbox 子树的
subtree_control 上注入目标错误。
"""
import errno

import pytest
from jiuwenbox.models.policy import CgroupPolicy
from jiuwenbox.supervisor import cgroup


def _fake_cgroup_root(tmp_path, monkeypatch, subtree_error):
    """搭一个最小可用的假 cgroup v2 层级,并注入子树写错误。

    root 上的第一次 subtree_control 写入保持成功;jiuwenbox 子树的
    subtree_control 写入抛 subtree_error,让 setup() 走到目标分支。
    """
    root = tmp_path / "cgroup"
    (root / "jiuwenbox").mkdir(parents=True)
    monkeypatch.setattr(cgroup, "_CGROUP_ROOT", root)

    def write_file(path, content):
        if subtree_error is not None and path.parent == root / "jiuwenbox":
            raise subtree_error

    monkeypatch.setattr(cgroup, "_write_file", write_file)
    monkeypatch.setattr(cgroup, "detect_backend", lambda: cgroup.CgroupBackend.V2)
    return root / "jiuwenbox"


def test_repeated_enable_ebusy_is_tolerated(tmp_path, monkeypatch):
    """控制器已使能(EBUSY)时不得中断沙箱创建流程。"""
    fake_root = _fake_cgroup_root(
        tmp_path, monkeypatch, OSError(errno.EBUSY, "Device or resource busy")
    )
    # EBUSY 被容忍:setup 走通并返回句柄,不抛异常
    handle = cgroup.setup("sb-ebusy", CgroupPolicy(memory_max=1))
    assert handle.paths == [fake_root / "sb-ebusy"]


@pytest.mark.parametrize("bad_errno", [errno.EACCES, errno.EINVAL, errno.ENOENT, errno.EROFS])
def test_other_errors_still_raise(tmp_path, monkeypatch, bad_errno):
    """非 EBUSY 错误仍然抛 CgroupSetupError。"""
    _fake_cgroup_root(tmp_path, monkeypatch, OSError(bad_errno, "real failure"))
    with pytest.raises(cgroup.CgroupSetupError):
        cgroup.setup("sb-fail", CgroupPolicy(memory_max=1))
