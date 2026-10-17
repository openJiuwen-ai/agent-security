# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Windows runtime adapter package (design doc section 5.1, phase 4-5).

This package hosts the Windows sandbox backend. It is imported lazily by
the runtime registry; importing it on Linux is harmless (the package module
imports are platform-guarded) but the adapter itself only runs on Windows.
"""