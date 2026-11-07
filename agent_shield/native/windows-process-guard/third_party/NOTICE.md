# Microsoft Detours

Detours is a **build-time** dependency of `windows-process-guard` only.
It is **not** a git submodule and is **not** required to install or import
`agent-shield` / `jiuwenbox` (Python packages).

Pin: [Microsoft Detours](https://github.com/microsoft/Detours) **v4.0.1** (MIT),
historically `1dbd4ea281d73d478aa8d09a8b83fbd265f715f7`.

```powershell
# Default location used by build.ps1 (gitignored):
$root = "agent_shield/native/windows-process-guard/third_party/detours"
git clone --branch v4.0.1 --depth 1 https://github.com/microsoft/Detours $root

# Or point at an existing / mirrored checkout:
$env:DETOURS_ROOT = "D:\mirror\Detours"
# Optional mirror URL when using build.ps1 -FetchDetours:
$env:DETOURS_GIT_URL = "https://gitcode.com/<org>/Detours.git"
```

The upstream MIT license is in `LICENSE.md` inside the checkout after clone.

Copyright (c) Microsoft Corporation. All rights reserved.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
