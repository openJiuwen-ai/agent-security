# Compile the Windows process guard unit tests with the installed MSVC toolset.
# Detours is an external checkout (DETOURS_ROOT), not a git submodule — so cloning
# this repo / `uv sync` never needs github.com/microsoft/Detours.
param(
    # When set, clone Detours into DETOURS_ROOT if Makefile is missing.
    # Off by default so CI without GitHub access fails fast with a clear message
    # instead of hanging on github.com.
    [switch]$FetchDetours,
    [string]$ToolchainRoot
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($ToolchainRoot) {
    $ToolchainRoot = (Resolve-Path -LiteralPath $ToolchainRoot).Path
    $vcvars = Join-Path $ToolchainRoot 'setup_x64.bat'
} else {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $install) { throw "MSVC C++ toolset was not found" }
    $vcvars = Join-Path $install "VC\Auxiliary\Build\vcvars64.bat"
}
$out = Join-Path $root "build"
New-Item -ItemType Directory -Force -Path $out | Out-Null

$tests = @(
    "test_path_classification",
    "test_message_framing",
    "test_operation_mapping",
    "test_record_json"
)
foreach ($name in $tests) {
    $source = Join-Path $root "tests\$name.cpp"
    $objects = @()
    if ($name -eq "test_path_classification") {
        $objects += Join-Path $root "src\path_classification.c"
    } elseif ($name -eq "test_message_framing") {
        $objects += Join-Path $root "src\message_framing.c"
    } elseif ($name -eq "test_record_json") {
        $objects += Join-Path $root "src\record_json.c"
        $objects += Join-Path $root "src\message_framing.c"
    } else {
        $objects += Join-Path $root "src\operation_mapping.c"
        $objects += Join-Path $root "src\path_classification.c"
    }
    $files = (@($source) + $objects) -join " "
    $command = "`"$vcvars`" && cl /nologo /W4 /WX /EHsc /utf-8 /Fo`"$out\\`" /Fe`"$out\$name.exe`" $files"
    cmd /c $command
    if ($LASTEXITCODE -ne 0) {
        throw "compile failed: $name"
    }
    & (Join-Path $out "$name.exe")
    if ($LASTEXITCODE -ne 0) {
        throw "test failed: $name"
    }
}
Write-Output "windows process guard unit tests passed"

$src = Join-Path $root "src"
$vcvarsAll = if ($ToolchainRoot) { $null } else { Join-Path $install "VC\Auxiliary\Build\vcvarsall.bat" }
$wheelBin = Join-Path $root "python\src\agent_security_dll\bin\win_amd64"
New-Item -ItemType Directory -Force -Path $wheelBin | Out-Null

# Resolve Detours the same way jiuwenbox softdelete does: external checkout only.
$detoursRoot = $env:DETOURS_ROOT
if (-not $detoursRoot) {
    $detoursRoot = Join-Path $root "third_party\detours"
}
$detoursSrc = Join-Path $detoursRoot "src"
$detoursGitUrl = $env:DETOURS_GIT_URL
if (-not $detoursGitUrl) {
    $detoursGitUrl = "https://github.com/microsoft/Detours.git"
}

function Test-DetoursCheckout([string]$Path) {
    # A real Detours tree has src\Makefile; a git clone also has .git.
    return (Test-Path (Join-Path $Path "src\Makefile")) -or (Test-Path (Join-Path $Path ".git"))
}

function Ensure-DetoursCheckout {
    if (Test-Path (Join-Path $detoursSrc "Makefile")) {
        return
    }
    if (-not $FetchDetours) {
        throw @"
Detours sources not found at: $detoursRoot
Native build needs an external checkout (not a git submodule).

  `$env:DETOURS_ROOT = '<path-to-Detours>'
  # or clone into the default gitignored path:
  git clone --branch v4.0.1 --depth 1 $detoursGitUrl `"$detoursRoot`"
  # mirrors: set `$env:DETOURS_GIT_URL before cloning / use -FetchDetours

See third_party/NOTICE.md.
"@
    }
    Write-Output "Fetching Detours into $detoursRoot from $detoursGitUrl"
    if (Test-Path $detoursRoot) {
        $entries = @(Get-ChildItem -Force $detoursRoot -ErrorAction SilentlyContinue)
        if ($entries.Count -gt 0 -and -not (Test-DetoursCheckout $detoursRoot)) {
            throw @"
DETOURS_ROOT=$detoursRoot exists but is not a Detours checkout (missing src\Makefile / .git).
Refusing to delete it. Point DETOURS_ROOT at a new empty path, or at a real Detours tree.
"@
        }
    }

    # Clone into a temp dir first; only replace the target after src\Makefile is verified.
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("detours-fetch-" + [guid]::NewGuid().ToString("n"))
    try {
        git clone --branch v4.0.1 --depth 1 $detoursGitUrl $tmp
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $tmp "src\Makefile"))) {
            throw "Failed to fetch Detours from $detoursGitUrl (clone missing src\Makefile)"
        }
        $parent = Split-Path -Parent $detoursRoot
        New-Item -ItemType Directory -Force -Path $parent | Out-Null
        if (Test-Path $detoursRoot) {
            # Safe: empty dir, or previously validated as a Detours-looking tree.
            Remove-Item -Recurse -Force $detoursRoot
        }
        Move-Item -Path $tmp -Destination $detoursRoot
    } finally {
        if (Test-Path $tmp) {
            Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
        }
    }
    if (-not (Test-Path (Join-Path $detoursSrc "Makefile"))) {
        throw "Failed to place Detours at $detoursRoot"
    }
}

Ensure-DetoursCheckout
# A copied tree with src\Makefile is valid. Pin the commit only for a git checkout.
if (Test-Path (Join-Path $detoursRoot ".git")) {
    $commit = $null
    try {
        $commit = & git -C $detoursRoot rev-parse HEAD 2>$null
    } catch {
        $commit = $null
    }
    if ($LASTEXITCODE -ne 0 -or -not $commit) {
        throw "Unable to read Detours HEAD at $detoursRoot (a git checkout is required)"
    }
    $commit = "$commit".Trim()
    if ($commit -ne "e4bfd6b03e50de46b47abfbd1e46b384f0c5f833") {
        throw "Use the pinned Detours v4.0.1 checkout"
    }
}

function Invoke-Vc([string]$Arch, [string]$Command) {
    if ($ToolchainRoot) {
        $setup = Join-Path $ToolchainRoot $(if ($Arch -eq 'x86') {'setup_x86.bat'} else {'setup_x64.bat'})
        cmd /c "`"$setup`" && $Command"
    } else {
        cmd /c "`"$vcvarsAll`" $Arch && $Command"
    }
    if ($LASTEXITCODE -ne 0) {
        throw "command failed ($Arch): $Command"
    }
}

Invoke-Vc "amd64" "cd /d `"$detoursSrc`" && nmake"
Invoke-Vc "x86" "cd /d `"$detoursSrc`" && nmake"

$common = @(
    "pipe_io.c",
    "record_json.c",
    "message_framing.c",
    "operation_mapping.c",
    "path_classification.c"
) | ForEach-Object { "`"$src\$_`"" }
$commonList = $common -join " "
$x64 = Join-Path $out "x64"
$x86 = Join-Path $out "x86"
New-Item -ItemType Directory -Force -Path $x64, $x86, (Join-Path $x64 "hook"), (Join-Path $x86 "hook") | Out-Null
$detoursX64 = Join-Path $detoursRoot "lib.X64\detours.lib"
$detoursX86 = Join-Path $detoursRoot "lib.X86\detours.lib"

Invoke-Vc "amd64" "cl /nologo /W4 /WX /EHsc /MD /utf-8 /I `"$src`" /I `"$detoursSrc`" /Fo`"$x64\\`" /Fe`"$out\process_guard.exe`" `"$src\process_guard_main.cpp`" $commonList /link `"$detoursX64`""
Invoke-Vc "amd64" "cl /nologo /W4 /WX /EHsc /MT /utf-8 /LD /I `"$src`" /I `"$detoursSrc`" /Fo`"$x64\hook\\`" /Fe`"$out\process_guard_hook_x64.dll`" `"$src\hooks.cpp`" $commonList /link /DEF:`"$src\process_guard_hook.def`" `"$detoursX64`""
Invoke-Vc "amd64" "cl /nologo /W4 /WX /EHsc /MD /utf-8 /Fo`"$x64\\`" /Fe`"$out\probe.exe`" `"$src\probe.cpp`""
Invoke-Vc "x86" "cl /nologo /W4 /WX /EHsc /MT /utf-8 /LD /I `"$src`" /I `"$detoursSrc`" /Fo`"$x86\hook\\`" /Fe`"$out\process_guard_hook_x86.dll`" `"$src\hooks.cpp`" $commonList /link /DEF:`"$src\process_guard_hook.def`" `"$detoursX86`""

foreach ($name in @("process_guard.exe", "process_guard_hook_x64.dll", "process_guard_hook_x86.dll")) {
    Copy-Item (Join-Path $out $name) (Join-Path $wheelBin $name) -Force
}
Copy-Item -LiteralPath (Join-Path $detoursRoot 'LICENSE.md') -Destination (Join-Path $wheelBin 'LICENSE.Detours.txt') -Force
Write-Output "windows process guard binaries built"
