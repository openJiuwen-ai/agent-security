# Compile the Windows process guard unit tests with the installed MSVC toolset.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $install) {
    throw "MSVC C++ toolset was not found"
}
$vcvars = Join-Path $install "VC\Auxiliary\Build\vcvars64.bat"
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
$detoursSrc = Join-Path $root "third_party\detours\src"
$vcvarsAll = Join-Path $install "VC\Auxiliary\Build\vcvarsall.bat"
$wheelBin = Join-Path $root "python\src\agent_security_windows_process_guard\bin\win_amd64"
New-Item -ItemType Directory -Force -Path $wheelBin | Out-Null

if (-not (Test-Path (Join-Path $detoursSrc "Makefile"))) {
    throw "Detours submodule is missing. Run: git submodule update --init"
}

function Invoke-Vc([string]$Arch, [string]$Command) {
    cmd /c "`"$vcvarsAll`" $Arch && $Command"
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
$detoursX64 = Join-Path $root "third_party\detours\lib.X64\detours.lib"
$detoursX86 = Join-Path $root "third_party\detours\lib.X86\detours.lib"

Invoke-Vc "amd64" "cl /nologo /W4 /WX /EHsc /MD /utf-8 /I `"$src`" /I `"$detoursSrc`" /Fo`"$x64\\`" /Fe`"$out\process_guard.exe`" `"$src\process_guard_main.cpp`" $commonList /link `"$detoursX64`""
Invoke-Vc "amd64" "cl /nologo /W4 /WX /EHsc /MT /utf-8 /LD /I `"$src`" /I `"$detoursSrc`" /Fo`"$x64\hook\\`" /Fe`"$out\process_guard_hook_x64.dll`" `"$src\hooks.cpp`" $commonList /link /DEF:`"$src\process_guard_hook.def`" `"$detoursX64`""
Invoke-Vc "amd64" "cl /nologo /W4 /WX /EHsc /MD /utf-8 /Fo`"$x64\\`" /Fe`"$out\probe.exe`" `"$src\probe.cpp`""
Invoke-Vc "x86" "cl /nologo /W4 /WX /EHsc /MT /utf-8 /LD /I `"$src`" /I `"$detoursSrc`" /Fo`"$x86\hook\\`" /Fe`"$out\process_guard_hook_x86.dll`" `"$src\hooks.cpp`" $commonList /link /DEF:`"$src\process_guard_hook.def`" `"$detoursX86`""

foreach ($name in @("process_guard.exe", "process_guard_hook_x64.dll", "process_guard_hook_x86.dll")) {
    Copy-Item (Join-Path $out $name) (Join-Path $wheelBin $name) -Force
}
Write-Output "windows process guard binaries built"
