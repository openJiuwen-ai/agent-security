param(
    [Parameter(Mandatory=$true)][string]$ToolchainRoot,
    [Parameter(Mandatory=$true)][string]$DetoursRoot,
    [switch]$BuildTestClient
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$src = Join-Path $root 'src'
$out = Join-Path $root 'build'
$bin = Join-Path $root '../windows-process-guard/python/src/agent_security_dll/bin/win_amd64'
$setup = Join-Path (Resolve-Path -LiteralPath $ToolchainRoot).Path 'setup_x64.bat'
$detours = (Resolve-Path -LiteralPath $DetoursRoot).Path
if (-not (Test-Path -LiteralPath $setup)) { throw 'Missing x64 toolchain setup' }
if (-not (Test-Path -LiteralPath (Join-Path $detours 'src/detours.h'))) { throw 'Missing external Detours source' }
$commit = (& git -C $detours rev-parse HEAD).Trim()
if ($commit -ne 'e4bfd6b03e50de46b47abfbd1e46b384f0c5f833') { throw 'Use the pinned Detours v4.0.1 checkout' }
New-Item -ItemType Directory -Force -Path $out,$bin | Out-Null
# A separate nmake configuration prevents reuse of objects built without CFG.
cmd /c "`"$setup`" && set DETOURS_TARGET_PROCESSOR=X64&& cd /d `"$detours/src`" && nmake DETOURS_CONFIG=.cfg `"CC=cl /guard:cf`""
if ($LASTEXITCODE -ne 0) { throw 'Detours build failed' }
$compile = '/nologo /utf-8 /std:c17 /O2 /W4 /WX /guard:cf /MT'
$link = '/WX /GUARD:CF /DYNAMICBASE /NXCOMPAT'
cmd /c "`"$setup`" && cl $compile /DUNICODE /D_UNICODE /I`"$detours/src`" /Fo`"$out\\`" /LD `"$src/guard.c`" /link $link /OUT:`"$out/jiuwen_runtime_guard.dll`" /IMPLIB:`"$out/guard.lib`" `"$detours/lib.X64.cfg/detours.lib`" kernel32.lib user32.lib ws2_32.lib winhttp.lib dnsapi.lib"
if ($LASTEXITCODE -ne 0) { throw 'DLL Guard build failed' }
Copy-Item -LiteralPath (Join-Path $out 'jiuwen_runtime_guard.dll') -Destination $bin -Force
Copy-Item -LiteralPath (Join-Path $detours 'LICENSE.md') -Destination (Join-Path $bin 'LICENSE.Detours.txt') -Force
$sources = [ordered]@{}
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    Get-ChildItem -LiteralPath $src -Filter '*.c' | Sort-Object Name | ForEach-Object {
        $text = [IO.File]::ReadAllText($_.FullName).Replace("`r`n","`n")
        $sources[$_.Name] = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant()
    }
} finally { $sha.Dispose() }
$manifest = [ordered]@{protocol=4;architecture='x64';hook_backend='detours';detours='v4.0.1';detours_commit=$commit;
    sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $bin 'jiuwen_runtime_guard.dll')).Hash.ToLowerInvariant();
    source_encoding='utf8-lf';sources=$sources}
[IO.File]::WriteAllText((Join-Path $bin 'jiuwen_runtime_guard.manifest.json'),($manifest|ConvertTo-Json -Depth 4),[Text.UTF8Encoding]::new($false))
if ($BuildTestClient) {
    cmd /c "`"$setup`" && cl $compile /Fo`"$out/client.obj`" /Fe`"$out/client.exe`" `"$root/tests/dll_guard_client.c`" /link $link kernel32.lib ws2_32.lib winhttp.lib dnsapi.lib"
    if ($LASTEXITCODE -ne 0) { throw 'DLL integration client build failed' }
}
Write-Output 'Windows DLL Guard built with Detours; protocol 4, x64'
