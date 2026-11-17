[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DetoursRoot,
    [string]$ToolchainRoot,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot '../build'),
    [switch]$BuildTestClient
)
$ErrorActionPreference = 'Stop'
$pkg = (Resolve-Path "$PSScriptRoot/..").Path
$src = "$pkg/native/windows"
$dep = (Resolve-Path -LiteralPath $DetoursRoot).Path
$commit = git -C $dep rev-parse HEAD
if ($LASTEXITCODE -or $commit -ne 'e4bfd6b03e50de46b47abfbd1e46b384f0c5f833') { throw 'Expected the pinned Detours v4.0.1 checkout' }
$out = [IO.Directory]::CreateDirectory($OutputDirectory).FullName
if (!$ToolchainRoot) {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $install = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (!$install) { throw 'MSVC x86 and x64 tools are required' }
} else {
    $ToolchainRoot = (Resolve-Path -LiteralPath $ToolchainRoot).Path
}

function Invoke-Compiler([string]$command) {
    & cmd.exe /d /c "call $setup && $command"
    if ($LASTEXITCODE) { throw "Build failed ($arch): $command" }
}
foreach ($arch in 'x64','x86') {
    $setup = if ($ToolchainRoot) { "`"$ToolchainRoot/setup_$arch.bat`"" } else {
        "`"$install/VC/Auxiliary/Build/vcvarsall.bat`" $arch"
    }
    $work = [IO.Directory]::CreateDirectory("$out/obj/$arch").FullName
    $bundle = [IO.Directory]::CreateDirectory("$out/$arch").FullName
    $lib = "`"$dep/lib.$($arch.ToUpperInvariant()).cfg/detours.lib`""
    Invoke-Compiler "cd /d `"$dep/src`" && nmake /NOLOGO DETOURS_TARGET_PROCESSOR=$($arch.ToUpperInvariant()) DETOURS_CONFIG=.cfg `"CC=cl /guard:cf`""
    $inc = @("$src/include","$src/file","$src/network","$src/guard","$dep/src") | ForEach-Object { "/I`"$_`"" }
    $flags = "/nologo /utf-8 /O2 /MT /guard:cf /DUNICODE /D_UNICODE $inc"
    $libs = "$lib shell32.lib advapi32.lib user32.lib kernel32.lib ws2_32.lib winhttp.lib wininet.lib dnsapi.lib ole32.lib uuid.lib"
    Push-Location -LiteralPath $work
    try {
        Invoke-Compiler "cl $flags /W3 /std:c17 /c `"$src/softdelete/softdelete.c`""
        Invoke-Compiler "cl $flags /W4 /WX /EHsc /c `"$src/softdelete/recycle_item.cpp`""
        $objects = 'file_hooks.obj'
        $exports = "/DEF:`"$src/guard/guard.def`""
        Invoke-Compiler "cl $flags /W4 /WX /std:c17 /c `"$src/file/file_hooks.c`" `"$src/guard/guard.c`""
        Invoke-Compiler "link /nologo /DLL /GUARD:CF /DYNAMICBASE /NXCOMPAT $exports /OUT:`"$bundle/agent_security_guard.dll`" guard.obj softdelete.obj recycle_item.obj $objects $libs"
        if ($BuildTestClient -and $arch -eq 'x86') {
            Invoke-Compiler "cl $flags /W4 /WX /EHsc `"$pkg/tests/probe.cpp`" /Fe:`"$out/probe_x86.exe`""
            Invoke-Compiler "cl $flags /W4 /WX /std:c17 `"$pkg/tests/x86_session_client.c`" softdelete.obj recycle_item.obj $objects /Fe:`"$out/session_client_x86.exe`" /link $libs"
        }
        if ($BuildTestClient -and $arch -eq 'x64') {
            Invoke-Compiler "cl $flags /W4 /WX /UUNICODE /U_UNICODE /std:c17 `"$pkg/tests/dll_guard_client.c`" /Fe:`"$out/client.exe`" /link $libs"
            Invoke-Compiler "cl $flags /W4 /WX /EHsc `"$pkg/tests/probe.cpp`" /Fe:`"$out/probe.exe`""
        }
        $caps = @('file','process','network','soft_delete','operation_results')
        $caps += 'standalone_recovery'
        $manifest = [ordered]@{protocol=13;architecture=$arch;platform='windows';host_architecture='x64';
            target_architectures=@('x64','x86');capabilities=$caps;hook_backend='detours';detours_commit=$commit;
            sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath "$bundle/agent_security_guard.dll").Hash.ToLowerInvariant()}
        [IO.File]::WriteAllText("$bundle/agent_security_guard.manifest.json",($manifest|ConvertTo-Json))
    } finally { Pop-Location }
}
