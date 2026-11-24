[CmdletBinding()]
param([string]$BuildDirectory = (Join-Path $PSScriptRoot '../build'),
      [Parameter(Mandatory)][string]$Destination, [string]$Python = 'python')
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
$out = [IO.Directory]::CreateDirectory($Destination).FullName
$stage = [IO.Directory]::CreateDirectory((Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N')))).FullName
try {
    foreach ($file in 'pyproject.toml','setup.cfg','NOTICE','LICENSE','README.md') {
        Copy-Item -LiteralPath "$root/$file" -Destination $stage
    }
    $package = [IO.Directory]::CreateDirectory("$stage/src/agent_security_dll").FullName
    Copy-Item -LiteralPath "$root/src/agent_security_dll/__init__.py" -Destination $package
    $licenses = [IO.Directory]::CreateDirectory("$stage/third_party").FullName
    Copy-Item -LiteralPath "$root/third_party/LICENSE.Detours.txt" -Destination $licenses
    foreach ($arch in 'x64','x86') {
        $bin = [IO.Directory]::CreateDirectory("$package/bin/$arch").FullName
        foreach ($name in 'agent_security_guard.dll','agent_security_guard.manifest.json') {
            Copy-Item -LiteralPath "$BuildDirectory/$arch/$name" -Destination $bin
        }
    }
    Copy-Item -LiteralPath "$BuildDirectory/x64/process_guard.exe" -Destination "$package/bin/x64"
    & $Python -c "import sys;sys.path.insert(0,sys.argv[1]);from agent_security_dll import validated_library;[validated_library(a) for a in ('x86','x64')]" "$stage/src"
    if ($LASTEXITCODE) { throw 'Local bundle validation failed' }
    & $Python -m build --wheel --no-isolation --outdir $out $stage
    if ($LASTEXITCODE) { throw 'Local wheel build failed' }
} finally {
    if ([IO.Path]::GetDirectoryName($stage) -eq [IO.Path]::GetTempPath().TrimEnd([IO.Path]::DirectorySeparatorChar)) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
}
