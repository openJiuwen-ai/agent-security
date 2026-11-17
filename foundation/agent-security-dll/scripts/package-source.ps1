[CmdletBinding()]
param([Parameter(Mandatory)][string]$Destination)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
$root = (Resolve-Path "$PSScriptRoot/..").Path
$files = @('LICENSE','NOTICE','README.md','pyproject.toml','setup.cfg')
$trees = @{
    'native/windows' = @('.c','.cpp','.h','.def','.md')
    'tests' = @('.c','.cpp','.py','.md')
    'third_party' = @('.md','.txt')
    'src/agent_security_dll' = @('.py')
    'scripts' = @('.ps1','.py')
}
foreach ($tree in $trees.Keys) {
    $allowed = $trees[$tree]
    $files += Get-ChildItem -File -Recurse -LiteralPath "$root/$tree" |
        Where-Object { $allowed -contains $_.Extension } |
        ForEach-Object { $_.FullName.Substring($root.Length + 1) }
}
$path = [IO.Path]::GetFullPath($Destination)
$stream = [IO.File]::Open($path, 'CreateNew', 'Write', 'None')
try {
    $zip = [IO.Compression.ZipArchive]::new($stream, 'Create', $true)
    try {
        foreach ($file in ($files | Sort-Object)) {
            $bytes = [IO.File]::ReadAllBytes("$root/$file")
            if ($bytes -contains 0) { throw "Unexpected binary input $file" }
            $entry = $zip.CreateEntry($file.Replace([IO.Path]::DirectorySeparatorChar, '/'))
            $entry.LastWriteTime = [DateTimeOffset]'2000-01-01T00:00:00Z'
            $writer = $entry.Open()
            try { $writer.Write($bytes, 0, $bytes.Length) } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose() }
} catch {
    $stream.Dispose()
    [IO.File]::Delete($path)
    throw
} finally { $stream.Dispose() }
