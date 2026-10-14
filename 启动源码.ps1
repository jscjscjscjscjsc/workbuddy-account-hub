$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
$taskPython = $null
$bundled = Join-Path $env:USERPROFILE '.workbuddy\binaries\python\versions'
if (Test-Path -LiteralPath $bundled) {
    $taskPython = Get-ChildItem -LiteralPath $bundled -Directory |
        Sort-Object LastWriteTime -Descending |
        ForEach-Object { Join-Path $_.FullName 'python.exe' } |
        Where-Object { Test-Path -LiteralPath $_ } |
        Select-Object -First 1
}
if (-not $taskPython) {
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command -and $command.Source -notlike '*\WindowsApps\*') { $taskPython = $command.Source }
}
if (-not $taskPython) {
    Write-Host '未找到 Python。请下载 Releases 中的 Windows 可运行包，解压后打开 WorkBuddyAccountHub.exe。'
    exit 1
}
& $taskPython -X utf8 (Join-Path $PSScriptRoot 'launch.py')
exit $LASTEXITCODE
