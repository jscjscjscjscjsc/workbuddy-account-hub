$ErrorActionPreference = 'Stop'
$env:PYTHONUTF8 = '1'
Push-Location $PSScriptRoot
try {
    python -m PyInstaller --noconfirm --clean --onedir --noconsole --contents-directory . --name WorkBuddyAccountHub --paths server --hidden-import server --hidden-import vault --hidden-import lifecycle --hidden-import phone_login --add-data 'server/server.py;server' --add-data 'server/vault.py;server' --add-data 'server/lifecycle.py;server' --add-data 'server/phone_login.py;server' --add-data 'server/wbkey.js;server' --add-data 'index.html;.' --add-data 'launch.py;.' desktop.py
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed' }
    foreach ($name in @('README.md', 'LICENSE', '一键启动.cmd')) {
        Copy-Item -LiteralPath $name -Destination 'dist\WorkBuddyAccountHub'
    }
    Write-Host 'Build output: dist\WorkBuddyAccountHub'
} finally { Pop-Location }
