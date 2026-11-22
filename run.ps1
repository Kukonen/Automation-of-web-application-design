param([int]$Port = 8080)
$ErrorActionPreference = 'Stop'
$projectRoot = $PSScriptRoot
$runtimePackages = Join-Path $env:ProgramFiles 'WindowsApps'
$bundledPython = Get-ChildItem -LiteralPath $runtimePackages -Directory -Filter 'OpenAI.CodexPrimaryRuntime*' -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'dependencies\python\python.exe' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Last 1
$projectPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $projectPython) {
    $selectedPython = $projectPython
} elseif ($bundledPython) {
    $selectedPython = $bundledPython
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $selectedPython = (Get-Command python).Source
} else {
    throw 'Install Python 3.11 or later and run this script again.'
}
Push-Location -LiteralPath $projectRoot
try {
    & $selectedPython -c 'import PIL' 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $selectedPython -m venv '.venv'
        if ($LASTEXITCODE -ne 0) { throw 'Could not create virtual environment' }
        $selectedPython = $projectPython
        & $selectedPython -m pip install -r 'requirements.txt'
        if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
    }
    & $selectedPython 'app.py' --host '127.0.0.1' --port $Port --demo
} finally {
    Pop-Location
}
