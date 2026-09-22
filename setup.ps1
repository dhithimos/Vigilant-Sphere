param([switch]$CreateSuperuser)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
if (-not (Test-Path -LiteralPath '.venv/Scripts/python.exe')) {
    py -3 -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.10 or newer is required.' }
}
& ./.venv/Scripts/python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& ./.venv/Scripts/python.exe manage.py migrate
if ($LASTEXITCODE -ne 0) { throw 'Database migration failed.' }
& ./.venv/Scripts/python.exe manage.py check
if ($LASTEXITCODE -ne 0) { throw 'Django checks failed.' }
if ($CreateSuperuser) { & ./.venv/Scripts/python.exe manage.py createsuperuser }
Write-Host 'Start: ./.venv/Scripts/python.exe manage.py runserver 127.0.0.1:8000'
