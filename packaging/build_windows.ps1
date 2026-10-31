# Windows-only opt-in build of the read-only REA Inspector.
# No original installer, drivers, services or Windows 7 VM are executed.
[CmdletBinding()]
param(
    [ValidateSet("win7-x86", "win7-x64", "win10plus")]
    [string]$Target = "win10plus"
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Push-Location $root
try {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw "Python nao instalado neste Windows."
    }
    $infoText = & python -c "import json,struct,sys;print(json.dumps({'version':list(sys.version_info[:2]),'bits':struct.calcsize('P')*8,'platform':sys.platform}))"
    if ($LASTEXITCODE -ne 0) { throw "Falha ao consultar Python." }
    $info = $infoText | ConvertFrom-Json
    if ($info.platform -ne "win32") { throw "Build de executavel Windows exige Windows." }
    if ($Target.StartsWith("win7")) {
        if ($info.version[0] -ne 3 -or $info.version[1] -ne 8) {
            throw "Candidato a Win7 exige Python 3.8 em ambiente isolado."
        }
        $expectedBits = if ($Target -eq "win7-x86") { 32 } else { 64 }
        if ($info.bits -ne $expectedBits) {
            throw "Python com arquitetura incorreta (esperado $expectedBits bits)."
        }
    }
    $pyiVersion = & python -m PyInstaller --version
    if ($LASTEXITCODE -ne 0) { throw "Instale PyInstaller na venv antes do build." }
    if ($Target.StartsWith("win7") -and $pyiVersion.Trim() -ne "5.13.2") {
        throw "Para candidato Win7, use PyInstaller 5.13.2; ainda exige teste real."
    }
    $dist = Join-Path $root ("out\release\" + $Target)
    $build = Join-Path $root ("out\work\" + $Target)
    $spec = Join-Path $root ("out\spec\" + $Target)
    New-Item -ItemType Directory -Force -Path $dist,$build,$spec | Out-Null
    $buildArgs = @("-m","PyInstaller","--noconfirm","--clean","--noupx",
        "--onedir","--console","--name","REA-Inspector",
        "--distpath",$dist,"--workpath",$build,"--specpath",$spec,
        (Join-Path $root "rea_diagnostic.py"))
    & python @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "Falha no empacotamento." }
    $exe = Join-Path $dist "REA-Inspector\REA-Inspector.exe"
    if (-not (Test-Path -LiteralPath $exe)) { throw "Executavel nao encontrado." }
    & $exe selfcheck
    if ($LASTEXITCODE -ne 0) { throw "Smoke test selfcheck falhou." }
    & $exe --help
    if ($LASTEXITCODE -ne 0) { throw "Smoke test ajuda falhou." }
    & python -c "import hashlib,sys;h=hashlib.sha256();p=sys.argv[1];f=open(p,'rb');[(h.update(b)) for b in iter(lambda:f.read(1048576),b'')];f.close();print('SHA256',h.hexdigest())" $exe
    if ($LASTEXITCODE -ne 0) { throw "Falha no SHA256 do exe." }
    Write-Host "Empacotamento e inicializacao OK: $exe"
    Write-Host "Distribua a pasta REA-Inspector inteira. Win7 ainda NAO validado."
} finally {
    Pop-Location
}
