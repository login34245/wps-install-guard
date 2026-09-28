param(
    [switch]$KeepTestBuild
)

$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$source = Join-Path $projectDirectory 'WpsInstallGuard.cs'
$manifest = Join-Path $projectDirectory 'app.manifest'
$outputDirectory = Join-Path $projectDirectory 'dist'
$releaseExe = Join-Path $outputDirectory 'WpsInstallGuard.exe'
$testExe = Join-Path $outputDirectory 'WpsInstallGuard.Test.exe'

if (-not (Test-Path -LiteralPath $compiler)) {
    throw "Компилятор .NET Framework не найден: $compiler"
}

New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

$references = @(
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Management.dll',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.Security.dll'
)

& $compiler /nologo /codepage:65001 /optimize+ /target:winexe "/win32manifest:$manifest" "/out:$releaseExe" $references $source
if ($LASTEXITCODE -ne 0) {
    throw "Не удалось собрать WpsInstallGuard.exe"
}

& $compiler /nologo /codepage:65001 /optimize+ /target:exe "/out:$testExe" $references $source
if ($LASTEXITCODE -ne 0) {
    throw "Не удалось собрать тестовую версию"
}

& $testExe --engine-test
if ($LASTEXITCODE -ne 0) {
    throw "Тесты правил распознавания не пройдены"
}

& $testExe --e2e-test
if ($LASTEXITCODE -ne 0) {
    throw "Сквозной тест блокировки не пройден"
}

& $testExe --ui-smoke-test
if ($LASTEXITCODE -ne 0) {
    throw "Проверка интерфейса не пройдена"
}

if (-not $KeepTestBuild) {
    Remove-Item -LiteralPath $testExe -Force
}

$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $releaseExe).Hash
Write-Output "Готово: $releaseExe"
Write-Output "SHA256: $hash"
