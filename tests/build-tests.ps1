# Builds the test programs. HWSyscalls and LayeredSyscall carry no license, so
# they are cloned here at a pinned commit and never committed to this repository.
#
#   powershell -File tests\build-tests.ps1
#   powershell -File tests\build-tests.ps1 -PivotGate C:\src\PivotGate

param([string]$PivotGate = "")

$ErrorActionPreference = "Stop"
$tests = $PSScriptRoot
$third = Join-Path $tests "third_party"
$build = Join-Path $tests "build"
New-Item -ItemType Directory -Force $third, $build | Out-Null

$pins = @(
    @{ Name = "HWSyscalls";     Url = "https://github.com/Dec0ne/HWSyscalls";     Commit = "6bdafa651687cd26a5cb353dec8d1d2cfcae816e" },
    @{ Name = "LayeredSyscall"; Url = "https://github.com/WKL-Sec/LayeredSyscall"; Commit = "19364dd361056432fb63e52679a2c13645a383a9" }
)
foreach ($pin in $pins) {
    $dir = Join-Path $third $pin.Name
    if (-not (Test-Path $dir)) {
        git clone --quiet $pin.Url $dir
    }
    git -C $dir checkout --quiet $pin.Commit
}

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"

$hw = Join-Path $third "HWSyscalls\Src"
$ls = Join-Path $third "LayeredSyscall"
$h = Join-Path $tests "harness"
$steps = @(
    "cl /nologo /EHsc /Od /W1 /Fo:`"$build\\`" /Fe:`"$build\hwsyscalls_benign.exe`" /I `"$hw`" `"$h\hwsyscalls_benign.cpp`" `"$hw\HWSyscalls.cpp`"",
    "cl /nologo /EHsc /Od /W1 /DUNICODE /D_UNICODE /Fo:`"$build\\`" /Fe:`"$build\layered_benign.exe`" /I `"$ls`" `"$h\layered_benign.cpp`" `"$ls\HookModule.cpp`" `"$ls\FuncWrappers.cpp`" user32.lib",
    "cl /nologo /O1 /W4 /Fo:`"$build\\`" /Fe:`"$build\fp_target.exe`" `"$h\fp_target.c`""
)
if ($PivotGate -ne "") {
    # Full path: cmd may be set not to search the current directory (NoDefaultCurrentDirectoryInExePath).
    $steps += "pushd `"$PivotGate`" && call `"$PivotGate\build.bat`" && copy /y build\pivotgate_poc.exe `"$build`" >nul"
}
foreach ($step in $steps) {
    cmd /c "`"$vcvars`" >nul 2>&1 && $step" | Where-Object { $_ -match " error | warning C" }
    if ($LASTEXITCODE -ne 0) { throw "build step failed: $step" }
}
Get-ChildItem $build -Filter *.exe | Select-Object -ExpandProperty Name
