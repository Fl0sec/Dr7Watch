# Records one syscall-entry trace per test program. Run elevated, after
# tests\build-tests.ps1. Decoding (decode.ps1) does not need elevation.

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$trace = Join-Path $root "build\syscall_trace.exe"
$bin = Join-Path $root "tests\build"
$out = Join-Path $root "tests\results\etw"
New-Item -ItemType Directory -Force $out | Out-Null

$cases = [ordered]@{
    "pivotgate"      = "$bin\pivotgate_poc.exe"
    "hwsyscalls"     = "$bin\hwsyscalls_benign.exe"
    "layeredsyscall" = "$bin\layered_benign.exe"
    "seh-veh-app"    = "$bin\fp_target.exe"
}
foreach ($name in $cases.Keys) {
    & $trace (Join-Path $out "$name.etl") $cases[$name] *> (Join-Path $out "$name.run.txt")
    "{0,-15} {1}" -f $name, (Get-Content (Join-Path $out "$name.run.txt") -Tail 1)
}
