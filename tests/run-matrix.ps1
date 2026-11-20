# Runs every test program under dr7watch and writes one log per case to tests\results.
# Expected: each technique gives findings and still completes; every baseline gives none.

$ErrorActionPreference = "Continue"
$root = Split-Path $PSScriptRoot -Parent
$watch = Join-Path $root "build\dr7watch.exe"
$bin = Join-Path $PSScriptRoot "build"
$h = Join-Path $PSScriptRoot "harness"
$results = Join-Path $PSScriptRoot "results"
New-Item -ItemType Directory -Force $results | Out-Null

$cases = @(
    @{ Name = "pivotgate";      Expect = "finding"; Cmd = @("$bin\pivotgate_poc.exe") },
    @{ Name = "hwsyscalls";     Expect = "finding"; Cmd = @("$bin\hwsyscalls_benign.exe") },
    @{ Name = "layeredsyscall"; Expect = "finding"; Cmd = @("$bin\layered_benign.exe") },
    @{ Name = "cmd";            Expect = "clean";   Cmd = @("$env:SystemRoot\System32\cmd.exe", "/c", "dir", "$env:SystemRoot") },
    @{ Name = "powershell";     Expect = "clean";   Cmd = @("$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe", "-NoProfile", "-Command", "Get-ChildItem `$env:SystemRoot\System32 | Out-Null; try { throw 'x' } catch {}; exit 0") },
    @{ Name = "seh-veh-app";    Expect = "clean";   Cmd = @("$bin\fp_target.exe", "500") }
)
$optional = @(
    @{ Name = "dotnet"; Exe = "dotnet";  Args = @("--info") },
    @{ Name = "python"; Exe = "python";  Args = @("$h\fp_python.py") },
    @{ Name = "node";   Exe = "node";    Args = @("$h\fp_node.js") },
    @{ Name = "git";    Exe = "git";     Args = @("--version") }
)
foreach ($o in $optional) {
    $exe = (Get-Command $o.Exe -ErrorAction SilentlyContinue).Source
    if ($exe) { $cases += @{ Name = $o.Name; Expect = "clean"; Cmd = @($exe) + $o.Args } }
}

$failed = 0
foreach ($case in $cases) {
    if (-not (Test-Path $case.Cmd[0])) {
        "{0,-15} skipped (not built)" -f $case.Name
        continue
    }
    $log = Join-Path $results "$($case.Name).txt"
    & $watch @($case.Cmd) *> $log
    $code = $LASTEXITCODE
    $exited = (Select-String -Path $log -Pattern "pid exited with (0x[0-9a-f]+)").Matches.Groups[1].Value
    $summary = (Select-String -Path $log -Pattern "summary: (.*)").Matches.Groups[1].Value
    $got = if ($code -eq 2) { "finding" } elseif ($code -eq 0) { "clean" } else { "error" }
    $ok = $got -eq $case.Expect -and $exited -eq "0x0"
    if (-not $ok) { $failed++ }
    "{0,-15} expect={1,-7} got={2,-7} exit={3,-10} {4} {5}" -f $case.Name, $case.Expect, $got, $exited, $summary, $(if ($ok) { "ok" } else { "FAIL" })
}
exit $failed
