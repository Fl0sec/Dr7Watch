# Dr7Watch

Dr7Watch is a small Windows x64 sensor for hardware-breakpoint syscall
techniques: the family where a vectored exception handler arms a debug register
on an `ntdll` syscall stub, catches the `#DB` and resumes the thread somewhere
else.

It watches the one moment those techniques cannot avoid: the exception being
resumed. A vectored continue handler runs after a vectored exception handler
returns `EXCEPTION_CONTINUE_EXECUTION`, with the context that handler produced.
The exception record still says where the thread stopped. The context says
where it will resume and which debug registers will be live.

```text
[dr7watch] ARM tid=11720 dr0=ntdll!NtWriteFile+0x0 code=0xe0425001 at=KERNELBASE.dll+0xc79da
[dr7watch] REDIRECT tid=11720 from=ntdll!NtWriteFile+0x0 to=ntdll!NtWriteFile+0x12 rax=0x8
[dr7watch] summary: 1 arm, 1 redirect, 0 ssn, 0 return finding(s)
```

That is [PivotGate](https://github.com/Fl0sec/PivotGate) running under the
sensor: a private exception arms `DR0` on `NtWriteFile`, and the `#DB` at its
entry resumes on the same stub's `syscall; ret`.

## What it reports

| Finding | Condition at a resumed exception |
|---|---|
| `ARM` | An enabled execute breakpoint in `DR0`-`DR3` points into an `Nt*` stub. |
| `REDIRECT` | A single-step resumes away from an `Nt*` stub, or onto a stub's `syscall` from somewhere else. |
| `SSN` | Execution resumes on a stub's `syscall` with a service number in `RAX` that differs from the stub's own `mov eax, imm32`. |
| `RETURN` | A single-step at a stub entry resumes with a return address at `[RSP]` that no `call` instruction precedes. |

`ARM` alone is the weakest signal. `REDIRECT`, `SSN` and `RETURN` describe a
context that a debugger stepping through code does not produce.

## Results

Windows 11 x64, `ntdll` `10.0.26100.8246`, each program run under `dr7watch.exe`
by [`tests/run-matrix.ps1`](tests/run-matrix.ps1):

| Program | ARM | REDIRECT | SSN | RETURN | Program still works |
|---|---|---|---|---|---|
| PivotGate PoC | 1 | 1 | 0 | 0 | yes |
| HWSyscalls (benign harness) | 1 | 0 | 0 | 1 | yes |
| LayeredSyscall (benign harness) | 2 | 2 | 0 | 0 | yes |
| cmd, PowerShell, `dotnet --info`, Python, Node, Git | 0 | 0 | 0 | 0 | yes |
| SEH/VEH test app (500 handled exceptions of each kind) | 0 | 0 | 0 | 0 | yes |

Each technique is caught differently:

- **PivotGate** keeps the genuine stack, so `RETURN` stays quiet. The redirect
  from the stub entry to its own `syscall` gives it away.
- **HWSyscalls** does not move `RIP` when the stub is unhooked. It pushes a new
  frame whose return address is an `add rsp, 68h; ret` gadget in `kernel32`
  (`KERNEL32.DLL+0xe295` above), and nothing calls into the middle of that.
- **LayeredSyscall** leaves the stub for a benign function, traces with the trap
  flag until it is inside `ntdll`, then jumps onto the stub's `syscall`. Both
  jumps are reported. The ~975 trap-flag resumes in between are folded into
  one line.

The harnesses in [`tests/harness`](tests/harness) call one harmless query
(`NtQueryInformationProcess` on the current process) through each library.
HWSyscalls and LayeredSyscall are not redistributed: the build script clones
them at a pinned commit.

## Kernel view

[`etw/syscall_trace.c`](etw/syscall_trace.c) records `SysCallEnter` events with
user stacks for one program, in a private system-logger session that leaves the
shared NT Kernel Logger alone. [`etw/stacks.py`](etw/stacks.py) resolves the
frames from an `xperf -a dumper` file.

```powershell
powershell -File etw\capture.ps1          # elevated
xperf -i tests\results\etw\pivotgate.etl -o pivotgate.txt -a dumper
python etw\stacks.py pivotgate.txt pivotgate_poc.exe NtWriteFile
```

What the kernel recorded for the same three runs:

| Program | Frame under the syscall | What it shows |
|---|---|---|
| PivotGate | `KernelBase!WriteFile+0x8d` | A normal `WriteFile`. Nothing to separate it from a real one. |
| HWSyscalls | `kernel32!GetLogicalDrives+0x45` | The gadget at `kernel32+0xe295`, named after the nearest export. |
| LayeredSyscall | `ntdll` internals under `MessageBoxW` | Real return addresses, borrowed from an unrelated call chain. |
## Build and run

Visual Studio 2022 or later with the C++ tools, from an x64 Native Tools
Command Prompt:

```bat
build.bat
build\dr7watch.exe <program> [arguments...]
```

`dr7watch.exe` starts the program suspended, loads `dr7watch_sensor.dll` into it
with a remote `LoadLibraryW` thread, resumes it and prints what the sensor saw
once it exits. Exit code `0` means no findings, `2` means findings.

To run the test matrix:

```powershell
powershell -File tests\build-tests.ps1 -PivotGate C:\path\to\PivotGate
powershell -File tests\run-matrix.ps1
```

## How the sensor stays out of the way

The continue handler runs while the thread's hardware debug registers are still
the ones that raised the exception. My first version logged with `WriteFile`
from the handler, which walked straight into the breakpoint on `NtWriteFile`
and crashed the PivotGate run. The handler now makes no system calls: it reads
memory under SEH, writes fixed-size records into a ring buffer, and a separate
thread formats and writes them.

## Limits

- **A debugger's breakpoints show up as `ARM`.** If a debugger has a hardware
  breakpoint on an `Nt*` stub and the program's own VEH resumes an exception,
  that breakpoint is in the resumed context. These events are tagged
  `debugger=attached` (from `PEB.BeingDebugged`) and not counted. Hits the
  debugger handles itself never reach the program's handlers.
- **Only resumes through the vectored path are seen.** A handler that calls
  `NtContinue` itself, or code that edits `LdrpVectorHandlerList`, skips
  continue handlers. So does a technique that uses no exception at all.
- **In-process sensors can be removed.** Anything loaded in the target can find
  and unregister the handler. Treat this as a lab sensor and a reference for
  where the signal lives, not as an EDR.
- **No register tampering without a redirect.** TamperingSyscalls rewrites
  argument registers and MutationGate rewrites `RAX` on a breakpoint inside a
  different stub. The `SSN` rule covers the second only when execution resumes
  on a `syscall`. Neither was in the test set.
- Native x64 processes only. WoW64 is not handled.

## Prior work

- [HWSyscalls](https://github.com/Dec0ne/HWSyscalls), Dec0ne
- [LayeredSyscall](https://github.com/WKL-Sec/LayeredSyscall), White Knight Labs
- [TamperingSyscalls](https://github.com/rad9800/TamperingSyscalls), rad9800
- [MutationGate](https://github.com/senzee1984/MutationGate), senzee1984
- [Patchless AMSI bypass and VEH²](https://www.crowdstrike.com/en-us/blog/crowdstrike-investigates-threat-of-patchless-amsi-bypass-attacks/), CrowdStrike
- [ETW Threat Intelligence and hardware breakpoints](https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/), Praetorian
- [Detecting anomalous vectored exception handlers](https://www.fox-it.com/be-en/detecting-anomalous-vectored-exception-handlers-on-windows/), NCC Group / Fox-IT

## License

[MIT](LICENSE) © 2026 fl0sec
