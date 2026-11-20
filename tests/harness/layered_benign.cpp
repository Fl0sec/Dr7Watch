// Benign LayeredSyscall run: one query on the current process through the library's wrapper.
#include <stdio.h>
#include <Windows.h>
#include "HookModule.h"
#include "FuncWrappers.h"

#pragma comment(lib, "ntdll.lib")

int main(void) {
    IntializeHooks();
    PROCESS_BASIC_INFORMATION basic = {0};
    ULONG length = 0;
    const ULONG status = wrpNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &basic,
                                                      sizeof(basic), &length);
    printf("[harness] NtQueryInformationProcess status=0x%08lx pid=%llu\n", status,
           (unsigned long long)basic.UniqueProcessId);
    DestroyHooks();
    return status == 0 ? 0 : 3;
}
