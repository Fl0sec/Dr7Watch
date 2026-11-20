// Benign HWSyscalls run: one 5-argument query on the current process.
#include <stdio.h>
#include "HWSyscalls.h"

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

int main(void) {
    if (!InitHWSyscalls()) {
        return 1;
    }
    NtQueryInformationProcess_t query = (NtQueryInformationProcess_t)PrepareSyscall((char*)"NtQueryInformationProcess");
    ULONG_PTR basic[6] = {0};
    ULONG length = 0;
    const NTSTATUS status = query(GetCurrentProcess(), 0 /* ProcessBasicInformation */, basic, sizeof(basic), &length);
    printf("[harness] NtQueryInformationProcess status=0x%08lx pid=%llu\n", (unsigned long)status,
           (unsigned long long)basic[4]);
    DeinitHWSyscalls();
    return status == 0 ? 0 : 3;
}
