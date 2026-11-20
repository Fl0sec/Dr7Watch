// syscall_trace: record kernel syscall-entry events with user stacks while one program runs.
//
//   syscall_trace.exe <output.etl> <program> [arguments...]      (run elevated)
//
// It starts a private SystemTraceProvider session in system-logger mode, so it does
// not need, or disturb, the shared NT Kernel Logger. Decode the file with
//   xperf -i out.etl -o out.txt -a dumper
// and read the SysCallEnter rows with their Stack rows.

#define INITGUID
#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <evntrace.h>

#define SESSION_NAME L"Dr7WatchSyscalls"

// PerfInfo class: SysCallEnter is event type 51.
DEFINE_GUID(PerfInfoGuid, 0xce1dbfb4, 0x137e, 0x4da6, 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc);
// SystemTraceProvider group masks used with TraceSystemTraceEnableFlagsInfo.
#define PERF_SYSCALL 0x00000080u
#define PERF_PROCESS 0x00000001u
#define PERF_THREAD 0x00000002u
#define PERF_LOADER 0x00000004u

typedef struct SESSION {
    EVENT_TRACE_PROPERTIES properties;
    wchar_t name[64];
    wchar_t file[MAX_PATH];
} SESSION;

static void stop_session(void) {
    SESSION session = {0};
    session.properties.Wnode.BufferSize = sizeof(session);
    session.properties.LoggerNameOffset = offsetof(SESSION, name);
    session.properties.LogFileNameOffset = offsetof(SESSION, file);
    ControlTraceW(0, SESSION_NAME, &session.properties, EVENT_TRACE_CONTROL_STOP);
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        fwprintf(stderr, L"usage: syscall_trace.exe <output.etl> <program> [arguments...]\n");
        return 1;
    }

    stop_session(); // a leftover from an interrupted run

    SESSION session = {0};
    session.properties.Wnode.BufferSize = sizeof(session);
    session.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    session.properties.Wnode.ClientContext = 1; // QPC timestamps
    session.properties.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_SYSTEM_LOGGER_MODE;
    session.properties.BufferSize = 1024;
    session.properties.MinimumBuffers = 64;
    session.properties.MaximumBuffers = 256;
    session.properties.LoggerNameOffset = offsetof(SESSION, name);
    session.properties.LogFileNameOffset = offsetof(SESSION, file);
    wcscpy_s(session.file, MAX_PATH, argv[1]);

    TRACEHANDLE handle = 0;
    ULONG status = StartTraceW(&handle, SESSION_NAME, &session.properties);
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr, L"StartTrace failed: %lu (run elevated)\n", status);
        return 1;
    }

    // Group masks: index 0 holds the classic kernel flags.
    ULONG masks[8] = {PERF_SYSCALL | PERF_PROCESS | PERF_THREAD | PERF_LOADER};
    status = TraceSetInformation(handle, TraceSystemTraceEnableFlagsInfo, masks, sizeof(masks));
    if (status == ERROR_SUCCESS) {
        CLASSIC_EVENT_ID stacks[1] = {{PerfInfoGuid, 51, {0}}};
        status = TraceSetInformation(handle, TraceStackTracingInfo, stacks, sizeof(stacks));
    }
    if (status != ERROR_SUCCESS) {
        fwprintf(stderr, L"TraceSetInformation failed: %lu\n", status);
        stop_session();
        return 1;
    }

    wchar_t command[4096] = L"";
    for (int i = 2; i < argc; ++i) {
        if (i > 2) {
            wcscat_s(command, 4096, L" ");
        }
        const int quote = wcschr(argv[i], L' ') != NULL;
        if (quote) {
            wcscat_s(command, 4096, L"\"");
        }
        wcscat_s(command, 4096, argv[i]);
        if (quote) {
            wcscat_s(command, 4096, L"\"");
        }
    }

    STARTUPINFOW startup = {.cb = sizeof(startup)};
    PROCESS_INFORMATION child = {0};
    int result = 1;
    if (CreateProcessW(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &child)) {
        wprintf(L"[trace] pid %lu\n", child.dwProcessId);
        WaitForSingleObject(child.hProcess, INFINITE);
        DWORD code = 0;
        GetExitCodeProcess(child.hProcess, &code);
        wprintf(L"[trace] exited with 0x%lx\n", code);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        result = 0;
    } else {
        fwprintf(stderr, L"CreateProcess failed: %lu\n", GetLastError());
    }

    stop_session();
    wprintf(L"[trace] wrote %ls\n", argv[1]);
    return result;
}
