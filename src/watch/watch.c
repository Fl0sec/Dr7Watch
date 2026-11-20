// dr7watch: start a program with the Dr7Watch sensor loaded, then report what it saw.
//
//   dr7watch.exe <program> [arguments...]
//
// The program is created suspended, the sensor DLL next to dr7watch.exe is
// loaded into it through a remote LoadLibraryW thread, and the main thread is
// resumed. Exit code: 0 no findings, 2 findings, 1 setup error.

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>

static bool dw_sensor_path(wchar_t* out, DWORD size) {
    DWORD length = GetModuleFileNameW(NULL, out, size);
    if (length == 0 || length >= size) {
        return false;
    }
    wchar_t* slash = wcsrchr(out, L'\\');
    if (slash == NULL) {
        return false;
    }
    slash[1] = L'\0';
    return wcscat_s(out, size, L"dr7watch_sensor.dll") == 0 &&
           GetFileAttributesW(out) != INVALID_FILE_ATTRIBUTES;
}

static bool dw_load_sensor(HANDLE process, const wchar_t* dll) {
    const SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote == NULL) {
        return false;
    }

    bool loaded = false;
    if (WriteProcessMemory(process, remote, dll, bytes, NULL)) {
        // kernel32 has the same base in every process of this boot session.
        const LPTHREAD_START_ROUTINE load =
            (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        HANDLE thread = CreateRemoteThread(process, NULL, 0, load, remote, 0, NULL);
        if (thread != NULL) {
            DWORD module = 0;
            WaitForSingleObject(thread, INFINITE);
            loaded = GetExitCodeThread(thread, &module) && module != 0;
            CloseHandle(thread);
        }
    }
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    return loaded;
}

static int dw_report(const wchar_t* log_path) {
    FILE* log = NULL;
    if (_wfopen_s(&log, log_path, L"rb") != 0 || log == NULL) {
        fprintf(stderr, "[dr7watch] no sensor output\n");
        return 1;
    }

    int arms = 0;
    int redirects = 0;
    int returns = 0;
    int ssns = 0;
    int repeats = 0;
    int debugger_arms = 0;
    bool ready = false;
    // A traced thread resumes many times with the same breakpoint live: report it once.
    static char seen[128][200];
    int seen_count = 0;
    char line[600];
    while (fgets(line, sizeof(line), log) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "READY ", 6) == 0) {
            ready = true;
            continue;
        }
        if (strncmp(line, "ARM ", 4) == 0) {
            const char* code = strstr(line, " code=");
            const size_t key = code != NULL ? (size_t)(code - line) : strlen(line);
            bool repeat = false;
            for (int i = 0; i < seen_count && !repeat; ++i) {
                repeat = strlen(seen[i]) == key && strncmp(seen[i], line, key) == 0;
            }
            if (repeat) {
                ++repeats;
                continue;
            }
            if (seen_count < 128 && key < sizeof(seen[0])) {
                memcpy(seen[seen_count], line, key);
                seen[seen_count++][key] = '\0';
            }
        }
        if (strncmp(line, "ARM ", 4) == 0 && strstr(line, " debugger=attached") != NULL) {
            ++debugger_arms; // the debugger's own breakpoint, visible in the app's resumed context
            printf("[dr7watch] %s\n", line);
            continue;
        }
        arms += strncmp(line, "ARM ", 4) == 0;
        redirects += strncmp(line, "REDIRECT ", 9) == 0;
        returns += strncmp(line, "RETURN ", 7) == 0;
        ssns += strncmp(line, "SSN ", 4) == 0;
        printf("[dr7watch] %s\n", line);
    }
    fclose(log);

    if (!ready) {
        fprintf(stderr, "[dr7watch] the sensor never initialized\n");
        return 1;
    }
    if (debugger_arms != 0) {
        printf("[dr7watch] %d breakpoint(s) seen while a debugger was attached (not counted)\n", debugger_arms);
    }
    if (repeats != 0) {
        printf("[dr7watch] (%d more resumes with an already reported breakpoint live)\n", repeats);
    }
    printf("[dr7watch] summary: %d arm, %d redirect, %d ssn, %d return finding(s)\n", arms, redirects, ssns,
           returns);
    return arms + redirects + ssns + returns == 0 ? 0 : 2;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: dr7watch.exe <program> [arguments...]\n");
        return 1;
    }

    wchar_t sensor[MAX_PATH];
    if (!dw_sensor_path(sensor, MAX_PATH)) {
        fprintf(stderr, "[dr7watch] dr7watch_sensor.dll must sit next to dr7watch.exe\n");
        return 1;
    }

    wchar_t log_path[MAX_PATH];
    wchar_t temp[MAX_PATH];
    if (GetTempPathW(MAX_PATH, temp) == 0 || GetTempFileNameW(temp, L"dr7", 0, log_path) == 0 ||
        !SetEnvironmentVariableW(L"DR7WATCH_LOG", log_path)) {
        fprintf(stderr, "[dr7watch] cannot create the sensor log\n");
        return 1;
    }

    // Rebuild the command line from the program onwards, quoting arguments that need it.
    wchar_t command[4096] = L"";
    for (int i = 1; i < argc; ++i) {
        if (i > 1) {
            wcscat_s(command, 4096, L" ");
        }
        const bool quote = argv[i][0] == L'\0' || wcspbrk(argv[i], L" \t") != NULL;
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
    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child)) {
        fprintf(stderr, "[dr7watch] CreateProcess failed: %lu\n", GetLastError());
        DeleteFileW(log_path);
        return 1;
    }

    if (!dw_load_sensor(child.hProcess, sensor)) {
        fprintf(stderr, "[dr7watch] could not load the sensor into pid %lu\n", child.dwProcessId);
        TerminateProcess(child.hProcess, 1);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        DeleteFileW(log_path);
        return 1;
    }

    printf("[dr7watch] watching pid %lu\n", child.dwProcessId);
    fflush(stdout);
    ResumeThread(child.hThread);
    WaitForSingleObject(child.hProcess, INFINITE);

    DWORD exit_code = 0;
    GetExitCodeProcess(child.hProcess, &exit_code);
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
    printf("[dr7watch] pid exited with 0x%lx\n", exit_code);

    const int result = dw_report(log_path);
    DeleteFileW(log_path);
    return result;
}
