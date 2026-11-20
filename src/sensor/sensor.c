// Dr7Watch sensor: loaded into a process, it watches how exceptions are resumed.
//
// A vectored continue handler runs after a vectored exception handler returns
// EXCEPTION_CONTINUE_EXECUTION, with the context that handler produced. That is
// the one place in user mode where the redirect itself is visible: the
// exception record still holds the address that faulted, and the context holds
// where execution will resume and which debug registers will be live.
//
// The handler runs while the thread's hardware debug registers are still the
// ones that raised the exception. A system call made from it can land on the
// breakpoint being investigated, so the handler makes none: it reads memory
// under SEH, stores raw events in a ring, and a separate thread formats them.

#include "stubs.h"

#include <intrin.h>
#include <stdio.h>
#include <string.h>

#define DW_RING 1024u

typedef enum DW_KIND {
    DW_ARM = 1,
    DW_REDIRECT,
    DW_SSN,
    DW_RETURN,
} DW_KIND;

typedef struct DW_EVENT {
    volatile LONG ready;
    DW_KIND kind;
    DWORD tid;
    DWORD code;
    uint32_t slot;
    uint64_t a; // ARM: breakpoint, REDIRECT/SSN/RETURN: exception address
    uint64_t b; // ARM: exception address, REDIRECT: resume, SSN: stub ssn, RETURN: return address
    uint64_t c; // ARM: debugger present, REDIRECT/SSN: rax
} DW_EVENT;

static DW_STUB_MAP g_stubs;
static HANDLE g_log = INVALID_HANDLE_VALUE;
static PVOID g_continue_handler;
static DW_EVENT g_ring[DW_RING];
static volatile LONG g_produced;
static LONG g_consumed;
static volatile LONG g_dropped;
static volatile LONG g_stop;
static HANDLE g_flusher;
static CRITICAL_SECTION g_flush_lock;

// ---- handler side: no system calls below this line -------------------------

static void dw_record(DW_KIND kind, DWORD code, uint32_t slot, uint64_t a, uint64_t b, uint64_t c) {
    const LONG index = InterlockedIncrement(&g_produced) - 1;
    if (index - g_consumed >= (LONG)DW_RING) {
        InterlockedIncrement(&g_dropped);
        return;
    }
    DW_EVENT* event = &g_ring[(ULONG)index % DW_RING];
    event->kind = kind;
    event->tid = GetCurrentThreadId();
    event->code = code;
    event->slot = slot;
    event->a = a;
    event->b = b;
    event->c = c;
    InterlockedExchange(&event->ready, 1);
}

static bool dw_read(uintptr_t address, void* out, size_t size) {
    __try {
        memcpy(out, (const void*)address, size);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// True when the bytes before a return address end in a call instruction.
static bool dw_call_precedes(uintptr_t ret) {
    uint8_t b[8];
    if (ret < sizeof(b) || !dw_read(ret - sizeof(b), b, sizeof(b))) {
        return false;
    }
    const uint8_t* p = b + sizeof(b); // p[-1] is the byte just before ret
    if (p[-5] == 0xE8) {
        return true; // call rel32
    }
    if (p[-6] == 0xFF && (p[-5] & 0x38) == 0x10) {
        return true; // call [rip+disp32], call [reg+disp32]
    }
    if (p[-2] == 0xFF && (p[-1] & 0xF8) == 0xD0) {
        return true; // call reg
    }
    if (p[-3] == 0xFF && (p[-2] & 0x38) == 0x10) {
        return true; // call [reg+disp8], call [reg+reg]
    }
    if (p[-3] >= 0x40 && p[-3] <= 0x4F && p[-2] == 0xFF && (p[-1] & 0xF8) == 0xD0) {
        return true; // call r8-r15
    }
    if (p[-4] == 0xFF && (p[-3] & 0x38) == 0x10) {
        return true; // call [reg+reg+disp8]
    }
    if (p[-7] == 0xFF && (p[-6] & 0x38) == 0x10) {
        return true; // call [reg+reg+disp32]
    }
    return false;
}

// PEB.BeingDebugged, read without a call. A debugger's own breakpoints are live in every
// context the process resumes, so an ARM seen under a debugger is reported as such.
static bool dw_debugger_present(void) {
    return ((const volatile uint8_t*)__readgsqword(0x60))[2] != 0;
}

static void dw_check_armed(const EXCEPTION_RECORD* record, const CONTEXT* context) {
    const uint64_t debugger = dw_debugger_present() ? 1 : 0;
    const DWORD64 slots[4] = {context->Dr0, context->Dr1, context->Dr2, context->Dr3};
    for (uint32_t i = 0; i < 4; ++i) {
        const bool enabled = (context->Dr7 & (3ull << (i * 2))) != 0;
        const bool execute = ((context->Dr7 >> (16 + i * 4)) & 3) == 0;
        if (enabled && execute && dw_stub_containing(&g_stubs, (uintptr_t)slots[i]) != NULL) {
            dw_record(DW_ARM, record->ExceptionCode, i, slots[i], (uint64_t)record->ExceptionAddress, debugger);
        }
    }
}

static void dw_check_single_step(const EXCEPTION_RECORD* record, const CONTEXT* context) {
    if (record->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return;
    }
    const uintptr_t at = (uintptr_t)record->ExceptionAddress;
    const uintptr_t rip = (uintptr_t)context->Rip;
    const DW_STUB* stub = dw_stub_containing(&g_stubs, at);
    const DW_STUB* target = dw_stub_containing(&g_stubs, rip);
    uint8_t resume[2] = {0};
    const bool onto_syscall = target != NULL && dw_read(rip, resume, 2) && resume[0] == 0x0F && resume[1] == 0x05;

    // Moved away from a stub, or moved onto a syscall instruction from anywhere else.
    if (rip != at && (stub != NULL || onto_syscall)) {
        dw_record(DW_REDIRECT, record->ExceptionCode, 0, at, rip, context->Rax);
    }

    // Resuming on a stub's syscall with another service number in RAX.
    uint8_t entry[8];
    if (onto_syscall && dw_read(g_stubs.base + target->rva, entry, sizeof(entry)) && entry[0] == 0x4C &&
        entry[1] == 0x8B && entry[2] == 0xD1 && entry[3] == 0xB8) {
        uint32_t ssn;
        memcpy(&ssn, entry + 4, sizeof(ssn));
        if ((uint32_t)context->Rax != ssn) {
            dw_record(DW_SSN, record->ExceptionCode, 0, rip, ssn, context->Rax);
        }
    }

    // At a stub entry, [rsp] is the return address the caller pushed.
    uintptr_t ret = 0;
    if (stub != NULL && at - g_stubs.base == stub->rva && dw_read(context->Rsp, &ret, sizeof(ret)) &&
        !dw_call_precedes(ret)) {
        dw_record(DW_RETURN, record->ExceptionCode, 0, at, ret, 0);
    }
}

static LONG CALLBACK dw_on_continue(EXCEPTION_POINTERS* pointers) {
    dw_check_armed(pointers->ExceptionRecord, pointers->ContextRecord);
    dw_check_single_step(pointers->ExceptionRecord, pointers->ContextRecord);
    return EXCEPTION_CONTINUE_SEARCH;
}

// ---- reporting side ---------------------------------------------------------

static void dw_describe(uint64_t address, char* out, size_t size) {
    const DW_STUB* stub = dw_stub_containing(&g_stubs, (uintptr_t)address);
    if (stub != NULL) {
        _snprintf_s(out, size, _TRUNCATE, "ntdll!%s+0x%x", stub->name,
                    (unsigned)(address - g_stubs.base - stub->rva));
        return;
    }
    if (dw_in_ntdll(&g_stubs, (uintptr_t)address)) {
        _snprintf_s(out, size, _TRUNCATE, "ntdll+0x%llx", (unsigned long long)(address - g_stubs.base));
        return;
    }

    HMODULE module = NULL;
    char path[MAX_PATH] = {0};
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)(uintptr_t)address, &module) &&
        GetModuleFileNameA(module, path, MAX_PATH) != 0) {
        const char* file = strrchr(path, '\\');
        _snprintf_s(out, size, _TRUNCATE, "%s+0x%llx", file != NULL ? file + 1 : path,
                    (unsigned long long)(address - (uintptr_t)module));
        return;
    }
    _snprintf_s(out, size, _TRUNCATE, "0x%llx", (unsigned long long)address);
}

static void dw_write(const char* line, int length) {
    DWORD written = 0;
    if (g_log != INVALID_HANDLE_VALUE && length > 0) {
        WriteFile(g_log, line, (DWORD)length, &written, NULL);
    }
}

static void dw_format(const DW_EVENT* e) {
    char a[160];
    char b[160];
    char line[512];
    int n = 0;
    dw_describe(e->a, a, sizeof(a));
    switch (e->kind) {
    case DW_ARM:
        dw_describe(e->b, b, sizeof(b));
        n = _snprintf_s(line, sizeof(line), _TRUNCATE, "ARM tid=%lu dr%u=%s code=0x%08lx at=%s%s\r\n", e->tid, e->slot,
                        a, e->code, b, e->c != 0 ? " debugger=attached" : "");
        break;
    case DW_REDIRECT:
        dw_describe(e->b, b, sizeof(b));
        n = _snprintf_s(line, sizeof(line), _TRUNCATE, "REDIRECT tid=%lu from=%s to=%s rax=0x%llx\r\n", e->tid, a, b,
                        (unsigned long long)e->c);
        break;
    case DW_SSN:
        n = _snprintf_s(line, sizeof(line), _TRUNCATE, "SSN tid=%lu at=%s stub-ssn=0x%llx rax=0x%llx\r\n", e->tid, a,
                        (unsigned long long)e->b, (unsigned long long)e->c);
        break;
    case DW_RETURN:
        dw_describe(e->b, b, sizeof(b));
        n = _snprintf_s(line, sizeof(line), _TRUNCATE, "RETURN tid=%lu at=%s ret=%s not-after-call\r\n", e->tid, a, b);
        break;
    }
    dw_write(line, n);
}

static void dw_flush(bool wait) {
    if (wait) {
        EnterCriticalSection(&g_flush_lock);
    } else if (!TryEnterCriticalSection(&g_flush_lock)) {
        return; // the flusher died holding it during process exit
    }
    for (;;) {
        DW_EVENT* event = &g_ring[(ULONG)g_consumed % DW_RING];
        if (g_consumed >= g_produced || InterlockedCompareExchange(&event->ready, 0, 0) == 0) {
            break;
        }
        dw_format(event);
        InterlockedExchange(&event->ready, 0);
        ++g_consumed;
    }
    LeaveCriticalSection(&g_flush_lock);
}

static DWORD WINAPI dw_flusher(LPVOID parameter) {
    (void)parameter;
    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) {
        Sleep(20);
        dw_flush(true);
    }
    return 0;
}

static void dw_open_log(void) {
    wchar_t path[MAX_PATH];
    const DWORD length = GetEnvironmentVariableW(L"DR7WATCH_LOG", path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return;
    }
    g_log = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        if (!dw_stub_map_build(&g_stubs)) {
            return FALSE;
        }
        InitializeCriticalSection(&g_flush_lock);
        dw_open_log();
        g_continue_handler = AddVectoredContinueHandler(1, dw_on_continue);
        g_flusher = CreateThread(NULL, 0, dw_flusher, NULL, 0, NULL);
        char line[128];
        const int n = _snprintf_s(line, sizeof(line), _TRUNCATE, "READY pid=%lu stubs=%zu\r\n",
                                  GetCurrentProcessId(), g_stubs.count);
        dw_write(line, n);
    } else if (reason == DLL_PROCESS_DETACH) {
        // On process exit the flusher is already gone; drain what it missed.
        InterlockedExchange(&g_stop, 1);
        if (g_continue_handler != NULL) {
            RemoveVectoredContinueHandler(g_continue_handler);
        }
        dw_flush(false);
        if (g_dropped != 0) {
            char line[64];
            const int n = _snprintf_s(line, sizeof(line), _TRUNCATE, "DROPPED %ld\r\n", g_dropped);
            dw_write(line, n);
        }
        if (g_log != INVALID_HANDLE_VALUE) {
            CloseHandle(g_log);
        }
        if (reserved == NULL) {
            dw_stub_map_free(&g_stubs);
        }
    }
    return TRUE;
}
