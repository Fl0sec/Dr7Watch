// False-positive target: ordinary exception traffic and repeated file writes.
#include <stdio.h>
#include <windows.h>

static int g_handled;

static LONG CALLBACK benign_veh(EXCEPTION_POINTERS* p) {
    // A legitimate VEH that recovers from a call through a null pointer by returning to the caller.
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && p->ContextRecord->Rip == 0) {
        ++g_handled;
        p->ContextRecord->Rip = *(DWORD64*)p->ContextRecord->Rsp;
        p->ContextRecord->Rsp += 8;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char** argv) {
    const int rounds = argc > 1 ? atoi(argv[1]) : 50;
    PVOID handler = AddVectoredExceptionHandler(1, benign_veh);
    HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    int seh = 0;
    for (int i = 0; i < rounds; ++i) {
        __try {
            RaiseException(0xE0000001, 0, 0, NULL);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            ++seh;
        }
        void (*volatile null_function)(void) = NULL;
        null_function(); // recovered by benign_veh
        DWORD written = 0;
        WriteFile(nul, "x", 1, &written, NULL);
        if (argc > 2) {
            Sleep(200);
        }
    }
    CloseHandle(nul);
    RemoveVectoredExceptionHandler(handler);
    printf("[fp] rounds=%d seh=%d veh=%d\n", rounds, seh, g_handled);
    return 0;
}

