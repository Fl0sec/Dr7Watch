#include "stubs.h"

#include <stdlib.h>
#include <string.h>

static int dw_compare_stubs(const void* left, const void* right) {
    const uint32_t a = ((const DW_STUB*)left)->rva;
    const uint32_t b = ((const DW_STUB*)right)->rva;
    return (a > b) - (a < b);
}

static bool dw_is_native_export(const char* name) {
    // Nt* system services; NtdllDefWindowProc_* and friends are ordinary functions.
    return name[0] == 'N' && name[1] == 't' && strncmp(name, "Ntdll", 5) != 0;
}

bool dw_stub_map_build(DW_STUB_MAP* map) {
    memset(map, 0, sizeof(*map));

    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }

    const uint8_t* base = (const uint8_t*)ntdll;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
    const IMAGE_NT_HEADERS64* nt = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir->VirtualAddress == 0) {
        return false;
    }

    const IMAGE_EXPORT_DIRECTORY* exports = (const IMAGE_EXPORT_DIRECTORY*)(base + dir->VirtualAddress);
    const uint32_t* names = (const uint32_t*)(base + exports->AddressOfNames);
    const uint16_t* ordinals = (const uint16_t*)(base + exports->AddressOfNameOrdinals);
    const uint32_t* functions = (const uint32_t*)(base + exports->AddressOfFunctions);

    map->stubs = (DW_STUB*)calloc(exports->NumberOfNames, sizeof(DW_STUB));
    if (map->stubs == NULL) {
        return false;
    }

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* name = (const char*)(base + names[i]);
        if (!dw_is_native_export(name)) {
            continue;
        }
        DW_STUB* stub = &map->stubs[map->count++];
        stub->rva = functions[ordinals[i]];
        strncpy_s(stub->name, sizeof(stub->name), name, _TRUNCATE);
    }

    qsort(map->stubs, map->count, sizeof(DW_STUB), dw_compare_stubs);
    map->base = (uintptr_t)base;
    map->end = map->base + nt->OptionalHeader.SizeOfImage;
    return true;
}

void dw_stub_map_free(DW_STUB_MAP* map) {
    free(map->stubs);
    memset(map, 0, sizeof(*map));
}

bool dw_in_ntdll(const DW_STUB_MAP* map, uintptr_t address) {
    return address >= map->base && address < map->end;
}

const DW_STUB* dw_stub_containing(const DW_STUB_MAP* map, uintptr_t address) {
    if (!dw_in_ntdll(map, address) || map->count == 0) {
        return NULL;
    }

    const uint32_t rva = (uint32_t)(address - map->base);
    size_t low = 0;
    size_t high = map->count;
    while (low < high) {
        const size_t mid = low + (high - low) / 2;
        if (map->stubs[mid].rva <= rva) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    if (low == 0) {
        return NULL;
    }

    const DW_STUB* candidate = &map->stubs[low - 1];
    return rva - candidate->rva < DW_STUB_SPAN ? candidate : NULL;
}
