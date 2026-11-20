#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <windows.h>

#define DW_STUB_SPAN 0x20u

typedef struct DW_STUB {
    uint32_t rva;
    char name[64];
} DW_STUB;

typedef struct DW_STUB_MAP {
    uintptr_t base;
    uintptr_t end;
    DW_STUB* stubs;
    size_t count;
} DW_STUB_MAP;

bool dw_stub_map_build(DW_STUB_MAP* map);
void dw_stub_map_free(DW_STUB_MAP* map);

// The Nt* export whose 0x20-byte stub contains the address, or NULL.
const DW_STUB* dw_stub_containing(const DW_STUB_MAP* map, uintptr_t address);

bool dw_in_ntdll(const DW_STUB_MAP* map, uintptr_t address);
