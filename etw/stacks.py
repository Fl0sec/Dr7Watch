"""Print one process's user-mode syscall stacks from an `xperf -a dumper` text file.

    python stacks.py <dump.txt> <image name> <ntdll export> [<ntdll export> ...]

Frames are resolved to module!export+offset from the images the process loaded
(I-Start / I-DCStart rows), reading export tables from the files on disk. Only
stacks whose top user frame is inside one of the named ntdll exports are shown.
"""

import bisect
import os
import re
import struct
import sys


def exports(path: str) -> list[tuple[int, str]]:
    with open(path, "rb") as handle:
        data = handle.read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional = struct.unpack_from("<H", data, pe + 20)[0]
    export_rva = struct.unpack_from("<I", data, pe + 24 + 112)[0]  # PE32+ data directory 0
    table = pe + 24 + optional
    spans = [struct.unpack_from("<IIII", data, table + i * 40 + 8) for i in range(sections)]

    def offset(rva: int) -> int:
        for size, address, _raw_size, raw in spans:
            if address <= rva < address + max(size, _raw_size):
                return rva - address + raw
        raise ValueError(hex(rva))

    base = offset(export_rva)
    count, names = struct.unpack_from("<II", data, base + 20)[1], struct.unpack_from("<I", data, base + 24)[0]
    functions, name_table, ordinals = struct.unpack_from("<III", data, base + 28)
    result = []
    for i in range(names):
        name_rva = struct.unpack_from("<I", data, offset(name_table) + i * 4)[0]
        raw = offset(name_rva)
        name = data[raw:data.index(b"\0", raw)].decode()
        ordinal = struct.unpack_from("<H", data, offset(ordinals) + i * 2)[0]
        result.append((struct.unpack_from("<I", data, offset(functions) + ordinal * 4)[0], name))
    del count
    # Nt and Zw names share an address; keep the Nt one.
    best: dict[int, str] = {}
    for rva, name in result:
        if rva not in best or name.startswith("Nt"):
            best[rva] = name
    return sorted(best.items())


def device_to_dos(path: str) -> str:
    match = re.match(r"\\Device\\HarddiskVolume\d+\\(.*)", path)
    if not match:
        return path
    rest = match.group(1)
    for drive in "CDEFG":
        candidate = f"{drive}:\\{rest}"
        if os.path.exists(candidate):
            return candidate
    return path


def main() -> int:
    dump, image, wanted = sys.argv[1], sys.argv[2].lower(), set(sys.argv[3:])
    thread_row = re.compile(r"^\s*(T-Start|T-DCStart),\s*\d+,\s*(.+?) \(\s*(\d+)\),\s*(\d+),")
    image_row = re.compile(r"^\s*(I-Start|I-DCStart),\s*\d+,\s*(.+?) \(\s*(\d+)\),\s*(0x[0-9a-f]+),\s*(0x[0-9a-f]+),.*\"(.+?)\"")

    tids: set[str] = set()
    modules: list[tuple[int, int, str]] = []
    with open(dump, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            match = thread_row.match(line)
            if match and match.group(2).strip().lower() == image:
                tids.add(match.group(4))
                continue
            match = image_row.match(line)
            if match and match.group(2).strip().lower() == image:
                modules.append((int(match.group(4), 16), int(match.group(5), 16), device_to_dos(match.group(6))))
    modules.sort()
    starts = [m[0] for m in modules]
    cache: dict[str, list[tuple[int, str]]] = {}

    def resolve(address: int) -> tuple[str, str, int]:
        i = bisect.bisect_right(starts, address) - 1
        if i < 0 or address >= modules[i][1]:
            return ("?", "", address)
        base, _end, path = modules[i]
        name = os.path.basename(path)
        if path not in cache:
            try:
                cache[path] = exports(path)
            except (OSError, ValueError, struct.error):
                cache[path] = []
        table = cache[path]
        rva = address - base
        j = bisect.bisect_right([e[0] for e in table], rva) - 1
        if j >= 0 and rva - table[j][0] < 0x400:
            return (name, table[j][1], rva - table[j][0])
        return (name, "", rva)

    stacks: dict[tuple[str, str], list[int]] = {}
    with open(dump, encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.lstrip().startswith("Stack,"):
                continue
            parts = [part.strip() for part in line.split(",", 5)]
            if len(parts) >= 5 and parts[2] in tids:
                address = int(parts[4], 16)
                if address < 0xFFFF000000000000:
                    stacks.setdefault((parts[1], parts[2]), []).append(address)

    if os.environ.get("STACKS_DEBUG"):
        print(len(tids), len(modules), len(stacks), modules[:2])
        from collections import Counter
        print(Counter(resolve(f[0])[:2] for f in stacks.values()).most_common(40))
    for (stamp, tid), frames in stacks.items():
        top = resolve(frames[0])
        if top[0].lower() != "ntdll.dll" or top[1] not in wanted:
            continue
        print(f"--- t={stamp} tid={tid}")
        for address in frames:
            module, export, delta = resolve(address)
            label = f"{module}!{export}+0x{delta:x}" if export else f"{module}+0x{delta:x}"
            print(f"    {label}")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    raise SystemExit(main())
