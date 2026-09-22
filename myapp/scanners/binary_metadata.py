"""Bounded PE/ELF metadata parsing. No loading, extraction or executable invocation."""

import struct
from collections import Counter
import math


def _entropy(data):
    return (
        round(
            -sum(
                n / len(data) * math.log2(n / len(data)) for n in Counter(data).values()
            ),
            3,
        )
        if data
        else 0
    )


def _slice(data, offset, size):
    if offset < 0 or size < 0 or offset + size > len(data):
        raise ValueError("Truncated structure")
    return data[offset : offset + size]


def _text(data, offset, limit=240):
    return (
        _slice(data, offset, min(limit, len(data) - offset))
        .split(b"\0", 1)[0]
        .decode("utf-8", "replace")
    )


def pe_metadata(data):
    result = {"state": "Not Applicable"}
    if not data.startswith(b"MZ"):
        return result
    result = {
        "state": "Unavailable",
        "dos_signature": "MZ",
        "limitations": "Static header metadata; signatures and execution behavior are not verified",
    }
    try:
        offset = struct.unpack("<I", _slice(data, 60, 4))[0]
        if _slice(data, offset, 4) != b"PE\0\0":
            raise ValueError("PE signature not observed")
        machine, count, stamp, _, _, optional_size, characteristics = struct.unpack(
            "<HHIIIHH", _slice(data, offset + 4, 20)
        )
        optional = offset + 24
        if optional_size < 20:
            raise ValueError("Truncated optional header")
        _slice(data, optional, optional_size)
        magic = struct.unpack("<H", _slice(data, optional, 2))[0]
        if magic not in {0x10B, 0x20B}:
            raise ValueError("Unsupported optional header")
        entry = struct.unpack("<I", _slice(data, optional + 16, 4))[0]
        sections = []
        raw_sections = []
        for i in range(min(count, 96)):
            block = _slice(data, optional + optional_size + i * 40, 40)
            name = block[:8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, rva, size, start = struct.unpack_from("<IIII", block, 8)
            if start + size > len(data):
                raise ValueError("Truncated section data")
            content = _slice(data, start, min(size, 256 * 1024))
            raw_sections.append((rva, max(virtual_size, size), start, size))
            sections.append(
                dict(
                    name=name,
                    virtual_address=rva,
                    virtual_size=virtual_size,
                    raw_size=size,
                    entropy_sample_bytes=len(content),
                    entropy=_entropy(content),
                )
            )

        def rva_offset(rva):
            for base, length, start, size in raw_sections:
                if base <= rva < base + length and rva - base < size:
                    return start + rva - base
            raise ValueError("RVA outside available sections")

        imports = []
        import_state = "Not Observed"
        directory = optional + (96 if magic == 0x10B else 112)
        if optional_size >= directory - optional + 16:
            import_rva, import_size = struct.unpack(
                "<II", _slice(data, directory + 8, 8)
            )
            if import_rva and import_size:
                import_state = "Observed"
                start = rva_offset(import_rva)
                for i in range(min(256, import_size // 20)):
                    fields = struct.unpack("<IIIII", _slice(data, start + i * 20, 20))
                    if not any(fields):
                        break
                    imports.append(_text(data, rva_offset(fields[3])))
        result.update(
            state="Observed",
            pe_signature="PE",
            architecture={
                0x14C: "x86",
                0x8664: "x86-64",
                0xAA64: "ARM64",
                0x1C4: "ARM",
            }.get(machine, hex(machine)),
            entry_point_rva=entry,
            characteristics=hex(characteristics),
            coff_timestamp=stamp,
            sections=sections,
            sections_truncated=count > 96,
            imports={"libraries": imports, "state": import_state, "limit": 256},
        )
    except (ValueError, struct.error, OverflowError) as exc:
        result["error"] = str(exc)
    return result


def elf_metadata(data):
    if not data.startswith(b"\x7fELF"):
        return {"state": "Not Applicable"}
    result = {
        "state": "Unavailable",
        "limitations": "Bounded header, section, program-header and symbol metadata only",
    }
    try:
        ident = _slice(data, 0, 16)
        bits = {1: 32, 2: 64}.get(ident[4])
        order = {1: "<", 2: ">"}.get(ident[5])
        if not bits or not order:
            raise ValueError("Unsupported ELF class or byte order")
        fmt = order + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH")
        header = struct.unpack(fmt, _slice(data, 16, struct.calcsize(fmt)))
        (
            kind,
            machine,
            version,
            entry,
            phoff,
            shoff,
            flags,
            ehsize,
            phsize,
            phnum,
            shsize,
            shnum,
            shstr,
        ) = header
        sections = []
        headers = []
        interpreter = None
        names = b""
        raw = []
        sfmt = order + ("IIIIIIIIII" if bits == 32 else "IIQQQQIIQQ")
        ssize = struct.calcsize(sfmt)
        if shnum and shsize < ssize:
            raise ValueError("Invalid section entry size")
        for i in range(min(shnum, 256)):
            raw.append(struct.unpack(sfmt, _slice(data, shoff + i * shsize, ssize)))
        if shstr < len(raw):
            names = _slice(data, raw[shstr][4], min(raw[shstr][5], 1024 * 1024))
        for row in raw:
            name = _text(names, row[0]) if row[0] < len(names) else ""
            sections.append(
                {
                    "name": name,
                    "type": row[1],
                    "address": row[3],
                    "offset": row[4],
                    "size": row[5],
                }
            )
        pfmt = order + ("IIIIIIII" if bits == 32 else "IIQQQQQQ")
        psize = struct.calcsize(pfmt)
        if phnum and phsize < psize:
            raise ValueError("Invalid program entry size")
        for i in range(min(phnum, 128)):
            p = struct.unpack(pfmt, _slice(data, phoff + i * phsize, psize))
            offset = p[1] if bits == 32 else p[2]
            size = p[4] if bits == 32 else p[5]
            headers.append({"type": p[0], "offset": offset, "file_size": size})
            if p[0] == 3:
                interpreter = (
                    _slice(data, offset, min(size, 512))
                    .split(b"\0", 1)[0]
                    .decode("utf-8", "replace")
                )
        symbols = []
        for row in raw:
            if row[1] not in {2, 11} or not row[9] or row[6] >= len(raw):
                continue
            strings = raw[row[6]]
            table = _slice(data, strings[4], min(strings[5], 1024 * 1024))
            for i in range(min(row[5] // row[9], 200 - len(symbols))):
                name_offset = struct.unpack(
                    order + "I", _slice(data, row[4] + i * row[9], 4)
                )[0]
                if 0 < name_offset < len(table):
                    symbols.append(_text(table, name_offset))
        result.update(
            state="Observed",
            elf_class=bits,
            endian="little" if order == "<" else "big",
            architecture={
                3: "x86",
                62: "x86-64",
                40: "ARM",
                183: "ARM64",
                243: "RISC-V",
            }.get(machine, str(machine)),
            entry_point=entry,
            sections=sections,
            program_headers=headers,
            interpreter=interpreter or "Not Observed",
            symbols=symbols,
            limits={"sections": 256, "program_headers": 128, "symbols": 200},
        )
    except (ValueError, struct.error, OverflowError) as exc:
        result["error"] = str(exc)
    return result


def binary_metadata(data):
    return pe_metadata(data), elf_metadata(data)
