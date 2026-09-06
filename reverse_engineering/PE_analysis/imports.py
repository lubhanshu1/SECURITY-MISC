from __future__ import annotations

from .sections import SectionInfo, rva_to_offset


def read_struct(
    data: bytes,
    offset: int,
    fmt: str,
):
    import struct

    size = struct.calcsize(fmt)

    if offset < 0 or offset + size > len(data):
        raise ValueError(
            f"Unexpected end of file at offset 0x{offset:X}"
        )

    return struct.unpack_from(
        fmt,
        data,
        offset,
    )


def read_c_string(
    data: bytes,
    offset: int,
    maximum: int = 4096,
) -> str:
    if offset < 0 or offset >= len(data):
        return ""

    end = min(
        len(data),
        offset + maximum,
    )

    value = data[offset:end]

    nul = value.find(b"\x00")

    if nul >= 0:
        value = value[:nul]

    return value.decode(
        "ascii",
        errors="replace",
    )


def parse_imports(
    data: bytes,
    import_rva: int,
    import_size: int,
    sections: list[SectionInfo],
    is_64_bit: bool,
) -> list[dict]:
    """
    Parse IMAGE_IMPORT_DESCRIPTOR entries and
    recover imported DLL/function names.

    The analyzed file is treated strictly as raw
    data. Nothing is executed.
    """
    if import_rva == 0:
        return []

    import_offset = rva_to_offset(
        import_rva,
        sections,
    )

    if import_offset is None:
        return []

    results: list[dict] = []

    descriptor_offset = import_offset

    max_descriptors = (
        max(1, import_size // 20)
        if import_size
        else 4096
    )

    for _ in range(max_descriptors):
        if descriptor_offset + 20 > len(data):
            break

        (
            original_first_thunk,
            timestamp,
            forwarder_chain,
            name_rva,
            first_thunk,
        ) = read_struct(
            data,
            descriptor_offset,
            "<IIIII",
        )

        # Null descriptor terminates the table.
        if (
            original_first_thunk == 0
            and timestamp == 0
            and forwarder_chain == 0
            and name_rva == 0
            and first_thunk == 0
        ):
            break

        name_offset = rva_to_offset(
            name_rva,
            sections,
        )

        if name_offset is None:
            descriptor_offset += 20
            continue

        dll_name = read_c_string(
            data,
            name_offset,
        )

        lookup_rva = (
            original_first_thunk
            or first_thunk
        )

        lookup_offset = rva_to_offset(
            lookup_rva,
            sections,
        )

        functions: list[str] = []

        if lookup_offset is not None:
            thunk_size = (
                8
                if is_64_bit
                else 4
            )

            ordinal_flag = (
                0x8000000000000000
                if is_64_bit
                else 0x80000000
            )

            current = lookup_offset

            for _ in range(10000):
                if current + thunk_size > len(data):
                    break

                if is_64_bit:
                    thunk_value = read_struct(
                        data,
                        current,
                        "<Q",
                    )[0]
                else:
                    thunk_value = read_struct(
                        data,
                        current,
                        "<I",
                    )[0]

                if thunk_value == 0:
                    break

                # Import by ordinal.
                if thunk_value & ordinal_flag:
                    ordinal = thunk_value & 0xFFFF

                    functions.append(
                        f"Ordinal_{ordinal}"
                    )

                # Import by name.
                else:
                    if is_64_bit:
                        hint_name_rva = (
                            thunk_value
                            & 0x7FFFFFFFFFFFFFFF
                        )
                    else:
                        hint_name_rva = (
                            thunk_value
                            & 0x7FFFFFFF
                        )

                    hint_name_offset = rva_to_offset(
                        hint_name_rva,
                        sections,
                    )

                    if (
                        hint_name_offset is not None
                        and hint_name_offset + 2
                        <= len(data)
                    ):
                        function_name = read_c_string(
                            data,
                            hint_name_offset + 2,
                        )

                        if function_name:
                            functions.append(
                                function_name
                            )

                current += thunk_size

        results.append(
            {
                "dll": dll_name,
                "timestamp": timestamp,
                "functions": functions,
                "function_count": len(functions),
            }
        )

        descriptor_offset += 20

    return results


def summarize_imports(
    imports: list[dict],
) -> dict:
    """
    Produce simple aggregate statistics for
    an already-parsed import table.
    """
    return {
        "dll_count": len(imports),
        "function_count": sum(
            item.get(
                "function_count",
                0,
            )
            for item in imports
        ),
    }