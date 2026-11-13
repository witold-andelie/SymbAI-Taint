"""Conservative relocation coverage for a file-byte-only AMD64 analysis."""


class UnsupportedELFLayout(ValueError):
    pass


def check_relocation_coverage(elf, loads, sections):
    """Refuse a table the reference loader can use but section parsing does not cover.

    This deliberately supports a narrow relocation subset. Unknown layouts return no
    certificate rather than guessing write widths or trusting empty section headers.
    """
    for segment in elf.iter_segments():
        if segment["p_type"] != "PT_DYNAMIC":
            continue
        tags = {}
        for tag in segment.iter_tags():
            name = tag.entry.d_tag
            if name in ("DT_RELR", "DT_RELRSZ", "DT_RELRENT", "DT_ANDROID_REL", "DT_ANDROID_RELA",
                        "DT_ANDROID_RELSZ", "DT_ANDROID_RELASZ", "DT_TEXTREL"):
                raise UnsupportedELFLayout("dynamic_relocation_format_outside_subset")
            if name in ("DT_RELA", "DT_RELASZ", "DT_RELAENT", "DT_REL", "DT_RELSZ", "DT_RELENT",
                        "DT_JMPREL", "DT_PLTRELSZ", "DT_PLTREL"):
                if name in tags:
                    raise UnsupportedELFLayout("duplicate_dynamic_relocation_tag")
                tags[name] = tag.entry.d_val
        tables = []
        for prefix, section_type, size in (("RELA", "SHT_RELA", 24), ("REL", "SHT_REL", 16)):
            address, length = tags.get("DT_" + prefix), tags.get("DT_" + prefix + "SZ")
            if address is None and length is None:
                continue
            if address is None or length is None or (length and tags.get("DT_" + prefix + "ENT") != size):
                raise UnsupportedELFLayout("incomplete_dynamic_relocation_table")
            if length:
                tables.append((address, length, section_type, size))
        if "DT_JMPREL" in tags or "DT_PLTRELSZ" in tags:
            if "DT_JMPREL" not in tags or "DT_PLTRELSZ" not in tags:
                raise UnsupportedELFLayout("incomplete_plt_relocation_table")
            if tags["DT_PLTRELSZ"]:
                kind = tags.get("DT_PLTREL")
                if kind not in (7, 17):  # ELF DT_RELA and DT_REL tag values.
                    raise UnsupportedELFLayout("unknown_plt_relocation_format")
                tables.append((tags["DT_JMPREL"], tags["DT_PLTRELSZ"],
                               "SHT_RELA" if kind == 7 else "SHT_REL", 24 if kind == 7 else 16))
        for address, length, kind, entry_size in tables:
            matches = [section for section in sections if section["sh_type"] == kind
                and section["sh_addr"] == address and section["sh_size"] == length
                and section["sh_entsize"] == entry_size]
            if len(matches) != 1 or length % entry_size:
                raise UnsupportedELFLayout("dynamic_relocation_section_coverage_unproved")
            mapped = [load for load in loads if load["p_vaddr"] <= address
                      and address + length <= load["p_vaddr"] + load["p_filesz"]]
            if len(mapped) != 1:
                raise UnsupportedELFLayout("dynamic_relocation_bytes_unmapped_or_ambiguous")
            load = mapped[0]
            start = address - load["p_vaddr"]
            if matches[0].data() != load.data()[start:start + length]:
                raise UnsupportedELFLayout("dynamic_relocation_file_bytes_differ")
    executable = [(load["p_vaddr"], load["p_vaddr"] + load["p_memsz"]) for load in loads if load["p_flags"] & 1]
    # Only AMD64 NONE, absolute 64, GLOB_DAT, JUMP_SLOT and RELATIVE are supported.
    widths = {0: 0, 1: 8, 6: 8, 7: 8, 8: 8}
    for section in sections:
        for relocation in section.iter_relocations():
            kind = relocation["r_info_type"]
            if kind not in widths:
                raise UnsupportedELFLayout("relocation_write_width_outside_subset")
            width, address = widths[kind], relocation["r_offset"]
            if width and any(address < end and start < address + width for start, end in executable):
                raise UnsupportedELFLayout("executable_relocation_outside_subset")
