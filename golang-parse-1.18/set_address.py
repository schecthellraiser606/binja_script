from binaryninja import SectionSemantics

gopclntab = 0xa0a9c0  # ここを候補アドレスに置き換える

seg = bv.get_segment_at(gopclntab)
if seg is None:
    raise Exception("gopclntab address is not inside a mapped segment")

secs = bv.get_sections_at(gopclntab)
end = secs[0].end if secs else seg.end

old = bv.get_section_by_name(".gopclntab")
if old:
    bv.remove_user_section(".gopclntab")

bv.add_user_section(
    ".gopclntab",
    gopclntab,
    end - gopclntab,
    SectionSemantics.ReadOnlyDataSectionSemantics,
)

bv.update_analysis_and_wait()
print("added .gopclntab: 0x%x - 0x%x" % (gopclntab, end))