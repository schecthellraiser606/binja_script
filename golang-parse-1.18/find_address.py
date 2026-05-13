from binaryninja import *

magics = [
    b"\xfb\xff\xff\xff",  # Go 1.2
    b"\xfa\xff\xff\xff",  # Go 1.16
    b"\xf0\xff\xff\xff",  # Go 1.18
    b"\xf1\xff\xff\xff",  # Go 1.20+
]

candidates = []

for seg in bv.segments:
    data = bv.read(seg.start, seg.length)
    if not data:
        continue

    for magic in magics:
        off = 0
        while True:
            i = data.find(magic, off)
            if i == -1:
                break

            addr = seg.start + i
            hdr = bv.read(addr, 32)

            if len(hdr) >= 16:
                pad1 = hdr[4]
                pad2 = hdr[5]
                min_lc = hdr[6]
                ptr_size = hdr[7]

                if pad1 == 0 and pad2 == 0 and ptr_size in (4, 8):
                    nfunc = int.from_bytes(hdr[8:8 + ptr_size], "little")
                    if 0 < nfunc < 10000000:
                        candidates.append((addr, magic.hex(), min_lc, ptr_size, nfunc))

            off = i + 1

for c in candidates:
    print("addr=0x%x magic=%s minLC=%d ptrSize=%d nfunc=%d" % c)