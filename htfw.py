#!/usr/bin/env python3
"""HTFW container parser.

Layout recovered from 5868USB.dll sub_180092eb0 (header reader) and
sub_180092240 (per-segment entry builder), and verified against
PocketMaster_CFW0.9.8_base1.3.3 (2,125,752 B, 5 segments):

  0x00  "HTFW"
  0x04  u16      (0x342b in the known image)
  0x06  u16      (1 in the known image)
  0x08  u32      image size == file length
  0x0C  16 B     model ("Pocket Master")
  0x1C  u32      (0x03030156 in the known image: bytes 56 01 03 03)
  0x20  u8       (0)
  0x21  u8       (0)
  0x22  u8       segment count (the DLL loop bound is byte[0x22]; 5 here)
  0x23  u8       high byte of the count field (0)
  0x24  u32      total payload length (sum of segment lengths; 0x206f30)
  0x28  16 B     digest slot (zeros in the known image)
  0x38  count * 16 B  segment records:
        +0  u16   (per-segment, e.g. 0xfa06)
        +2  u16   (low byte 0, high byte per-segment)
        +3  u8    flags (0x63,0x67,0x66,0x62,0x65)
        +4  u32   destination address
        +8  u32   data offset (relative to the data region)
        +C  u32   data length
  data region = 0x38 + count*16; segments are data[dataoff:dataoff+length].

The old "80-byte 0xFF trailer" was a misreading: 5 records * 16 B = 80 B, and
the data region starts right after it.  There is no trailer.
"""
import re
import struct
import hashlib
import json
import sys

MAGIC = b"HTFW"
USAGE = "usage: htfw.py [--expect-model NAME] FILE.bin [FILE.bin ...]"


def image_version(segments):
    """Best-effort version tag from the start of segment 0.

    Both shipping images carry a short banner there: ``V132`` in
    Pocket Master 1.3.3 and ``V101`` in Smart Box 1.0.6.  The ``0x1C`` header
    field is *not* a version on every model -- Smart Box stores ``42 00 00 04``
    in a 1.0.6 release -- so this is a display aid, not an authority.
    """
    if not segments or not segments[0]["data"]:
        return None
    m = re.search(rb"V\d+(?:\.\d+){0,2}", segments[0]["data"][:32])
    return m.group(0).decode("ascii") if m else None
HDR_LEN = 0x38
REC_LEN = 16


def parse(path):
    with open(path, "rb") as fh:
        b = fh.read()
    if len(b) < HDR_LEN or b[:4] != MAGIC:
        raise ValueError("%s: not an HTFW container" % path)

    def u32(o):
        return struct.unpack_from("<I", b, o)[0]

    def u16(o):
        return struct.unpack_from("<H", b, o)[0]

    count = b[0x22]
    data_base = HDR_LEN + count * REC_LEN
    f = {
        "magic": b[0:4].decode("ascii", "replace"),
        "u04": u16(0x04),
        "u06": u16(0x06),
        "image_size": u32(0x08),
        "model": b[0x0C:0x1C].split(b"\0")[0].decode("ascii", "replace"),
        "u1C": u32(0x1C),
        "version": "%d.%d.%d" % (b[0x1D], b[0x1E], b[0x1F]),
        "version_raw": b[0x1C:0x20].hex(),
        "b1C": b[0x1C],
        "b20": b[0x20],
        "b21": b[0x21],
        "count": count,
        "count_hi": b[0x23],
        "payload_len": u32(0x24),
        "digest_slot": b[0x28:0x38].hex(),
        "data_base": data_base,
        "file_size": len(b),
    }

    segments = []
    for i in range(count):
        r = HDR_LEN + i * REC_LEN
        rec = {
            "index": i,
            "u00": u16(r + 0),
            "u02": u16(r + 2),
            "flags": b[r + 3],
            "addr": u32(r + 4),
            "dataoff": u32(r + 8),
            "length": u32(r + 0xC),
        }
        start = data_base + rec["dataoff"]
        rec["data"] = b[start:start + rec["length"]]
        rec["data_ok"] = len(rec["data"]) == rec["length"]
        segments.append(rec)
    f["segments"] = segments

    f["image_version"] = image_version(segments)
    f["payload"] = b[data_base:data_base + f["payload_len"]]
    f["payload_sha256"] = hashlib.sha256(f["payload"]).hexdigest()
    f["total_len"] = sum(s["length"] for s in segments)

    w = f["warnings"] = []
    if f["image_size"] != f["file_size"]:
        w.append("0x08 (%d) != file length (%d)" % (f["image_size"], f["file_size"]))
    if f["count_hi"] != 0:
        w.append("0x23 (count high byte) is %#x, expected 0" % f["count_hi"])
    if f["total_len"] != f["payload_len"]:
        w.append("sum(segment lengths) %d != 0x24 payload_len %d"
                 % (f["total_len"], f["payload_len"]))
    if data_base + f["payload_len"] != f["file_size"]:
        w.append("data_base+payload_len (%d) != file size (%d)"
                 % (data_base + f["payload_len"], f["file_size"]))
    for s in segments:
        if not s["data_ok"]:
            w.append("segment %d data truncated (%d/%d B)"
                     % (s["index"], len(s["data"]), s["length"]))
    if f["u06"] != 1:
        w.append("u06 is %d, expected 1" % f["u06"])
    f["sane"] = not w
    return f


def check_model(f, expected):
    """Mirror isRealFirmware: the DLL's tag is literally 'equalsIgnoreCase'."""
    return f["model"].lower() == expected.lower()


def main(argv):
    expect = None
    files = []
    rest = list(argv)
    while rest:
        a = rest.pop(0)
        if a in ("--expect-model", "--confirm-model"):
            if not rest:
                print("%s needs a NAME" % a, file=sys.stderr)
                return 2
            expect = rest.pop(0)
        elif a in ("-h", "--help"):
            print(USAGE)
            return 0
        else:
            files.append(a)
    if not files:
        print(USAGE, file=sys.stderr)
        return 2
    rc = 0
    for p in files:
        try:
            f = parse(p)
        except ValueError as e:
            print("%s\n  ERROR: %s" % (p, e), file=sys.stderr)
            rc = 1
            continue
        if expect is not None and not check_model(f, expect):
            print("%s\n  ERROR: model %r != expected %r"
                  % (p, f["model"], expect), file=sys.stderr)
            rc = 1
            continue
        print("  model %r, version field %s, image tag %s"
              % (f["model"], f["version_raw"], f["image_version"] or "-"),
              file=sys.stderr)
        shown = dict((k, v) for k, v in f.items()
                     if k not in ("payload", "segments"))
        shown["segments"] = [
            dict((k, v) for k, v in s.items() if k != "data") for s in f["segments"]
        ]
        print(p)
        print(json.dumps(shown, indent=2))
        for w in f["warnings"]:
            print("  WARNING: %s" % w, file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
