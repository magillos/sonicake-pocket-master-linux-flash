#!/usr/bin/env python3
"""Upload an HTFW firmware image to a 5868USB device.

Works for the Sonicake Pocket Master and the Sonicake Smart Box: both ship the
same HTFW container, the same 5-segment flash map and the same upload state
machine, and both are flashed by the same DLL code path.  The image is
identified by the model string in its header, which is matched against the
ALSA card name -- the same check the DLL exposes as
``isRealFirmwareWithDeviceName``.

Protocol recovered from 5868USB.dll.  The device runs a small state machine
(sub_180092850) that is ACK-paced: after every frame it sets a "waiting" flag
(state+0xc4) and only advances when the first byte of the reassembled reply
message body is 0 (sub_1800932f0).  For a single-frame ACK that byte is
payload[2] (payload[0] is the 0x13/0x14 ACK type).  A nonzero status aborts
(sub_1800916a0), and no reply within 9000 ticks also aborts.  So we send one
frame and wait for an ACK before the next.

Sequence (confirmed against sub_180092850 / sub_180092240 / sub_180091f60 /
sub_180092b70 / sub_180091cb0 / sub_180091a00):

  init        11 60                                   count=1 index=0
  per segment (i = 0..count-1):
    announce  11 61 <flags> 00 00 00 <frame_count:u32> <size:u32>   count=1 index=0
              where buf = 11 <flags> <segment data>, size = len(buf),
              frame_count = ceil(size / 19)
    stream    buf[off:off+19]                            count=0xFF index=j
    end       11 6e <flags> 00                           count=1 index=0
  commit      11 6e 6e 00                              count=1 index=0 (no wait)

All frames are nibble-expanded (the entry type at state+0xa8 is 1, so chunk
size is 19).  byte3 of the wire header is the payload length.

The addresses cited above are from the 2,437,120 B DLL build the protocol was
recovered from.  Sonicake Manager 1.5.2 ships a newer 2,902,016 B build with the
same exports (isRealFirmwareWithDeviceName, checkCrc, deviceStartUpdate) and the
same Smart Box handling, so the sequence below still applies.

DANGEROUS BY DESIGN GUARD: dry run unless --i-understand-the-risk is given.
"""
import argparse
import math
import os
import re
import select
import sys
import time

import htfw
import sxproto

CHUNK = 19
ACK_TYPES = (0x13, 0x14)


def init_frame():
    return sxproto.frame(1, 0, b"\x11\x60")


def segment_frames(seg):
    """Yield (frame, expect_ack) for one segment record."""
    flags = seg["flags"]
    buf = bytes([0x11, flags]) + seg["data"]
    size = len(buf)
    nframes = math.ceil(size / CHUNK)
    ann = bytes([0x11, 0x61, flags, 0, 0, 0])
    ann += nframes.to_bytes(4, "little")
    ann += size.to_bytes(4, "little")
    yield sxproto.frame(1, 0, ann), True
    for j, off in enumerate(range(0, size, CHUNK)):
        yield sxproto.frame(0xFF, j & 0xFF, buf[off:off + CHUNK]), True
    yield sxproto.frame(1, 0, bytes([0x11, 0x6E, flags, 0])), True


def commit_frame():
    return sxproto.frame(1, 0, b"\x11\x6e\x6e\x00")


def build_actions(fw):
    actions = [(init_frame(), True)]
    for seg in fw["segments"]:
        actions.extend(segment_frames(seg))
    actions.append((commit_frame(), False))
    return actions


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def sound_cards():
    """Parse /proc/asound/cards -> {card_no: (id, description)}."""
    try:
        text = open("/proc/asound/cards", encoding="utf-8", errors="replace").read()
    except OSError:
        return {}
    cards = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s*\[([^\]]*)\]\s*:\s*\S+\s*-\s*(.*)$", line)
        if m:
            cards[int(m.group(1))] = (m.group(2).strip(), m.group(3).strip())
    return cards


def midi_node(card):
    for d in range(4):
        path = "/dev/snd/midiC%dD%d" % (card, d)
        if os.path.exists(path):
            return path
    return None


def card_of_node(path):
    m = re.search(r"midiC(\d+)D\d+", os.path.basename(path))
    return int(m.group(1)) if m else None


def usb_id(card):
    try:
        return open("/proc/asound/card%d/usbid" % card).read().strip()
    except OSError:
        return ""


def find_rawmidi(explicit=None, model=None):
    """Locate the rawmidi node (e.g. /dev/snd/midiC2D0) for a 5868USB device.

    Prefers the card whose ALSA id/description matches the firmware's model
    ("Pocket Master" / "Smart Box"), then the only card exposing a rawmidi
    node, and finally reports the candidates so the caller can pick one.
    """
    if explicit:
        return explicit, card_of_node(explicit)
    cards = sound_cards()
    wanted = _norm(model)
    candidates = []
    for num in sorted(cards):
        node = midi_node(num)
        if not node:
            continue
        cid, desc = cards[num]
        if wanted and (wanted in _norm(cid) or wanted in _norm(desc)):
            return node, num
        candidates.append((node, num, "%d [%s] %s" % (num, cid, desc)))
    if len(candidates) == 1:
        node, num, label = candidates[0]
        print("rawmidi: no card named %r; using the only MIDI card: %s"
              % (model, label), file=sys.stderr)
        return node, num
    lines = ["no rawmidi node for model %r (is the device connected in update "
             "mode?)" % model if model else "no rawmidi node found"]
    for node, num, label in candidates:
        lines.append("  %s -> %s (usb %s)" % (label, node, usb_id(num) or "?"))
    lines.append("pass --rawmidi /dev/snd/midiCxDy to select one")
    sys.exit("\n".join(lines))


def guard_model(fw, card, allow):
    """Refuse to flash an image that is not for the connected device.

    Mirrors the DLL's isRealFirmwareWithDeviceName: the image model and the
    device name (here the ALSA card name) must agree.
    """
    if card is None:
        return
    cid, desc = sound_cards().get(card, ("", ""))
    label = "%d [%s] %s" % (card, cid, desc)
    device = _norm(desc) or _norm(cid)
    model = _norm(fw["model"])
    if not device:
        print("warning: cannot read the name of card %d; model not checked" % card,
              file=sys.stderr)
        return
    if model and (model in device or device in model):
        print("card %s matches the image model %r" % (label, fw["model"]),
              file=sys.stderr)
        return
    msg = "refusing: image is for %r but the connected card is %s" % (fw["model"], label)
    if allow:
        print("warning: %s (continuing: --allow-model-mismatch)" % msg, file=sys.stderr)
        return
    sys.exit(msg + "\npass --allow-model-mismatch to override")


def _write_all(fd, data, timeout=5.0):
    mv = memoryview(data)
    while mv:
        try:
            n = os.write(fd, mv)
            mv = mv[n:]
        except BlockingIOError:
            _, w, _ = select.select([], [fd], [], timeout)
            if not w:
                raise TimeoutError("rawmidi write stalled")


class RawMidi:
    """Full-duplex rawmidi transport (separate read/write fds, SysEx framed)."""

    def __init__(self, path):
        self.path = path
        self.rfd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        self.wfd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
        self.buf = bytearray()
        self.msgs = []

    def send(self, msg):
        _write_all(self.wfd, msg)

    def poll(self):
        while True:
            try:
                chunk = os.read(self.rfd, 4096)
            except BlockingIOError:
                break
            if not chunk:
                break
            self.buf += chunk
        while True:
            start = self.buf.find(0xF0)
            if start < 0:
                self.buf.clear()
                break
            if start:
                del self.buf[:start]
            end = self.buf.find(0xF7, 1)
            if end < 0:
                break
            self.msgs.append(bytes(self.buf[:end + 1]))
            del self.buf[:end + 1]
        return self.msgs.pop(0) if self.msgs else None

    def close(self):
        os.close(self.rfd)
        os.close(self.wfd)


def open_alsa(port):
    """rtmidi/ALSA-sequencer transport (kept as a fallback)."""
    import rtmidi
    out = rtmidi.MidiOut()
    inp = rtmidi.MidiIn()
    outs = out.get_ports()
    ins = inp.get_ports()

    def index(ports):
        if isinstance(port, int):
            return port
        if port in ports:
            return ports.index(port)
        for i, p in enumerate(ports):
            if port in p:
                return i
        sys.exit("port %r not found\n  out=%r\n  in =%r" % (port, outs, ins))

    inp.ignore_types(sysex=False, timing=True, active_sense=True)
    out.open_port(index(outs))
    inp.open_port(index(ins))

    def send(msg):
        out.send_message(list(msg))

    def poll():
        m = inp.get_message()
        return bytes(m[0]) if m else None

    return send, poll, (out, inp)


def usb_packetise(sysex):
    """SysEx -> USB-MIDI 1.0 4-byte event packets (vendor transport only)."""
    out = bytearray()
    i = 0
    while i < len(sysex):
        c = sysex[i:i + 3]
        cin = 0x04 if len(c) == 3 else (0x06 if len(c) == 2 else 0x05)
        out += bytes([cin]) + c + b"\0" * (3 - len(c))
        i += 3
    return bytes(out)


def open_usb(vid, pid):
    import usb.core
    import usb.util
    dev = usb.core.find(idVendor=vid, idProduct=pid)
    if dev is None:
        sys.exit("device %04x:%04x not found" % (vid, pid))
    intf = ep = None
    for cfg in dev:
        for i in cfg:
            if i.bInterfaceClass == 0xFF:
                intf = i
                ep = next(e for e in i if not (e.bEndpointAddress & 0x80))
    if intf is None:
        sys.exit("no vendor-specific interface; the device is probably MIDI class "
                 "-> use --transport rawmidi instead")
    try:
        dev.detach_kernel_driver(intf.bInterfaceNumber)
    except Exception:
        pass
    usb.util.claim_interface(dev, intf.bInterfaceNumber)
    return lambda msg: dev.write(ep.bEndpointAddress, usb_packetise(msg), timeout=2000), \
        lambda: None, None


def decode_reply(msg):
    """Decode a device reply.  The pedal's replies are nibble-expanded (same
    encoding as our outgoing frames); raw is also accepted for robustness.
    The DLL receiver collapses with an 8-bit ``(b[i]<<4)|b[i+1]``."""
    if len(msg) < 6 or msg[0] != 0xF0 or msg[-1] != 0xF7:
        return None
    body = msg[1:-1]
    for cand, enc in ((body, "raw"), (sxproto.collapse(body), "expanded")):
        if len(cand) >= 4 and sxproto.crc8(cand[1:]) == cand[0]:
            return {"frame": cand, "enc": enc, "crc": cand[0], "count": cand[1],
                    "index": cand[2], "blen": cand[3], "payload": cand[4:]}
    return None


def describe_reply(msg):
    d = decode_reply(msg)
    if d is None:
        return "invalid %s" % msg.hex()
    return ("%s crc=ok count=%d index=%d blen=%d payload=%s"
            % (d["enc"], d["count"], d["index"], d["blen"],
               d["payload"][:16].hex()))


def ack_status(d):
    """ACK messages carry payload[0] in {0x13,0x14}; for a single frame the
    reassembled body starts at payload[2], which is the status byte."""
    if not d or not d["payload"] or d["payload"][0] not in ACK_TYPES:
        return None
    p = d["payload"]
    return p[2] if len(p) >= 3 else 0


def wait_ack(poll, timeout, label, verbose):
    t0 = time.time()
    while time.time() - t0 < timeout:
        msg = poll()
        if msg is not None:
            d = decode_reply(msg)
            status = ack_status(d)
            if status is not None:
                if verbose:
                    print("  <- ACK %s" % describe_reply(msg), file=sys.stderr)
                return status
            if verbose:
                print("  <- (non-ACK) %s" % describe_reply(msg), file=sys.stderr)
        time.sleep(0.001)
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("firmware")
    ap.add_argument("--transport", choices=["none", "rawmidi", "alsa", "usb"],
                    default="none")
    ap.add_argument("--rawmidi", default=None,
                    help="rawmidi node, e.g. /dev/snd/midiC2D0 (auto-detected)")
    ap.add_argument("--port", default=None,
                    help="rtmidi ALSA port name or index (--transport alsa)")
    ap.add_argument("--vid", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--pid", type=lambda s: int(s, 0), default=None)
    ap.add_argument("--timeout", type=float, default=10.0,
                    help="seconds to wait for each ACK (default 10)")
    ap.add_argument("--no-ack", action="store_true",
                    help="blind pacing (ignore replies; debugging only)")
    ap.add_argument("--probe", action="store_true",
                    help="send only the init frame, print replies, then exit")
    ap.add_argument("--confirm-model", "--expect-model", dest="confirm_model",
                    default=None, help="expected HTFW model string")
    ap.add_argument("--allow-model-mismatch", action="store_true",
                    help="flash even if the card name and the image model differ")
    ap.add_argument("--i-understand-the-risk", action="store_true")
    a = ap.parse_args()

    fw = htfw.parse(a.firmware)
    if a.confirm_model and not htfw.check_model(fw, a.confirm_model):
        sys.exit("refusing: model %r != %r" % (fw["model"], a.confirm_model))
    for w in fw["warnings"]:
        print("WARNING: %s" % w, file=sys.stderr)

    actions = build_actions(fw)
    wire = sum(len(f) for f, _ in actions)
    print("HTFW %r version field %s, image tag %s: %d segments, %d B payload, "
          "%d frames, %d wire bytes, %d B chunks"
          % (fw["model"], fw["version_raw"], fw["image_version"] or "-",
             len(fw["segments"]), fw["payload_len"], len(actions), wire, CHUNK),
          file=sys.stderr)
    for s in fw["segments"]:
        print("  seg %d flags=%#04x addr=%#010x off=%#08x len=%d (%d frames)"
              % (s["index"], s["flags"], s["addr"], s["dataoff"], s["length"],
                 math.ceil((2 + s["length"]) / CHUNK)), file=sys.stderr)

    dry = a.transport == "none" or not a.i_understand_the_risk
    if dry:
        for i in range(min(5, len(actions))):
            print("  %4d %3dB %s" % (i, len(actions[i][0]), actions[i][0].hex()))
        print("  ...")
        for i in range(max(5, len(actions) - 3), len(actions)):
            print("  %4d %3dB %s" % (i, len(actions[i][0]), actions[i][0].hex()))
        print("dry run: nothing sent (pass --i-understand-the-risk to transmit)")
        return 0

    if a.transport == "rawmidi":
        node, card = find_rawmidi(a.rawmidi, fw["model"])
        guard_model(fw, card, a.allow_model_mismatch)
        port = RawMidi(node)
        print("rawmidi %s" % port.path, file=sys.stderr)
        send, poll, keep = port.send, port.poll, port
    elif a.transport == "alsa":
        send, poll, keep = open_alsa(a.port)
    else:
        if a.vid is None or a.pid is None:
            sys.exit("--vid and --pid are required for the usb transport")
        send, poll, keep = open_usb(a.vid, a.pid)

    if a.probe:
        print("probe: sending init only; waiting %.1fs for replies" % a.timeout,
              file=sys.stderr)
        send(init_frame())
        t0 = time.time()
        n = 0
        while time.time() - t0 < a.timeout:
            msg = poll()
            if msg is not None:
                n += 1
                print("  reply %d: %s" % (n, describe_reply(msg)))
            time.sleep(0.002)
        print("probe: %d reply message(s)" % n, file=sys.stderr)
        return 0

    t0 = time.time()
    for i, (frame, expect_ack) in enumerate(actions):
        send(frame)
        if expect_ack and not a.no_ack:
            status = wait_ack(poll, a.timeout, i,
                              verbose=(i < 20 or i % 500 == 0))
            if status is None:
                sys.exit("timeout after frame %d/%d (no ACK in %.1fs)"
                         % (i, len(actions), a.timeout))
            if status != 0:
                sys.exit("device error after frame %d/%d: status=%#x"
                         % (i, len(actions), status))
        if i % 500 == 0:
            print("  %d/%d (%.1fs)" % (i, len(actions), time.time() - t0),
                  file=sys.stderr)
    print("done in %.1fs (%d frames)" % (time.time() - t0, len(actions)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
