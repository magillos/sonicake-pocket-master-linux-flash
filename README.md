# sonicake-flash

Unofficial Linux tools to inspect and flash **Sonicake Pocket Master** and
**Sonicake Smart Box** HTFW firmware over their MIDI SysEx protocol, recovered
from `5868USB.dll`.

Both products ship the same firmware container and the same 5-segment flash
map; only the model string and the payload differ, so one toolset covers both.

> **WARNING:** Experimental. Flashing the wrong image, or interrupting an
> upload, can brick the pedal. Use at your own risk and keep the stock firmware
> plus the official Sonicake Manager as a fallback.
>
> **Smart Box support is not upstream.** It was written and tested against
> **one** Smart Box unit (USB `84ef:0287`) with a single
> successful flash.
> There is no warranty of any kind: if it bricks your device, that risk is
> entirely yours.

## Files

| file | purpose |
|---|---|
| `htfw.py` | Parse an HTFW container (header, segment table, payload). |
| `sxproto.py` | Encode/decode the 5868USB SysEx frames (CRC-8, nibble expansion). |
| `upload.py` | ACK-paced multi-segment uploader; dry-runs by default. |
| `flash-firmware.sh` | Wrapper around `upload.py` using the rawmidi transport. |
| `sonicake-flash.md` | Full protocol/container reference and findings. |
| `probe.py` | Dump USB descriptors. |

## Requirements

- Linux with ALSA rawmidi. Both devices are class-compliant USB-MIDI:
  Pocket Master `84ef:0285`, Smart Box `84ef:0287`.
- `uv` (or Python 3.10+) and membership in the `audio` group.
- The pedal must be **manually put into update mode** first.

## Enter update mode

The button combination is mandatory; there is no software way in.

**Pocket Master** — hold the **1st and 2nd footswitch** and the **VOL/VALUE
knob** at the same time, then power on and keep holding until the screen lights
up.

**Smart Box** — hold **PARA** while powering on, until the device enters update
mode.

Connect USB after the device is in update mode.

## Usage

Inspect a firmware file (no device access):

```sh
python3 htfw.py ~/Downloads/PocketMaster_CFW0.9.8_base1.3.3.bin
```

Refuse a file that is not for the device you meant to flash:

```sh
python3 htfw.py --expect-model "Smart Box" "Smart Box Firmware V1.0.6.bin"
```

Dry run — shows the frame plan and sends nothing:

```sh
uv run --with python-rtmidi python upload.py FIRMWARE.bin
```

Probe — sends only the init frame and prints replies (confirms update mode):

```sh
uv run --with python-rtmidi python upload.py FIRMWARE.bin \
    --transport rawmidi --probe --timeout 5 --i-understand-the-risk
```

Flash:

```sh
./flash-firmware.sh FIRMWARE.bin
# or: uv run --with python-rtmidi python upload.py FIRMWARE.bin \
#       --transport rawmidi --i-understand-the-risk
```

The rawmidi node is auto-detected by matching the ALSA card against the
firmware's model (Smart Box shows up as card id `Box`, description `Smart Box`,
node `/dev/snd/midiC3D0`); override with `--rawmidi /dev/snd/midiCxDy` if
needed.

## Notes

- Use the **rawmidi** transport. `rtmidi` input does not receive the pedal's
  ACK frames.
- The upload is ACK-paced and long (~112k frames for a full image); keep the
  pedal powered and connected.
- The firmware's `0x1C` header field is not a version on every model: the
  Smart Box 1.0.6 image stores `42 00 00 04`, so the 1.3.3-style decode prints a
  bogus `0.0.4`. Trust the release file name or the image tag (`V132`, `V101`)
  that `htfw.py` prints next to the raw bytes.
- The uploader checks the image model against the ALSA card name and refuses on
  a mismatch (override with `--allow-model-mismatch`).
- Status: the container, frame format, and init ACK are verified on hardware;
  the full multi-segment upload has not yet been completed.
- See `sonicake-flash.md` for the protocol details and current caveats.
