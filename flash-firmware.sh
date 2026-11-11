#!/usr/bin/env bash
# Flash firmware to a Sonicake Pocket Master or Smart Box (5868USB chipset).
#
# The device must first be put into update mode manually; there is no software
# way in.
#   Pocket Master: hold the 1st and 2nd footswitch and the VOL/VALUE knob while
#                  powering on, until the screen lights up.
#   Smart Box:     hold PARA while powering on, until the device enters update
#                  mode.
# Connect USB after the device is in update mode.
#
# Uses rawmidi: rtmidi input does not receive the device's ACK frames.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <firmware.bin> [rawmidi_node]" >&2
    echo "  firmware.bin: Pocket Master or Smart Box HTFW image" >&2
    echo "  rawmidi_node: optional, e.g. /dev/snd/midiC2D0 (default: auto-detect)" >&2
    exit 1
fi

FIRMWARE="$1"
RAW="${2:-}"

if [ ! -f "$FIRMWARE" ]; then
    echo "Error: firmware file not found: $FIRMWARE" >&2
    exit 1
fi

ARGS=(--transport rawmidi --i-understand-the-risk)
if [ -n "$RAW" ]; then
    ARGS+=(--rawmidi "$RAW")
fi

exec uv run --with python-rtmidi python "$SCRIPT_DIR/upload.py" \
    "$FIRMWARE" "${ARGS[@]}"
