#!/usr/bin/env python3
"""Capture option words (and optionally raw fuse rows) from a live CMP 170HX.

The word capture is strictly read-only: pure reads against BAR0 via
/sys/.../resource0. Address table is vendored at
ffcalc/data/ga100-fuses.json.

Hardened safety guarantees:
  - Supports 8GB (0x20c2), 10GB (0x2082), and converted A100 (0x20b5) GA100 GPUs.
  - Refuses to auto-pick a GPU when >1 candidate is present (pass --bdf).
  - Validates --sku against the actual PCI device ID (no mislabeling 20c2 as 10gb).
  - Single aligned 32-bit BAR0 reads/writes with strict alignment and bounds checks.
  - --read-ff-rows aborts on controller fault instead of saving a half-broken dump.

Run on the card's host as root:
    python3 -m ffcalc.capture --bdf 0000:05:00.0 --sku 8gb \
        --read-ff-rows -o dump.json
"""
import argparse
import io
import json
import mmap
import operator
import os
import struct
import sys

from . import dump as snapshot
from . import ffmacro, ffrows
from .optionmap import A100_DEVID, CMP_DEVID

BAR0_LEN = 0x1000000
CMP_10GB_DEVID = 0x2082

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MAP = os.path.join(_HERE, "data", "ga100-fuses.json")

# Supported GA100 PCI device IDs (8GB CMP 170HX, 10GB CMP 170HX, A100 PCIe 80GB).
DEVICE_IDS = tuple("0x%04x" % v for v in (CMP_DEVID, CMP_10GB_DEVID, A100_DEVID))


def _scan_devices(base="/sys/bus/pci/devices"):
    """Return sorted list of (bdf, dev_id_str) for supported NVIDIA GA100 devices."""
    cands = []
    for dev in sorted(os.listdir(base)):
        venp = os.path.join(base, dev, "vendor")
        vp = os.path.join(base, dev, "device")
        try:
            with io.open(venp) as f:
                ven_id = f.read().strip().lower()
            with io.open(vp) as f:
                dev_id = f.read().strip().lower()
        except IOError:
            continue
        if ven_id != "0x10de" or dev_id not in DEVICE_IDS:
            continue
        cands.append((dev, dev_id))
    return cands


def select_device(bdf=None, base="/sys/bus/pci/devices"):
    """Select exactly one supported GA100 device; refuse ambiguity when >1 GPU exists."""
    cands = _scan_devices(base=base)
    if bdf:
        want = bdf if len(bdf.split(":")) == 3 else "0000:" + bdf
        cands = [c for c in cands if c[0] == want]
        if not cands:
            raise SystemExit("device %s is not a supported NVIDIA GA100 (%s)"
                             % (want, " or ".join(DEVICE_IDS)))
    if not cands:
        raise SystemExit("no device %s found" % " or ".join(DEVICE_IDS))
    if len(cands) > 1:
        raise SystemExit("multiple NVIDIA GA100 GPUs found (%s); pass --bdf explicitly"
                         % ", ".join(b for b, _ in cands))
    return cands[0]


def open_bar0(bdf=None, read_only=False):
    base = "/sys/bus/pci/devices"
    chosen_bdf, _dev_id = select_device(bdf=bdf, base=base)
    path = os.path.join(base, chosen_bdf, "resource0")
    flags = os.O_RDONLY if read_only else (os.O_SYNC | os.O_RDWR)
    access = mmap.ACCESS_READ if read_only else mmap.ACCESS_WRITE
    fd = os.open(path, flags)
    try:
        length = os.path.getsize(path) or BAR0_LEN
        mm = mmap.mmap(fd, length, access=access)
    finally:
        os.close(fd)
    return chosen_bdf, mm


def _off(addr):
    """BAR0 offset as an int, from either address style we pass around."""
    if isinstance(addr, str):
        return int(addr, 0)
    return operator.index(addr)


def _check_aligned_bounds(mm, off):
    if isinstance(off, bool) or (off & 3) != 0 or off < 0:
        raise ValueError("unaligned or negative BAR0 offset: 0x%x" % off)
    if isinstance(mm, (mmap.mmap, bytearray, memoryview)):
        if off + 4 > len(mm):
            raise ValueError("BAR0 offset 0x%x out of bounds (len=0x%x)" % (off, len(mm)))


def rd(mm, addr):
    off = _off(addr)
    _check_aligned_bounds(mm, off)
    if isinstance(mm, (mmap.mmap, bytearray, memoryview)):
        mv = memoryview(mm)[off:off + 4].cast("I")
        try:
            return int(mv[0])
        finally:
            mv.release()
    mm.seek(off)
    return struct.unpack("<I", mm.read(4))[0]


def wr(mm, addr, value):
    off = _off(addr)
    _check_aligned_bounds(mm, off)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("BAR0 write value must be an int: %r" % (value,))
    val = value & 0xFFFFFFFF
    if isinstance(mm, (mmap.mmap, bytearray, memoryview)):
        mv = memoryview(mm)[off:off + 4].cast("I")
        try:
            mv[0] = val
        finally:
            mv.release()
        return
    mm.seek(off)
    mm.write(struct.pack("<I", val))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bdf")
    ap.add_argument("--map", default=DEFAULT_MAP)
    ap.add_argument("--sku", default=None, choices=("8gb", "10gb"),
                    help="SKU label (auto-derived from PCI device ID when omitted; validated when given)")
    ap.add_argument("-o", "--out", default="dump.json")
    ap.add_argument("--ffrows", metavar="FILE",
                    help="FF rows file read out elsewhere; merged into the "
                         "dump (see also --read-ff-rows)")
    ap.add_argument("--read-ff-rows", action="store_true",
                    help="capture all 512 physical rows via fuse macro "
                         "CMD_READ (writes FUSEADDR/FUSECTRL; idle card "
                         "only)")
    args = ap.parse_args()

    try:
        with io.open(args.map, encoding="utf-8") as f:
            m = json.load(f)
    except ValueError as e:
        raise SystemExit("bad option map %s: %s" % (args.map, e))

    chosen_bdf, dev_id = select_device(args.bdf)
    inferred_sku = "10gb" if dev_id == ("0x%04x" % CMP_10GB_DEVID) else "8gb"
    if args.sku is not None and dev_id != ("0x%04x" % A100_DEVID) and args.sku != inferred_sku:
        raise SystemExit("SKU mismatch: --sku %s does not match PCI device %s (%s -> %s)"
                         % (args.sku, chosen_bdf, dev_id, inferred_sku))
    sku = args.sku or inferred_sku

    bdf, mm = open_bar0(chosen_bdf, read_only=(not args.read_ff_rows))
    try:
        # Fail-fast health gate before reading option map.
        ctrl = rd(mm, ffmacro.FUSECTRL)
        if ffmacro.is_poisoned(ctrl) or ffmacro.is_dead(ctrl):
            raise SystemExit("ABORT: FUSECTRL=0x%08x (poisoned/dead BAR0; stopped immediately)" % ctrl)
        words = {}
        for key, loc in m["fields"].items():
            fused = rd(mm, loc["fused"]) if loc.get("fused") else None
            status = rd(mm, loc["status"]) if loc.get("status") else None
            cur = status if status is not None else fused
            words[key] = "0x%x" % cur
            if fused is not None and status is not None and fused != status:
                words[key + "__fused"] = "0x%x" % fused

        for key, spec in m["bit_fields"].items():
            w = rd(mm, spec["reg"])
            words[key] = "0x%x" % ((w >> spec["bit"]) & 1)

        for key, addr in m["defective"].items():
            words[key] = "0x%x" % rd(mm, addr)

        info = {}
        for name, addr in m["info"].items():
            info[name] = "0x%x" % rd(mm, addr)

        ff_rows = {}
        if args.ffrows:
            try:
                rows = ffrows.parse_file(args.ffrows)
            except ValueError as e:
                raise SystemExit("bad FF rows file %s: %s" % (args.ffrows, e))
            ff_rows.update((r, v) for r, v in rows.items())
        wrote_rows = bool(args.read_ff_rows)
        if args.read_ff_rows:
            try:
                ffmacro.capture_rows(lambda a: rd(mm, a),
                                     lambda a, v: wr(mm, a, v), rows=ff_rows)
            except ffmacro.FuseControllerError as e:
                raise SystemExit("ABORT: CMD_READ pass failed after %d row(s): %s"
                                 % (len(ff_rows), e))
    finally:
        mm.close()
    dump = {"sku": sku, "bdf": bdf, "pci_device": dev_id, "ff_rows": ff_rows,
            "option_words": words, "info": info,
            "read_only": not wrote_rows}
    try:
        dump = snapshot.to_json_form(dump, args.out)
        snapshot.atomic_write_json(args.out, dump)
    except snapshot.BadSnapshot as e:
        raise SystemExit("cannot write %s: %s" % (args.out, e))
    state, missing = ffrows.coverage(dump)
    if state != "complete":
        print("note: FF rows %s (%d of %d unknown); ffcalc will not emit a "
              "burn plan until a full readout is merged (ffcalc mergeff)"
              % (state, len(missing), ffrows.N_FF_ROWS))
    print("wrote %s (%s, sku=%s)" % (args.out, bdf, sku))


if __name__ == "__main__":
    sys.exit(main())
