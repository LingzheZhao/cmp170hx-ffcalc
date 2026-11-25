"""Ingest ffprobe.ko output into UUID-keyed card dumps.

Input is a collected directory produced by scripts/ffscan.sh:

    collected/
      bar0map.tsv                 bdf <TAB> bar0_phys <TAB> nvidia-smi-uuid
      probe_0000_05_00_0.txt      FFPROBE lines for that GPU (from dmesg)

The card identity is the nvidia-smi GPU UUID (chip-derived, survives
reboot and FF burns). `fingerprint` is a burn-invariant hash over the
*_DEFECTIVE words + SBFE bit, used to verify identity when nvidia-smi
is unavailable (e.g. on the glitch bench).
"""
import hashlib
import io
import json
import os
import re

from . import dump as snapshot

LINE = re.compile(r"FFPROBE (\S+) ([0-9a-fA-F]+) ([0-9a-fA-F]+)")
ERR_LINE = re.compile(r"FFPROBE ffrow_error\b(.*)")

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_MAP = os.path.join(_HERE, "data", "ga100-fuses.json")


def load_map(path=None):
    with io.open(path or DEFAULT_MAP, encoding="utf-8") as f:
        return json.load(f)


def sanitize(bdf):
    return re.sub(r"[.:]", "_", bdf)


def parse_log(text, expected_bar0=None):
    """FFPROBE log text -> list of (name, addr, value).

    Hardened framing & integrity checks:
      - If probe_start/probe_end markers are present, extracts ONLY the final
        framed session (preventing stale dmesg lines from an earlier card from
        bleeding in) and verifies probe_end status == 0.
      - Rejects ANY ffrow_error entry or nonzero ffrows_done status.
      - When expected_bar0 is provided, verifies every non-zero register
        address falls inside [expected_bar0, expected_bar0 + 0x1000000) so
        another card's BAR0 lines can never be ingested under this card's UUID.
    """
    parsed = []
    for line in text.splitlines():
        em = ERR_LINE.search(line)
        if em:
            parsed.append(("ffrow_error", 0, em.group(1).strip()))
            continue
        m = LINE.search(line)
        if not m:
            continue
        parsed.append((m.group(1), int(m.group(2), 16), int(m.group(3), 16)))

    # If framed with probe_start, slice from the last probe_start for expected_bar0 (or last overall).
    starts = [i for i, (n, a, _) in enumerate(parsed)
              if n == "probe_start" and (expected_bar0 is None or a == expected_bar0)]
    if starts:
        parsed = parsed[starts[-1]:]
        ends = [i for i, (n, a, _) in enumerate(parsed)
                if n == "probe_end" and (expected_bar0 is None or a == expected_bar0)]
        if not ends:
            raise ValueError("incomplete FFPROBE session: missing probe_end marker")
        end_idx = ends[0]
        if parsed[end_idx][2] != 0:
            raise ValueError("FFPROBE session reported failure status 0x%x" % parsed[end_idx][2])
        parsed = parsed[1:end_idx]

    out = {}
    order = []
    for name, addr, val in parsed:
        if name == "ffrow_error":
            raise ValueError("FFPROBE reported row read error (%s); refusing capture" % (val,))
        if name == "ffrows_done" and val != 0:
            raise ValueError("FFPROBE ffrows_done=%d (nonzero); refusing partial/failed capture" % val)
        if expected_bar0 is not None and addr != 0:
            if not (expected_bar0 <= addr < expected_bar0 + 0x1000000):
                raise ValueError("FFPROBE line %s has addr 0x%x outside expected BAR0 0x%x (cross-card mixup)"
                                 % (name, addr, expected_bar0))
        if name not in out:
            order.append(name)
        out[name] = (addr, val)
    return [(n, out[n][0], out[n][1]) for n in order]


def fingerprint(entries):
    h = hashlib.sha256()
    for name, _addr, val in sorted(entries):
        if name.startswith("defective.") or \
                name == "info.secured_burn_feature_enable":
            h.update(("%s=%08x\n" % (name, val)).encode("ascii"))
    return h.hexdigest()[:16]


FFROW = re.compile(r"ffrow\.(\d+)$")


def build_dump(m, entries, sku="8gb", bdf=None, uuid=None, source=None):
    raw = dict((name, val) for name, _addr, val in entries)
    ff_rows = {}
    for name, val in raw.items():
        mm = FFROW.match(name)
        if mm:
            ff_rows[int(mm.group(1))] = val
    words = {}
    for key, loc in m["fields"].items():
        fused = raw.get(key + ".fused")
        status = raw.get(key + ".status")
        cur = status if status is not None else fused
        if cur is None:
            continue
        words[key] = cur
        if fused is not None and status is not None and fused != status:
            words[key + "__fused"] = fused
    for key, spec in m["bit_fields"].items():
        w = raw.get("bitfield." + key)
        if w is not None:
            words[key] = (w >> spec["bit"]) & 1
    for key in m["defective"]:
        w = raw.get("defective." + key)
        if w is not None:
            words[key] = w
    info = {}
    for name in m["info"]:
        w = raw.get("info." + name)
        if w is not None:
            info[name] = w
    dump = {"sku": sku, "ff_rows": ff_rows, "option_words": words,
            "info": info, "source": source or "ffprobe.ko",
            "read_only": not ff_rows}
    if bdf:
        dump["bdf"] = bdf
    if uuid:
        dump["uuid"] = uuid
    dump["fingerprint"] = fingerprint(entries)
    return dump


def read_collected(dirpath, m=None, sku="8gb"):
    """Yield dumps for every GPU row in collected/bar0map.tsv."""
    m = m or load_map()
    path = os.path.join(dirpath, "bar0map.tsv")
    with io.open(path, encoding="utf-8") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 2:
                continue
            bdf, bar0 = parts[0], parts[1]
            uuid = parts[2] if len(parts) > 2 else None
            log = os.path.join(dirpath, "probe_%s.txt" % sanitize(bdf))
            if not os.path.exists(log):
                continue
            with io.open(log, encoding="utf-8", errors="replace") as lf:
                exp_bar0 = int(bar0, 16) if bar0 else None
                entries = parse_log(lf.read(), expected_bar0=exp_bar0)
            dump = build_dump(m, entries, sku=sku, bdf=bdf, uuid=uuid,
                              source="ffprobe.ko@%s" % bar0)
            yield dump


def card_id(dump):
    """Filesystem-safe unique id for a card: UUID without prefix, or fp."""
    uuid = dump.get("uuid") or ""
    if uuid.startswith("GPU-"):
        return uuid[4:]
    return uuid or "fp-" + dump.get("fingerprint", "unknown")


def save_dump(outdir, dump):
    """Write cards/<id>.json through the snapshot codec: every value checked,
    one on-disk shape, and the file renamed into place only after it has been
    read back, so an interrupted scan cannot leave a card without a
    snapshot."""
    if not os.path.isdir(outdir):
        os.makedirs(outdir)
    path = os.path.join(outdir, card_id(dump) + ".json")
    snapshot.atomic_write_json(path, snapshot.to_json_form(dump, path))
    return path
