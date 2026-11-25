from . import ffrecord, ffrows
from .analyze import free_ff_rows, replay_blocks, used_ff_rows
from .optionmap import BY_KEY, FIELDS, FF_ROW_MAX, FF_ROW_MIN, decode_field


def simulate(dump, plan_obj):
    errors = []
    warnings = []
    for idfield in ("uuid", "fingerprint"):
        p, d = plan_obj.get(idfield), dump.get(idfield)
        if p and d and p != d:
            errors.append("plan %s %s does not match card %s"
                          % (idfield, p, d))
    state, missing = ffrows.coverage(dump)
    if state != "complete":
        errors.append(
            "ff rows readout %s (%d of %d FF rows unknown): row occupancy "
            "and old values cannot be verified -- how to fix: %s"
            % (state, len(missing), ffrows.N_FF_ROWS, ffrows.GUIDANCE))
        return {"table": [], "errors": errors, "warnings": warnings,
                "pending": [], "ff_rows_used_after": None}
    base = {c: dict(b) for c, b in replay_blocks(dump).items()}
    after = {c: dict(b) for c, b in base.items()}
    used = set(used_ff_rows(dump))
    free = set(free_ff_rows(dump))

    for rec in plan_obj["burn"]:
        row = rec["row"]
        chain, blk = rec["chain"], rec["block"]
        data = int(rec["new"], 0)
        enc = int(rec["record"], 0)
        if ffrecord.encode(chain, blk, data) != enc:
            errors.append("row %d: record 0x%08x does not match chain/block/data"
                          % (row, enc))
        if not FF_ROW_MIN <= row <= FF_ROW_MAX:
            errors.append("row %d outside FF range" % row)
        elif row in used:
            errors.append("row %d already burned" % row)
        if row in [r["row"] for r in plan_obj["burn"]
                   if r is not rec and r["row"] == row]:
            errors.append("row %d used by two planned records" % row)
        if row not in free:
            errors.append("row %d is not a free FF row in the dump" % row)
        if int(rec.get("old"), 0) != base.get(chain, {}).get(blk, 0):
            errors.append("row %d: planned old 0x%04x != replayed 0x%04x"
                          % (row, int(rec["old"], 0),
                             base.get(chain, {}).get(blk, 0)))
        after.setdefault(chain, {})[blk] = data

    merged = dict(dump["ff_rows"])
    for rec in plan_obj["burn"]:
        merged[rec["row"]] = int(rec["record"], 0)
    # Replay merged rows in physical row order (matching cold-boot hardware order!),
    # not JSON list order.
    after = replay_blocks({"ff_rows": merged})

    def decode(blocks):
        return {f.key: decode_field(blocks, f) for f in FIELDS}

    cur = decode(base)
    new = decode(after)
    targets = {k: int(v, 0) for k, v in plan_obj["targets"].items()}

    table = []
    pending = []
    burned_keys = {k for rec in plan_obj["burn"] for k in rec["fields"]}
    for f in FIELDS:
        if f.key in cur or f.key in new:
            changed = cur.get(f.key) != new.get(f.key)
            table.append({
                "key": f.key, "name": f.name, "chain": f.chain,
                "bit": "%d+%d" % (f.bit, f.width),
                "before": "0x%x" % cur.get(f.key, 0),
                "after": "0x%x" % new.get(f.key, 0),
                "changed": changed,
            })
            if changed and f.key in targets and new.get(f.key) != targets[f.key]:
                errors.append("%s: after=0x%x != target 0x%x"
                              % (f.key, new.get(f.key), targets[f.key]))
            if not changed and f.key in targets and \
                    cur.get(f.key, 0) != targets[f.key]:
                if f.key in burned_keys:
                    errors.append("%s: burned but still != target 0x%x"
                                  % (f.key, targets[f.key]))
                else:
                    pending.append(f.key)

    # Check collateral changes on ALL fields (including opt-in / device-ID fields!)
    # at bit granularity: any bit changed outside the bit positions owned by
    # burned_keys | targets is reported as a collateral error.
    auth_bits = set()
    for key in burned_keys | set(targets):
        fld = BY_KEY.get(key)
        if fld is not None:
            for bit_pos in range(fld.bit, fld.bit + fld.width):
                auth_bits.add((fld.chain, bit_pos))
    for f in FIELDS:
        if f.key in burned_keys or f.key in targets:
            continue
        diff = cur.get(f.key, 0) ^ new.get(f.key, 0)
        if not diff:
            continue
        unauth = 0
        for i in range(f.width):
            if ((diff >> i) & 1) and (f.chain, f.bit + i) not in auth_bits:
                unauth |= (1 << i)
        if unauth:
            errors.append("%s: collateral change 0x%x -> 0x%x (unauthorized bits 0x%x)"
                          % (f.key, cur[f.key], new[f.key], unauth))

    free_after = len(free) - len(plan_obj["burn"])
    if free_after < 0:
        errors.append("plan does not fit in free FF rows")
    warnings.append("%d of %d free FF rows consumed; %d left for corrections"
                    % (len(plan_obj["burn"]), len(free), free_after))
    return {"table": table, "errors": errors, "warnings": warnings,
            "pending": pending,
            "ff_rows_used_after": len(used) + len(plan_obj["burn"])}
