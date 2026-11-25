from . import ffrecord, ffrows
from .dump import int_value as _fuse_value
from .optionmap import (BY_KEY, ENGINES, FIELDS, FF_ROW_MAX, FF_ROW_MIN,
                        TOTAL_FBP, TOTAL_GPC, TPC_PER_GPC, SM_PER_TPC,
                        TOTAL_SYS_PIPE, BYTES_PER_FBP, popcount)


def ff_rows_only(dump):
    return {r: v for r, v in dump["ff_rows"].items()
            if FF_ROW_MIN <= r <= FF_ROW_MAX}


def used_ff_rows(dump):
    return sorted(r for r, v in ff_rows_only(dump).items() if v != 0)


def free_ff_rows(dump):
    used = set(used_ff_rows(dump))
    return [r for r in range(FF_ROW_MIN, FF_ROW_MAX + 1) if r not in used]


def replay_blocks(dump):
    return ffrecord.replay(ff_rows_only(dump))


def decode_current(blocks_by_chain):
    from .optionmap import decode_field
    return {f.key: decode_field(blocks_by_chain, f) for f in FIELDS}


def resolve_targets(dump, overrides=None):
    words = dump["option_words"]
    info = _info_words(dump)
    overrides = overrides or {}
    targets = {}
    warnings = []
    for f in FIELDS:
        if not f.burnable:
            continue
        if f.opt_in and f.key not in overrides:
            continue
        if f.proof_keys:
            # Media-engine floorsweep (category "engine"): there is no
            # *_DEFECTIVE register for these, so the STATUS_OPT_* readout is
            # the only evidence that the engine exists on this die --
            # STATUS_OPT_* = OPT_DISABLE | OPT_DEFECTIVE, so the two words
            # having to agree is what says "no defects". If the snapshot did
            # not read them, the field is skipped rather than guessed at: an
            # FF row spent on an engine that turns out to be missing cannot be
            # given back. `--set` does not bypass this, because the value in a
            # `--set` says nothing about the silicon either.
            missing = [k for k in f.proof_keys if k not in info]
            if missing:
                warnings.append(
                    "%s: OPT_*/STATUS_OPT_* not in this snapshot (%s never "
                    "read), so this engine's defect state is unknown and no FF "
                    "row was planned for it -- re-capture the card (the "
                    "readout map grew) before asking for it"
                    % (f.key, "/".join(missing)))
                continue
            targets[f.key] = overrides.get(f.key, 0)
            continue
        if f.key in overrides:
            targets[f.key] = overrides[f.key]
        elif f.defect_key and f.defect_key in words:
            targets[f.key] = words[f.defect_key]
        elif f.category == "pcie":
            targets[f.key] = 0
        elif f.key in words:
            targets[f.key] = words[f.key]
            warnings.append(
                "%s: no %s in dump; assuming current value (no-op)"
                % (f.key, f.defect_key))
        else:
            warnings.append("%s: no value and no defect key; skipped" % f.key)
        if f.key in targets and f.defect_key and f.defect_key in words:
            defect = words[f.defect_key]
            if (targets[f.key] & defect) != defect:
                warnings.append(
                    "%s: target 0x%x does not contain defective 0x%x "
                    "(would enable known-bad blocks)"
                    % (f.key, targets[f.key], defect))
    return targets, warnings


def _info_words(dump):
    """``dump["info"]`` with every value as an int.

    Info words arrive through two channels that write them differently -- the
    probe module through ``ingest`` writes ints, ``capture`` writes
    ``"0x..."`` strings -- so anything doing arithmetic on them has to
    normalise first, exactly like ``option_words``. Bad values are refused
    rather than guessed at.
    """
    return dict((k, _fuse_value(v, "info.%s" % k))
                for k, v in (dump.get("info") or {}).items())


def analyze_media(dump, targets, warnings, info=None):
    """What the media engines and MIG are now, and what the plan makes them.

    There is no ``*_DEFECTIVE`` register for NVDEC/NVJPG/OFA, but the defect
    state is still readable: hardware computes ``STATUS_OPT_* = OPT_DISABLE |
    OPT_DEFECTIVE``, so the two words agreeing proves the engine exists on this
    die, and a STATUS bit outside OPT names a unit that no fuse can switch on.
    That comparison is the whole reason these three fields require the readout
    (``OptionField.proof_keys``) instead of trusting a ``--set``: a burnt row
    spent on silicon that is not there is the one mistake here that cannot be
    undone.
    """
    info = _info_words(dump) if info is None else info
    words = dump["option_words"]
    engines = []
    for label, opt_key, status_key, total, mask, gates in ENGINES:
        planned = all(k in targets for k in gates)
        e = {"label": label, "total": total, "keys": list(gates),
             "read": False, "planned": planned, "now": None, "after": None,
             "defective": None}
        opt, status = info.get(opt_key), info.get(status_key)
        if opt is not None and status is not None:
            # Bits STATUS_OPT has that OPT_DISABLE does not = physical defects.
            defect = status & ~opt & mask
            e.update({"read": True, "opt": opt, "status": status,
                      "defective": defect,
                      "now": total - popcount(opt & mask),
                      "after": total - popcount(
                          (defect if planned else opt) & mask)})
            if planned and defect:
                warnings.append(
                    "%s: STATUS_OPT has 0x%x beyond OPT_DISABLE, so %d of the "
                    "%d units are physically missing -- clearing the fuse "
                    "unlocks the rest but cannot create those, and the FF rows "
                    "spent on them stay spent"
                    % (label, defect & mask, popcount(defect & mask), total))
        engines.append(e)

    # MIG is gated by SYS_PIPE, one pipe per GPC, and it is in the default plan
    # already; what --mig adds is the media engines the profiles report as
    # DEC/JPEG/OFA. 1 pipe is what makes `nvidia-smi mig -lgip` offer a single
    # non-partitionable profile, which is the "MIG works but only 1g" that the
    # community kept running into.
    sp = words.get("sys_pipe_disable")
    sp_def = words.get("sys_pipe_defective", 0)
    sp_after = targets.get("sys_pipe_disable", sp)
    mig = {"read": sp is not None, "defective": sp_def,
           "now": (TOTAL_SYS_PIPE - popcount(sp | sp_def))
                  if sp is not None else None,
           "after": (TOTAL_SYS_PIPE - popcount(sp_after | sp_def))
                    if sp_after is not None else None}
    if mig["after"] == 1:
        why = ("sys_pipe_defective 0x%x leaves one" % sp_def if not sp_after
               else "sys_pipe_disable is that gate and this plan does not "
                    "clear it")
        warnings.append(
            "1 SYS_PIPE after this plan: MIG stays single-instance (`mig "
            "-lgip` shows one non-partitionable 1g profile); %s" % why)

    # Why the FF burn is the only lever: with the software-override route dead
    # on datacenter GA100, no volatile write to CTRL_OPT_* moves STATUS_OPT_*.
    # Note the alias: 0x820084 is the word ffmacro reads as DSOV_STATUS and
    # demands be 0 inside the write window (and the community floorsweep reports
    # call FUSE_DIS_SW_OVR, read as 1 under a running driver -- same register,
    # two names, two ends of the same fact). So the verdict rests on
    # EN_SW_OVERRIDE = 0, which says the override path is not enabled at all,
    # and DSOV is reported alongside so the reader can see both names.
    en, dsov = info.get("en_sw_override"), info.get("dsov_status")
    sw_override = {"read": en is not None and dsov is not None,
                   "en": en, "dsov": dsov,
                   "dead": en is not None and not en}
    # The other half of chain 1's unclaimed 1-bits, read out so the report can
    # say what is *not* being burned and why: DISPLAY (chain1 bits 78..82) and
    # DISP_HEAD stay fused on every GA100 because the part has no display
    # outputs, so those five bits are accounted for rather than "unknown".
    disp, heads = info.get("status_display"), info.get("status_disp_head")
    return {"mig": mig, "engines": engines, "sw_override": sw_override,
            "display": {"read": disp is not None and heads is not None,
                        "status": disp, "disp_head": heads}}


def analyze(dump, overrides=None):
    targets, warnings = resolve_targets(dump, overrides)
    words = dump["option_words"]
    media = analyze_media(dump, targets, warnings, _info_words(dump))

    fbp_cur = words.get("fbp_disable")
    fbp_tgt = targets.get("fbp_disable")
    usable_fbp = None
    fb_gib = None
    fb_now = None
    if fbp_cur is not None:
        fb_now = (TOTAL_FBP - popcount(fbp_cur & 0xfff)) * \
            BYTES_PER_FBP[dump["sku"]]
    if fbp_tgt is not None:
        usable_fbp = TOTAL_FBP - popcount(fbp_tgt & 0xfff)
        fb_gib = usable_fbp * BYTES_PER_FBP[dump["sku"]]
        if dump["sku"] == "8gb" and usable_fbp > 10:
            warnings.append(
                "%d FBP usable -> %d GiB; production A100 caps at 10 FBP/80 "
                "GiB, verify geometry encoding before trusting >80" %
                (usable_fbp, fb_gib))

    gpc_tgt = targets.get("gpc_disable", 0)
    tpc_tgts = [targets.get("tpc_gpc%d_disable" % i, 0) for i in range(TOTAL_GPC)]
    sm_count = None
    per_gpc = []
    if "gpc_disable" in targets:
        sm_count = 0
        for i in range(TOTAL_GPC):
            if (gpc_tgt >> i) & 1:
                per_gpc.append(0)
                continue
            t = TPC_PER_GPC - popcount(tpc_tgts[i] & 0xff)
            per_gpc.append(t * SM_PER_TPC)
            sm_count += t * SM_PER_TPC

    nvlink = targets.get("nvlink_disable")
    pcie_clear = all(targets.get(k) == 0 for k in (
        "disable_gen3_speed_bit1", "disable_gen3_speed_bit9",
        "pcie_magic_gen4_dis", "pcie_boot_gen23_dis", "pcie_boot_gen3_dis"))

    return {
        "sku": dump["sku"],
        "uuid": dump.get("uuid"),
        "fingerprint": dump.get("fingerprint"),
        "ff_rows_state": ffrows.coverage(dump)[0],
        "ff_rows_used": len(used_ff_rows(dump)),
        "ff_rows_free": len(free_ff_rows(dump)),
        "current": decode_current(replay_blocks(dump)),
        "words": words,
        "targets": targets,
        "usable_fbp": usable_fbp,
        "fb_gib": fb_gib,
        "fb_now_gib": fb_now,
        "sm_count": sm_count,
        "sm_per_gpc": per_gpc,
        "nvlink_ok": (nvlink == 0) if nvlink is not None else None,
        "pcie_gen4_ok": pcie_clear,
        "media": media,
        "warnings": warnings,
    }
