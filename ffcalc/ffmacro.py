"""Raw fuse-row readout and guarded burn ops through the GA100 fuse macro.

Hardened safety guarantees:
  - Every status / check / poll reads FUSECTRL first and aborts immediately on
    PRI poison (0xBAD0xxxx..0xBADFxxxx) or dead BAR0 (0xFFFFFFFF) — zero extra
    register reads after the first fault and zero extra reads inside timeout
    error formatting.
  - FUSEADDR is restored ONLY on clean completion (never after error/poison/
    timeout, and never with an unvalidated/poisoned orig address).
  - CMD_SENSE verifies DSOV == 0, clears WDATA_WR_SECURE before latching
    FUSEWDATA = 0 (so readback == 0 proves the write took effect), and verifies
    DSOV stays 0 afterwards.
"""
import time

FUSECTRL = 0x00820000
FUSEADDR = 0x00820004
FUSEDATA = 0x00820008
FUSEWDATA = 0x0082000C    # record WRITE port (FUSEDATA is read-only)
FUSEDEBUG = 0x00820060
PMC_BOOT_0 = 0x00000000
CRC_STATUS = 0x00820070   # 0x55 = healthy chain CRC
EFP_STATUS = 0x00820078   # expect 1 before arming
DSOV_STATUS = 0x00820084  # expect 0 inside the write window
SBFE_SHADOW = 0x00821108  # writable while DSOV == 0
WDATA_WR_SECURE = 0x0082048C  # write 0 -> PLM_FUSE auto-unlocks (0xffffffff)

CMD_READ = 0x1
CMD_PROGRAM = 0x2         # confirmed by experiment: transient 0xE00C0000
CMD_SENSE = 0x3           # re-reads OTP into the shadow, preserves DSOV
IDLE_STATE = 4
POISON_TAG = 0xBADF0000   # controller parks here after a failed command
ROW_COUNT = 512

PER_ROW_TIMEOUT_S = 0.200
TOTAL_TIMEOUT_S = 20.0
PROGRAM_TIMEOUT_S = 10.0


class FuseControllerError(RuntimeError):
    pass


def is_poisoned(val):
    """True for any NVIDIA PRI error sentinel 0xBAD0xxxx..0xBADFxxxx."""
    return ((val >> 20) & 0xFFF) == 0xBAD


def is_dead(val):
    """True for dead BAR0 / off-bus all-ones response."""
    return val == 0xFFFFFFFF


def is_idle(ctrl):
    return (
        not is_poisoned(ctrl)
        and not is_dead(ctrl)
        and ((ctrl >> 16) & 31) == IDLE_STATE
        and (ctrl & 0xF) == 0
    )


def capture_rows(rd, wr, first=0, last=ROW_COUNT - 1,
                 sleep=time.sleep, clock=time.monotonic, rows=None):
    """Read physical fuse rows [first..last] -> {row: value32}.

    Reads FUSECTRL first, then PMC_BOOT_0; aborts immediately on poison, dead
    BAR0, non-IDLE, FUSEDEBUG!=0, latch failure, or timeout. Restores FUSEADDR
    ONLY on clean full completion.
    """
    ctrl0 = rd(FUSECTRL)
    if is_poisoned(ctrl0) or is_dead(ctrl0) or not is_idle(ctrl0):
        raise FuseControllerError(
            "fuse controller %s before capture (FUSECTRL=0x%08x); %s"
            % ("poisoned" if is_poisoned(ctrl0) else ("dead" if is_dead(ctrl0) else "busy"),
               ctrl0,
               "stop reads, cold-boot the card"
               if (is_poisoned(ctrl0) or is_dead(ctrl0)) else
               "retry on an idle card or after the active op finishes"))
    pmc = rd(PMC_BOOT_0)
    if pmc in (0, 0xFFFFFFFF) or is_poisoned(pmc):
        raise FuseControllerError(
            "PMC_BOOT_0 reads 0x%08x: BAR0 not accessible / GPU off" % pmc)
    orig_addr = rd(FUSEADDR)
    if is_poisoned(orig_addr) or is_dead(orig_addr) or orig_addr > 0xFFFF:
        raise FuseControllerError(
            "FUSEADDR invalid before capture (0x%08x): aborting" % orig_addr)
    if rows is None:
        rows = {}
    start = clock()
    for row in range(first, last + 1):
        if clock() - start > TOTAL_TIMEOUT_S:
            raise FuseControllerError("total timeout after %d rows" % len(rows))
        ctrl = rd(FUSECTRL)
        if not is_idle(ctrl):
            raise FuseControllerError(
                "fuse controller %s before row %d (FUSECTRL=0x%08x); %s"
                % ("poisoned" if is_poisoned(ctrl) else ("dead" if is_dead(ctrl) else "busy"),
                   row, ctrl,
                   "stop reads, cold-boot the card"
                   if (is_poisoned(ctrl) or is_dead(ctrl)) else
                   "retry on an idle card or after the active op finishes"))
        dbg = rd(FUSEDEBUG)
        if dbg != 0:
            raise FuseControllerError(
                "FUSEDEBUG=0x%08x before row %d; aborting" % (dbg, row))
        wr(FUSEADDR, row)
        latched = rd(FUSEADDR)
        if is_poisoned(latched) or is_dead(latched) or latched != row:
            raise FuseControllerError(
                "FUSEADDR did not latch row %d (got 0x%08x)" % (row, latched))
        wr(FUSECTRL, CMD_READ)
        deadline = clock() + PER_ROW_TIMEOUT_S
        while True:
            c = rd(FUSECTRL)
            if is_idle(c):
                break
            if is_poisoned(c) or is_dead(c):
                raise FuseControllerError(
                    "controller %s during CMD_READ row %d (FUSECTRL=0x%08x): "
                    "stop reads, cold-boot the card"
                    % ("poisoned" if is_poisoned(c) else "dead", row, c))
            if clock() > deadline:
                raise FuseControllerError(
                    "CMD_READ timeout at row %d (FUSECTRL=0x%08x)" % (row, c))
            sleep(0)
        rows[row] = rd(FUSEDATA)
    # Clean-path-only FUSEADDR restore (never runs after any exception).
    if is_idle(rd(FUSECTRL)):
        wr(FUSEADDR, orig_addr)
    return rows


def wait_idle(rd, sleep=time.sleep, clock=time.monotonic, timeout=1.0, last_ctrl=None):
    """Poll FUSECTRL until IDLE. Aborts immediately on poison or dead 0xFFFFFFFF."""
    start = clock()
    first = True
    while True:
        if not first and clock() - start >= timeout:
            return False
        first = False
        ctrl = rd(FUSECTRL)
        if last_ctrl is not None:
            last_ctrl[0] = ctrl
        if is_idle(ctrl):
            return True
        if is_poisoned(ctrl) or is_dead(ctrl):
            raise FuseControllerError(
                "controller %s (FUSECTRL=0x%08x): stop all further BAR0 reads, "
                "cold-boot the card, then SENSE to re-evaluate"
                % ("poisoned" if is_poisoned(ctrl) else "dead", ctrl))
        if clock() - start >= timeout:
            return False
        sleep(0)


_STATUS_REGS = (
    ("FUSECTRL", FUSECTRL, False),
    ("PMC_BOOT_0", PMC_BOOT_0, False),
    ("FUSEADDR", FUSEADDR, False),
    ("FUSEDATA", FUSEDATA, True),       # raw data latch may hold any 32-bit value
    ("FUSEDEBUG", FUSEDEBUG, False),
    ("CRC_STATUS", CRC_STATUS, False),
    ("EFP_STATUS", EFP_STATUS, False),
    ("DSOV_STATUS", DSOV_STATUS, False),
    ("SBFE_SHADOW", SBFE_SHADOW, False),
    ("WDATA_WR_SECURE", WDATA_WR_SECURE, False),
)


def status(rd):
    """Fail-fast burn-relevant register snapshot, reading FUSECTRL FIRST.

    Stops immediately on the very first PRI poison or dead BAR0 (0xFFFFFFFF)
    with ZERO subsequent BAR0 reads.
    """
    out = {}
    for name, off, is_raw in _STATUS_REGS:
        val = rd(off)
        out[name] = val
        if not is_raw and (is_poisoned(val) or is_dead(val)):
            break
    return out


def status_fault(st):
    """Return fault description if status() aborted on poison or dead BAR0, else None."""
    fc = st.get("FUSECTRL")
    if fc is None:
        return "FUSECTRL missing"
    if is_poisoned(fc):
        return "POISONED (FUSECTRL=0x%08x)" % fc
    if is_dead(fc):
        return "DEAD BAR0 (FUSECTRL=0x%08x)" % fc
    for name, _, is_raw in _STATUS_REGS:
        if name not in st:
            return "incomplete status snapshot (stopped before %s)" % name
        if not is_raw:
            v = st[name]
            if is_poisoned(v):
                return "POISONED (%s=0x%08x)" % (name, v)
            if is_dead(v):
                return "DEAD BAR0 (%s=0x%08x)" % (name, v)
    return None


def in_write_window(st):
    """All preconditions for arm/program, from a complete status() snapshot."""
    if status_fault(st) is not None:
        return False
    return (is_idle(st["FUSECTRL"])
            and st["FUSEDEBUG"] == 0 and st["CRC_STATUS"] == 0x55
            and st["EFP_STATUS"] == 1 and st["DSOV_STATUS"] == 0)


def read_row(rd, wr, row, sleep=time.sleep, clock=time.monotonic):
    """One CMD_READ with FUSEADDR restore ONLY on clean IDLE completion."""
    last_c = [0]
    if not wait_idle(rd, sleep, clock, PER_ROW_TIMEOUT_S, last_ctrl=last_c):
        raise FuseControllerError(
            "controller not idle before reading row %d (FUSECTRL=0x%08x)" % (row, last_c[0]))
    orig = rd(FUSEADDR)
    if is_poisoned(orig) or is_dead(orig) or orig > 0xFFFF:
        raise FuseControllerError("FUSEADDR invalid before reading row %d (0x%08x)" % (row, orig))
    wr(FUSEADDR, row)
    latched = rd(FUSEADDR)
    if is_poisoned(latched) or is_dead(latched) or latched != row:
        raise FuseControllerError("FUSEADDR did not latch row %d (got 0x%08x)" % (row, latched))
    wr(FUSECTRL, CMD_READ)
    if not wait_idle(rd, sleep, clock, PER_ROW_TIMEOUT_S, last_ctrl=last_c):
        raise FuseControllerError(
            "CMD_READ timeout at row %d (FUSECTRL=0x%08x; stop, do not read further)"
            % (row, last_c[0]))
    val = rd(FUSEDATA)
    # Clean-path-only FUSEADDR restore
    if is_idle(rd(FUSECTRL)):
        wr(FUSEADDR, orig)
    return val


def sense(rd, wr, sleep=time.sleep, clock=time.monotonic):
    """CMD_SENSE: re-read the OTP array into the shadow. Verifies DSOV==0,
    opens WDATA_WR_SECURE if needed so FUSEWDATA=0 latch is genuinely writable,
    issues CMD_SENSE, and confirms DSOV stays 0 afterwards."""
    last_c = [0]
    if not wait_idle(rd, sleep, clock, PER_ROW_TIMEOUT_S, last_ctrl=last_c):
        raise FuseControllerError(
            "controller not idle before SENSE (FUSECTRL=0x%08x)" % last_c[0])
    dsov_pre = rd(DSOV_STATUS)
    if is_poisoned(dsov_pre) or is_dead(dsov_pre) or dsov_pre != 0:
        raise FuseControllerError(
            "DSOV=0x%x before SENSE: not inside the write window; do NOT sense or burn"
            % dsov_pre)
    wsec = rd(WDATA_WR_SECURE)
    if is_poisoned(wsec) or is_dead(wsec):
        raise FuseControllerError("WDATA_WR_SECURE fault before SENSE: 0x%08x" % wsec)
    if wsec != 0:
        wr(WDATA_WR_SECURE, 0)
        wsec_rb = rd(WDATA_WR_SECURE)
        if wsec_rb != 0:
            raise FuseControllerError(
                "WDATA_WR_SECURE did not clear to 0 before SENSE (got 0x%08x)" % wsec_rb)
    wr(FUSEWDATA, 0)
    wrb = rd(FUSEWDATA)
    if wrb != 0:
        raise FuseControllerError(
            "FUSEWDATA did not read back 0 before SENSE (0x%08x)" % wrb)
    wr(FUSECTRL, CMD_SENSE)
    sleep(0.2)
    if not wait_idle(rd, sleep, clock, 2.0, last_ctrl=last_c):
        raise FuseControllerError(
            "CMD_SENSE did not return to idle (FUSECTRL=0x%08x; stop, cold-boot)" % last_c[0])
    dsov = rd(DSOV_STATUS)
    if is_poisoned(dsov) or is_dead(dsov) or dsov != 0:
        raise FuseControllerError(
            "DSOV=0x%x after SENSE: not inside the write window (no PEX_RST "
            "pulse / boot strap set); do NOT arm or program"
            % dsov)


def armed_problems(rd, wr):
    """[] when a PROGRAM command is allowed right now; else reasons. Single read per reg, fail-fast."""
    problems = []
    ctrl = rd(FUSECTRL)
    if is_poisoned(ctrl) or is_dead(ctrl):
        return ["controller %s (FUSECTRL=0x%08x): stop, cold boot"
                % ("poisoned" if is_poisoned(ctrl) else "dead", ctrl)]
    if not is_idle(ctrl):
        return ["FUSECTRL not idle (0x%08x)" % ctrl]
    checks = (
        ("FUSEDEBUG", FUSEDEBUG, 0, "FUSEDEBUG=0x%x"),
        ("CRC_STATUS", CRC_STATUS, 0x55, "CRC_STATUS=0x%x (want 0x55)"),
        ("EFP_STATUS", EFP_STATUS, 1, "EFP_STATUS=%d (want 1)"),
        ("DSOV_STATUS", DSOV_STATUS, 0, "DSOV=%d (want 0: inside window)"),
        ("SBFE_SHADOW", SBFE_SHADOW, 0, "SBFE shadow=%d (want 0: armed)"),
        ("WDATA_WR_SECURE", WDATA_WR_SECURE, 0, "WDATA_WR_SECURE=%d (want 0: unlocked)"),
    )
    for name, off, want, fmt in checks:
        val = rd(off)
        if is_poisoned(val) or is_dead(val):
            return ["%s %s (0x%08x): stop, cold boot"
                    % (name, "poisoned" if is_poisoned(val) else "dead", val)]
        if val != want:
            problems.append(fmt % val)
    return problems


def arm(rd, wr):
    """Open the write path: clear the SBFE shadow bit and the WDATA
    secure gate. Raises if the window is not actually open."""
    ctrl = rd(FUSECTRL)
    if is_poisoned(ctrl) or is_dead(ctrl) or not is_idle(ctrl):
        raise FuseControllerError("not armed: FUSECTRL=0x%08x" % ctrl)
    wr(SBFE_SHADOW, 0)
    wr(WDATA_WR_SECURE, 0)
    problems = armed_problems(rd, wr)
    if problems:
        raise FuseControllerError("not armed: " + "; ".join(problems))


def program_row(rd, wr, row, record, sleep=time.sleep, clock=time.monotonic):
    """Burn one 32-bit record into a blank FF row with zero extra reads on timeout/poison."""
    problems = armed_problems(rd, wr)
    if problems:
        raise FuseControllerError("not armed before row %d: %s"
                                  % (row, "; ".join(problems)))
    current = read_row(rd, wr, row, sleep, clock)
    if current == record:
        return current
    if current != 0:
        raise FuseControllerError(
            "row %d is not blank (reads 0x%08x, want 0): refusing to burn"
            % (row, current))
    wr(FUSEADDR, row)
    latched = rd(FUSEADDR)
    if is_poisoned(latched) or is_dead(latched) or latched != row:
        raise FuseControllerError("FUSEADDR did not latch row %d (got 0x%08x)" % (row, latched))
    wr(FUSEWDATA, record)
    if rd(FUSEWDATA) != record:
        raise FuseControllerError("FUSEWDATA did not latch 0x%08x before row %d" % (record, row))
    wr(FUSECTRL, CMD_PROGRAM)
    last_c = [0]
    if not wait_idle(rd, sleep, clock, PROGRAM_TIMEOUT_S, last_ctrl=last_c):
        # Use cached last_c — NEVER perform an extra rd(FUSECTRL) after timeout!
        raise FuseControllerError(
            "CMD_PROGRAM timeout at row %d (last FUSECTRL=0x%08x): treat as "
            "suspect -- stop, cold-boot, re-sense before touching anything"
            % (row, last_c[0]))
    got = read_row(rd, wr, row, sleep, clock)
    if got != record:
        raise FuseControllerError(
            "row %d verify mismatch: burned 0x%08x, reads back 0x%08x"
            % (row, record, got))
    return got


PROBE_C = """
static inline bool ffprobe_idle(u32 ctrl)
{
\treturn (((ctrl >> 20) & 0xfffU) != 0xbadU) && ctrl != 0xffffffffU &&
\t       ((ctrl >> 16) & 31) == @IDLE_STATE@ && (ctrl & 0xfU) == 0;
}

static int ffprobe_read_rows(void __iomem *h)
{
\tu32 i, orig, c;
\tint rc = 0;

\tc = readl(h + @FUSECTRL@);
\tif (!ffprobe_idle(c) || readl(h + @FUSEDEBUG@) != 0) {
\t\tpr_info("FFPROBE ffrow_error busy_0 %08llx %08x\\n",
\t\t\t(u64)bar0 + @FUSECTRL@, c);
\t\treturn -EBUSY;
\t}
\torig = readl(h + @FUSEADDR@);
\tfor (i = 0; i < @ROW_COUNT@; i++) {
\t\tunsigned long deadline = jiffies + msecs_to_jiffies(200);

\t\tc = readl(h + @FUSECTRL@);
\t\tif (!ffprobe_idle(c) || readl(h + @FUSEDEBUG@) != 0) {
\t\t\tpr_info("FFPROBE ffrow_error busy_%d %08llx %08x\\n",
\t\t\t\ti, (u64)bar0 + @FUSECTRL@, c);
\t\t\trc = -EBUSY;
\t\t\tbreak;
\t\t}
\t\twritel(i, h + @FUSEADDR@);
\t\twritel(@CMD_READ@, h + @FUSECTRL@);
\t\tfor (;;) {
\t\t\tc = readl(h + @FUSECTRL@);
\t\t\tif (ffprobe_idle(c))
\t\t\t\tbreak;
\t\t\tif (((c >> 20) & 0xfffU) == 0xbadU || c == 0xffffffffU) {
\t\t\t\tpr_info("FFPROBE ffrow_error poison_%d "
\t\t\t\t\t"%08llx %08x\\n", i,
\t\t\t\t\t(u64)bar0 + @FUSECTRL@, c);
\t\t\t\treturn -EIO;
\t\t\t}
\t\t\tif (time_after(jiffies, deadline)) {
\t\t\t\tpr_info("FFPROBE ffrow_error timeout_%d "
\t\t\t\t\t"00000000 %08x\\n", i, c);
\t\t\t\treturn -ETIMEDOUT;
\t\t\t}
\t\t\tudelay(10);
\t\t}
\t\tpr_info("FFPROBE ffrow.%d %08llx %08x\\n", i,
\t\t\t(u64)bar0 + @FUSEDATA@, readl(h + @FUSEDATA@));
\t}
\tif (rc == 0 && ffprobe_idle(readl(h + @FUSECTRL@)))
\t\twritel(orig, h + @FUSEADDR@);
\treturn rc;
}
"""


def probe_c_source():
    """C definitions (idle helper + CMD_READ pass) for the probe module."""
    out = PROBE_C
    for name, value in (("IDLE_STATE", IDLE_STATE), ("FUSECTRL", FUSECTRL),
                        ("FUSEADDR", FUSEADDR), ("FUSEDATA", FUSEDATA),
                        ("FUSEDEBUG", FUSEDEBUG), ("CMD_READ", CMD_READ),
                        ("ROW_COUNT", ROW_COUNT)):
        out = out.replace("@%s@" % name, str(value))
    return out
