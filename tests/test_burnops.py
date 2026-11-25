import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ffcalc import burntool, cli, ffmacro
from ffcalc.dump import load_dump


class BurnBar(object):
    """Fake fuse controller with OTP rows; programs are one-shot fuses."""

    def __init__(self, rows=None, poison_row=None, dsov=0, crc=0x55,
                 efp=1, debug=0):
        self.rows = dict(rows or {})
        self.ctrl = 0xE0040000
        self.addr = 0
        self.data = 0
        self.wdata = 0
        self.reg = {ffmacro.FUSEDEBUG: debug, ffmacro.CRC_STATUS: crc,
                    ffmacro.EFP_STATUS: efp, ffmacro.DSOV_STATUS: dsov,
                    ffmacro.SBFE_SHADOW: 1,
                    ffmacro.WDATA_WR_SECURE: 1}
        self.poison_row = poison_row
        self.programs = []

    def rd(self, off):
        if off == ffmacro.FUSECTRL:
            return self.ctrl
        if off == ffmacro.FUSEADDR:
            return self.addr
        if off == ffmacro.FUSEDATA:
            return self.data
        if off == ffmacro.FUSEWDATA:
            return self.wdata
        return self.reg.get(off, 0)

    def wr(self, off, val):
        if off == ffmacro.FUSEADDR:
            self.addr = val
        elif off == ffmacro.FUSEWDATA:
            self.wdata = val
        elif off == ffmacro.FUSECTRL:
            cmd = val & 0x1F
            if cmd == ffmacro.CMD_READ:
                self.data = self.rows.get(self.addr, 0)
            elif cmd == ffmacro.CMD_SENSE:
                self.reg[ffmacro.SBFE_SHADOW] = 1
                self.reg[ffmacro.EFP_STATUS] = 1
            elif cmd == ffmacro.CMD_PROGRAM:
                if self.addr == self.poison_row:
                    self.ctrl = 0xBADF510E
                    return
                self.rows[self.addr] = self.wdata
                self.programs.append((self.addr, self.wdata))
        else:
            self.reg[off] = val


def noop(_s):
    pass


def zero_clock():
    return 0.0


PLAN = {"uuid": "GPU-test", "fingerprint": "abc",
        "targets": {"fbp_disable": "0x840"}, "warnings": [],
        "burn": [{"row": 315, "record": "0x420004c1", "chain": 1,
                  "block": 19, "old": "0x4290", "new": "0x4200",
                  "fields": ["fbp_disable"]}]}

# A --a100 plan cut down to its two identity rows -- the records the community
# conversion report burned. The plan carries its own warnings, because burntool
# echoes them for a hand-written plan or one from an older ffcalc as well.
DEVID_PLAN = {
    "uuid": "GPU-test", "fingerprint": "abc",
    "targets": {"pcie_devida": "0x20b5", "pcie_devidb": "0x20b5"},
    "warnings": ["pcie_devida/pcie_devidb: rewrites the FUSED device id"],
    "burn": [
        {"row": 316, "record": "0x416a0942", "chain": 2, "block": 37,
         "old": "0x0000", "new": "0x416a", "fields": ["pcie_devida"]},
        {"row": 317, "record": "0x416a0982", "chain": 2, "block": 38,
         "old": "0x0000", "new": "0x416a", "fields": ["pcie_devidb"]}]}


class TestBurnOps(unittest.TestCase):
    def setUp(self):
        self.bar = BurnBar(rows={290: 0x429004C1})

    def test_read_row_and_restore(self):
        self.bar.addr = 0x123
        got = ffmacro.read_row(self.bar.rd, self.bar.wr, 290,
                               sleep=noop, clock=zero_clock)
        self.assertEqual(got, 0x429004C1)
        self.assertEqual(self.bar.addr, 0x123)

    def test_sense_checks_dsov(self):
        bar = BurnBar(dsov=1)
        with self.assertRaises(ffmacro.FuseControllerError) as cm:
            ffmacro.sense(bar.rd, bar.wr, sleep=noop, clock=zero_clock)
        self.assertIn("DSOV", str(cm.exception))
        ffmacro.sense(self.bar.rd, self.bar.wr, sleep=noop,
                      clock=zero_clock)

    def test_arm_requires_window(self):
        bar = BurnBar(efp=0)
        with self.assertRaises(ffmacro.FuseControllerError) as cm:
            ffmacro.arm(bar.rd, bar.wr)
        self.assertIn("EFP", str(cm.exception))
        ffmacro.arm(self.bar.rd, self.bar.wr)
        self.assertEqual(self.bar.programs, [])

    def test_program_row_full_chain(self):
        ffmacro.arm(self.bar.rd, self.bar.wr)
        got = ffmacro.program_row(self.bar.rd, self.bar.wr, 315,
                                  0x420004C1, sleep=noop, clock=zero_clock)
        self.assertEqual(got, 0x420004C1)
        self.assertEqual(self.bar.programs, [(315, 0x420004C1)])

    def test_program_row_refuses_nonblank(self):
        ffmacro.arm(self.bar.rd, self.bar.wr)
        with self.assertRaises(ffmacro.FuseControllerError) as cm:
            ffmacro.program_row(self.bar.rd, self.bar.wr, 290, 0x420004C1,
                                sleep=noop, clock=zero_clock)
        self.assertIn("not blank", str(cm.exception))
        self.assertEqual(self.bar.programs, [])

    def test_program_row_already_burned_is_skipped(self):
        self.bar.rows[315] = 0x420004C1
        ffmacro.arm(self.bar.rd, self.bar.wr)
        got = ffmacro.program_row(self.bar.rd, self.bar.wr, 315,
                                  0x420004C1, sleep=noop, clock=zero_clock)
        self.assertEqual(got, 0x420004C1)
        self.assertEqual(self.bar.programs, [])

    def test_poison_aborts_with_guidance(self):
        bar = BurnBar(poison_row=315)
        ffmacro.arm(bar.rd, bar.wr)
        with self.assertRaises(ffmacro.FuseControllerError) as cm:
            ffmacro.program_row(bar.rd, bar.wr, 315, 0x420004C1,
                                sleep=noop, clock=zero_clock)
        self.assertIn("cold-boot", str(cm.exception))


class TestBurnTool(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.plan_path = os.path.join(self.tmp, "plan.json")
        self.dump_path = os.path.join(self.tmp, "dump.json")
        with open(self.plan_path, "w") as f:
            json.dump(PLAN, f)
        rows = dict(("%d" % r, "0") for r in range(512))
        rows["290"] = "0x429004c1"
        dump = {"sku": "8gb", "uuid": "GPU-test", "fingerprint": "abc",
                "ff_rows": rows,
                "option_words": {"fbp_disable": "0x852",
                                 "fbp_defective": "0x0",
                                 "fbpa_defective": "0x0",
                                 "fbio_defective": "0x0",
                                 "gpc_defective": "0x0",
                                 "pes_defective": "0x0"}}
        for i in range(8):
            dump["option_words"]["tpc_gpc%d_defective" % i] = "0x0"
        with open(self.dump_path, "w") as f:
            json.dump(dump, f)

    def _plan(self, obj, name="devid.json"):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            json.dump(obj, f)
        return path

    def test_devid_plan_warns_before_the_first_write(self):
        """A plan that rewrites the fused id has to say so to whoever is about
        to answer `YES`: an A100 vBIOS is owed after this, and CH341A is the
        only way back if the platform stops POSTing."""
        bar = BurnBar(rows={290: 0x429004C1})
        bar.reg[ffmacro.SBFE_SHADOW] = 0
        bar.reg[ffmacro.WDATA_WR_SECURE] = 0
        logs = []
        rc = burntool.cmd_burn(bar.rd, bar.wr, self._plan(DEVID_PLAN),
                               self.dump_path, sleep=noop, clock=zero_clock,
                               log=logs.append)
        self.assertEqual(rc, 0)
        text = "\n".join(logs)
        self.assertIn("plan warning: pcie_devida", text)
        self.assertIn("NOTICE", text)
        self.assertIn("vBIOS", text)
        self.assertIn("CH341A", text)
        self.assertEqual(bar.programs, [(316, 0x416a0942), (317, 0x416a0982)])

    def test_confirm_gate_blocks_every_write(self):
        """`YES` is the last gate, and it comes after the offline checks and
        the warnings: refusing then must leave the card untouched."""
        bar = BurnBar(rows={290: 0x429004C1})
        logs = []
        rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path, self.dump_path,
                               sleep=noop, clock=zero_clock,
                               log=logs.append, confirm=lambda: False)
        self.assertEqual(rc, 2, logs)
        self.assertEqual(bar.programs, [])
        self.assertEqual(bar.addr, 0, "not even a row address was written")

    def test_offline_gate_blocks_used_row(self):
        bar = BurnBar(rows={315: 0xDEADBEEF})
        plan2 = json.loads(json.dumps(PLAN))
        plan2["burn"][0]["row"] = 290     # row used by a snapshot record
        p = os.path.join(self.tmp, "bad.json")
        with open(p, "w") as f:
            json.dump(plan2, f)
        rc = burntool.cmd_burn(bar.rd, bar.wr, p, self.dump_path,
                               sleep=noop, clock=zero_clock, log=lambda *_: None)
        self.assertEqual(rc, 1)
        self.assertEqual(bar.programs, [])

    def test_happy_path_burns_and_verifies(self):
        bar = BurnBar(rows={290: 0x429004C1})
        bar.reg[ffmacro.SBFE_SHADOW] = 0
        bar.reg[ffmacro.WDATA_WR_SECURE] = 0
        rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path,
                               self.dump_path, sleep=noop,
                               clock=zero_clock, log=lambda *_: None)
        self.assertEqual(rc, 0)
        self.assertEqual(bar.programs, [(315, 0x420004C1)])

    def test_live_mismatch_refuses(self):
        bar = BurnBar(rows={290: 0x429004C1, 315: 0x1234})
        bar.reg[ffmacro.SBFE_SHADOW] = 0
        bar.reg[ffmacro.WDATA_WR_SECURE] = 0
        rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path,
                               self.dump_path, sleep=noop,
                               clock=zero_clock, log=lambda *_: None)
        self.assertEqual(rc, 1)
        self.assertEqual(bar.programs, [])

    def test_interrupted_run_resumes_and_skips_burned_row(self):
        bar = BurnBar(rows={290: 0x429004C1, 315: 0x420004C1})
        rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path,
                               self.dump_path, sleep=noop,
                               clock=zero_clock, log=lambda *_: None)
        self.assertEqual(rc, 0)
        self.assertEqual(bar.programs, [])

    def test_poison_during_burn_returns_3(self):
        bar = BurnBar(rows={290: 0x429004C1}, poison_row=315)
        rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path,
                               self.dump_path, sleep=noop,
                               clock=zero_clock, log=lambda *_: None)
        self.assertEqual(rc, 3)
        self.assertEqual(bar.programs, [])

    def test_poisoned_controller_refused(self):
        bar = BurnBar()
        bar.ctrl = 0xBADF510E
        rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path,
                               self.dump_path, log=lambda *_: None)
        self.assertEqual(rc, 3)

    def test_untrusted_snapshot_refuses_without_touching_the_card(self):
        """Whatever is wrong with the snapshot, the answer is a REFUSED line
        and no command to the controller: an unreadable snapshot is not
        permission to burn, and the operator must not be left reading a
        traceback with the card already sitting in the write window."""
        cases = {
            "row outside the array": '{"sku": "8gb", "ff_rows": {"999": 0}}',
            "value wider than 32 bits":
                '{"sku": "8gb", "ff_rows": {"222": "0x1ffffffff"}}',
            "truncated by an interrupted write":
                '{"sku": "8gb", "ff_rows": {"222": "0x0f',
        }
        for why, body in cases.items():
            with open(self.dump_path, "w") as f:
                f.write(body)
            bar = BurnBar(rows={290: 0x429004C1})
            logs = []
            rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path,
                                   self.dump_path, sleep=noop,
                                   clock=zero_clock, log=logs.append)
            self.assertEqual(rc, 1, (why, logs))
            self.assertTrue(any("REFUSED" in line for line in logs), (why, logs))
            self.assertEqual(bar.programs, [], why)
            self.assertEqual(bar.addr, 0,
                             "%s: not even a row address was written" % why)

    def test_plan_that_is_not_a_plan_refuses(self):
        with open(self.plan_path, "w") as f:
            json.dump({"burn": "not a list"}, f)
        bar = BurnBar(rows={290: 0x429004C1})
        logs = []
        rc = burntool.cmd_burn(bar.rd, bar.wr, self.plan_path, self.dump_path,
                               log=logs.append)
        self.assertEqual(rc, 1)
        self.assertTrue(any("not a burn plan" in line for line in logs), logs)
        self.assertEqual(bar.programs, [])


class TestCaptureSnapshotEndToEnd(unittest.TestCase):
    """The whole fallback path over a capture-style snapshot -- the shape
    mergeff used to crash on: rows read out elsewhere -> mergeff -> gen -> sim
    -> burntool re-reading every planned row off the card."""

    SAMPLE = os.path.join(os.path.dirname(__file__), "..",
                          "samples", "blog_card_example.json")

    def test_readout_to_burn(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        base = load_dump(self.SAMPLE)
        ff = dict((r, v) for r, v in base["ff_rows"].items()
                  if 222 <= r <= 487)
        card = os.path.join(tmp, "card.json")
        rows = dict(("%d" % r, "0x%08x" % v) for r, v in sorted(ff.items()))
        for r in range(222):        # a capture lists the whole array, so the
            rows.setdefault("%d" % r, "0x00000000")    # rows outside FF are strings
        with open(card, "w") as f:
            json.dump({"sku": "8gb", "uuid": "GPU-e2e", "fingerprint": "e2e",
                       "ff_rows": rows,
                       "option_words": dict((k, "0x%x" % v) for k, v
                                            in base["option_words"].items())}, f)
        rows_file = os.path.join(tmp, "ffrows.txt")
        with open(rows_file, "w") as f:
            for r, v in sorted(ff.items()):
                f.write("%d %s\n" % (r, v))
        plan_path = os.path.join(tmp, "plan.json")
        self.assertEqual(cli.main(["mergeff", card, rows_file]), 0)
        self.assertEqual(cli.main(["gen", card, "-o", plan_path]), 0)
        self.assertEqual(cli.main(["sim", card, plan_path]), 0)
        with open(plan_path) as f:
            planned = json.load(f)["burn"]
        self.assertTrue(planned)
        bar = BurnBar(rows=dict(load_dump(card)["ff_rows"]))
        bar.reg[ffmacro.SBFE_SHADOW] = 0
        bar.reg[ffmacro.WDATA_WR_SECURE] = 0
        rc = burntool.cmd_burn(bar.rd, bar.wr, plan_path, card, sleep=noop,
                               clock=zero_clock, log=lambda *_: None)
        self.assertEqual(rc, 0)
        self.assertEqual(bar.programs,
                         [(rec["row"], int(rec["record"], 0)) for rec in planned])


class TestSafetyHardening(unittest.TestCase):
    def test_no_fuseaddr_restore_write_on_poison_or_timeout(self):
        writes = []

        def rd_poison(off):
            if off == ffmacro.PMC_BOOT_0:
                return 0x170000A1
            if off == ffmacro.FUSECTRL:
                return 0xBAD01234
            return 0

        def wr_log(off, val):
            writes.append((off, val))

        with self.assertRaises(ffmacro.FuseControllerError):
            ffmacro.capture_rows(rd_poison, wr_log, first=222, last=223,
                                 sleep=noop, clock=zero_clock)
        self.assertEqual(writes, [], "must not write FUSEADDR when poisoned")

        # Poison during CMD_READ in read_row must not trigger finally wr(FUSEADDR)
        writes2 = []
        state = {"ctrl": 0xE0040000, "addr": 0}

        def rd2(off):
            if off == ffmacro.FUSECTRL:
                return state["ctrl"]
            if off == ffmacro.FUSEADDR:
                return state["addr"]
            return 0

        def wr2(off, val):
            writes2.append((off, val))
            if off == ffmacro.FUSEADDR:
                state["addr"] = val
            elif off == ffmacro.FUSECTRL and val == ffmacro.CMD_READ:
                state["ctrl"] = 0xBADF510E

        with self.assertRaises(ffmacro.FuseControllerError):
            ffmacro.read_row(rd2, wr2, 222, sleep=noop, clock=zero_clock)
        # Only writes should be FUSEADDR=222 and FUSECTRL=CMD_READ — NO finally restore!
        self.assertEqual(writes2, [(ffmacro.FUSEADDR, 222), (ffmacro.FUSECTRL, ffmacro.CMD_READ)])

    def test_capture_rd_wr_single_32bit_memoryview(self):
        from ffcalc import capture
        buf = bytearray(0x100)
        capture.wr(buf, 0x20, 0xCAFEBABE)
        self.assertEqual(capture.rd(buf, 0x20), 0xCAFEBABE)

    def test_burntool_catches_sense_poison_returning_rc3(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        plan_path = os.path.join(tmp, "plan.json")
        dump_path = os.path.join(tmp, "dump.json")
        with open(plan_path, "w") as f:
            json.dump(PLAN, f)
        rows = dict(("%d" % r, "0") for r in range(512))
        rows["290"] = "0x429004c1"
        with open(dump_path, "w") as f:
            json.dump({"sku": "8gb", "uuid": "GPU-test", "fingerprint": "abc",
                       "ff_rows": rows,
                       "option_words": {"fbp_disable": "0x852",
                                        "fbp_defective": "0x840"}}, f)

        bar = BurnBar(rows={290: 0x429004C1})
        orig_wr = bar.wr

        def poison_on_sense(off, val):
            if off == ffmacro.FUSECTRL and (val & 0x1F) == ffmacro.CMD_SENSE:
                bar.ctrl = 0xBADF510E
                return
            orig_wr(off, val)

        bar.wr = poison_on_sense
        logs = []
        rc = burntool.cmd_burn(bar.rd, bar.wr, plan_path, dump_path,
                               sleep=noop, clock=zero_clock, log=logs.append)
        self.assertEqual(rc, 3)
        self.assertTrue(any("ABORT:" in m for m in logs))

    def test_pcie_bit_fields_target_zero_even_when_word_reads_one(self):
        from ffcalc import analyze
        base = load_dump(TestCaptureSnapshotEndToEnd.SAMPLE)
        base["option_words"]["pcie_magic_gen4_dis"] = 1
        base["option_words"]["disable_gen3_speed_bit1"] = 1
        targets, _ = analyze.resolve_targets(base)
        self.assertEqual(targets["pcie_magic_gen4_dis"], 0)
        self.assertEqual(targets["disable_gen3_speed_bit1"], 0)

    def test_dead_bus_status_reads_once_and_returns_3(self):
        reads = []

        def dead_rd(off):
            reads.append(off)
            return 0xFFFFFFFF

        logs = []
        rc = burntool.cmd_status(dead_rd, log=logs.append)
        self.assertEqual(rc, 3, logs)
        self.assertEqual(reads, [ffmacro.FUSECTRL])

    def test_capture_alignment_bounds_and_multi_gpu_refusal(self):
        from ffcalc import capture
        buf = bytearray(0x100)
        for bad in (-4, 1, 2, 0x100, 0xFE):
            with self.assertRaises(ValueError):
                capture.rd(buf, bad)
            with self.assertRaises(ValueError):
                capture.wr(buf, bad, 0)

        # Fake sysfs with two GPUs (20c2 + 2082): omitted --bdf MUST fail; explicit --bdf picks 2082 cleanly
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        for bdf, dev in (("0000:05:00.0", "0x20c2"), ("0000:06:00.0", "0x2082")):
            d = os.path.join(tmp, bdf)
            os.makedirs(d)
            with open(os.path.join(d, "vendor"), "w") as f:
                f.write("0x10de\n")
            with open(os.path.join(d, "device"), "w") as f:
                f.write(dev + "\n")
        with self.assertRaises(SystemExit) as cm:
            capture.select_device(bdf=None, base=tmp)
        self.assertIn("multiple NVIDIA GA100 GPUs", str(cm.exception))
        self.assertEqual(capture.select_device(bdf="0000:06:00.0", base=tmp), ("0000:06:00.0", "0x2082"))

    def test_swapped_card_with_blank_target_row_is_refused(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        plan_path = os.path.join(tmp, "plan.json")
        dump_path = os.path.join(tmp, "dump.json")
        with open(plan_path, "w") as f:
            json.dump(PLAN, f)
        rows = dict(("%d" % r, "0") for r in range(512))
        rows["8"] = "0x11111111"
        rows["290"] = "0x429004c1"
        with open(dump_path, "w") as f:
            json.dump({"sku": "8gb", "uuid": "GPU-test", "fingerprint": "abc",
                       "ff_rows": rows,
                       "option_words": {"fbp_disable": "0x852", "fbp_defective": "0x840"}}, f)
        # Card B has blank target row 315 AND matching row 290, but DIFFERENT die-ID row 8!
        bar_b = BurnBar(rows={8: 0x22222222, 290: 0x429004C1})
        logs = []
        rc = burntool.cmd_burn(bar_b.rd, bar_b.wr, plan_path, dump_path,
                               sleep=noop, clock=zero_clock, log=logs.append)
        self.assertEqual(rc, 1, logs)
        self.assertTrue(any("WRONG CARD" in m for m in logs), logs)
        self.assertEqual(bar_b.programs, [])

    def test_simulate_physical_row_order_and_optin_collateral_detection(self):
        from ffcalc.simulate import simulate
        # Put an existing record at row 250 for chain1 blk19 = 0x4290, and try to burn
        # at row 240 (a hole BEFORE row 250!): physical replay must see row 250 win (0x4290),
        # NOT the earlier row 240!
        rows = {r: 0 for r in range(512)}
        rows[250] = 0x429004C1
        dump = {"sku": "8gb", "ff_rows": rows, "option_words": {}}
        plan_hole = {
            "targets": {"fbp_disable": "0x840"},
            "burn": [{"row": 240, "record": "0x420004c1", "chain": 1, "block": 19,
                      "old": "0x4290", "new": "0x4200", "fields": ["fbp_disable"]}],
        }
        res = simulate(dump, plan_hole)
        self.assertTrue(any("burned but still != target" in e for e in res["errors"]), res["errors"])

        # Collateral modification of opt-in pcie_devidb MSB (bit 0 of block 2,39) MUST FAIL!
        rows2 = {r: 0 for r in range(512)}
        rows2[222] = (0x0782 << 16) | (39 << 6) | 2
        dump2 = {"sku": "8gb", "ff_rows": rows2, "option_words": {}}
        bad_new = 0x0581  # clears bit 1 & bit 9, AND flips bit 0 (DEVIDB MSB)!
        plan_bad_bit0 = {
            "targets": {"disable_gen3_speed_bit1": "0x0", "disable_gen3_speed_bit9": "0x0"},
            "burn": [{"row": 223, "record": "0x%08x" % ((bad_new << 16) | (39 << 6) | 2),
                      "chain": 2, "block": 39, "old": "0x0782", "new": "0x%04x" % bad_new,
                      "fields": ["disable_gen3_speed_bit1", "disable_gen3_speed_bit9"]}],
        }
        res2 = simulate(dump2, plan_bad_bit0)
        self.assertTrue(any("pcie_devidb: collateral change" in e for e in res2["errors"]), res2["errors"])

    def test_ingest_rejects_ffrow_error_and_cross_card_bar0(self):
        from ffcalc import ingest
        with self.assertRaises(ValueError):
            ingest.parse_log("FFPROBE ffrow_error poison_5 fa820000 badf510e\n")
        with self.assertRaises(ValueError):
            ingest.parse_log("FFPROBE ffrows_done fa000000 00000001\n", expected_bar0=0xfa000000)
        # Card A lines mixed with Card B expected_bar0 MUST be rejected
        mixed = (
            "FFPROBE probe_start fa000000 00000001\n"
            "FFPROBE ffrow.222 f9820008 00000000\n"
            "FFPROBE probe_end fa000000 00000000\n"
        )
        with self.assertRaises(ValueError):
            ingest.parse_log(mixed, expected_bar0=0xfa000000)
        # Clean framed log slices out stale earlier lines
        framed = (
            "FFPROBE ffrow.222 f9820008 deadbeef\n"
            "FFPROBE probe_start fa000000 00000001\n"
            "FFPROBE ffrow.222 fa820008 12345678\n"
            "FFPROBE ffrows_done fa000000 00000000\n"
            "FFPROBE probe_end fa000000 00000000\n"
        )
        entries = ingest.parse_log(framed, expected_bar0=0xfa000000)
        self.assertEqual(dict((n, v) for n, _, v in entries)["ffrow.222"], 0x12345678)

    def test_program_row_timeout_performs_zero_extra_reads_after_timeout(self):
        bar = BurnBar(rows={290: 0x429004C1})
        ffmacro.arm(bar.rd, bar.wr)
        reads = []
        t = [0.0]

        def clock():
            t[0] += 6.0  # first poll t=6, second check t=12 >= 10s timeout
            return t[0]

        orig_rd = bar.rd
        orig_wr = bar.wr

        def spy_rd(off):
            reads.append(off)
            return orig_rd(off)

        def stall_wr(off, val):
            orig_wr(off, val)
            if off == ffmacro.FUSECTRL and val == ffmacro.CMD_PROGRAM:
                bar.ctrl = 0xE00C0000  # busy forever

        with self.assertRaises(ffmacro.FuseControllerError) as cm:
            ffmacro.program_row(spy_rd, stall_wr, 315, 0x420004C1, sleep=noop, clock=clock)
        self.assertIn("0xe00c0000", str(cm.exception))
        # Exactly ONE poll read of FUSECTRL after CMD_PROGRAM (no extra rd(FUSECTRL) for formatting!)
        last_wdata_idx = len(reads) - 1 - reads[::-1].index(ffmacro.FUSEWDATA)
        self.assertEqual(reads[last_wdata_idx + 1:], [ffmacro.FUSECTRL])


if __name__ == "__main__":
    unittest.main()
