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


if __name__ == "__main__":
    unittest.main()
