#!/usr/bin/env python3
"""Generate the ffprobe.ko kernel module from the vendored fuse register map.
Build on the target, insmod once per GPU (bar0=<phys>), values land in
dmesg, module auto-removes itself. Option-word reads are pure MMIO; by
default the module then captures all 512 physical fuse rows via fuse-macro
CMD_READ (writes to FUSEADDR/FUSECTRL only; procedure from
kate-land/ga100vfi, shared with ffcalc/ffmacro.py). Pass ffrows=0 at
insmod time to skip the CMD_READ pass on a card that is not idle.

    python3 gen_probe_c.py > ffprobe.c
    make -C /lib/modules/$(uname -r)/build M=$PWD modules
    sudo insmod ffprobe.ko bar0=0xfa000000
    sudo dmesg | grep FFPROBE
"""
import io
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MAP = os.path.join(HERE, "..", "ffcalc", "data", "ga100-fuses.json")
sys.path.insert(0, os.path.join(HERE, ".."))

from ffcalc import ffmacro  # noqa: E402

TPL = """\
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("ffcalc GA100 fuse probe (words read-only + CMD_READ rows)");

static u64 bar0;
module_param(bar0, ullong, 0444);
MODULE_PARM_DESC(bar0, "physical BAR0 base address of the GPU");

static bool ffrows = true;
module_param(ffrows, bool, 0444);
MODULE_PARM_DESC(ffrows, "capture 512 raw rows via CMD_READ (default on)");

struct probe_entry { u32 off; const char *name; };
static const struct probe_entry entries[] = {
@BODY@
};
@FFROWS@
static int __init ffprobe_init(void)
{
	void __iomem *h;
	size_t i;

	if (!bar0)
		return -EINVAL;
	h = ioremap(bar0, 0x00830000);
	if (!h)
		return -ENOMEM;
	pr_info("FFPROBE probe_start %08llx 00000001\\n", (u64)bar0);
	for (i = 0; i < ARRAY_SIZE(entries); i++)
		pr_info("FFPROBE %s %08llx %08x\\n", entries[i].name,
			(u64)bar0 + entries[i].off,
			readl(h + entries[i].off));
	if (ffrows)
		pr_info("FFPROBE ffrows_done %08llx %08x\\n", (u64)bar0,
			ffprobe_read_rows(h) ? 1 : 0);
	pr_info("FFPROBE probe_end %08llx 00000000\\n", (u64)bar0);
	iounmap(h);
	return -EAGAIN;
}

static void __exit ffprobe_exit(void) { }

module_init(ffprobe_init);
module_exit(ffprobe_exit);
"""


def main():
    with io.open(MAP, encoding="utf-8") as f:
        m = json.load(f)
    regs = []
    for key, spec in sorted(m["bit_fields"].items()):
        regs.append((int(spec["reg"], 0), "bitfield." + key))
    for key, addr in sorted(m["defective"].items()):
        regs.append((int(addr, 0), "defective." + key))
    for key, addr in sorted(m["info"].items()):
        regs.append((int(addr, 0), "info." + key))
    entries = []
    for key, loc in sorted(m["fields"].items()):
        for kind in ("status", "fused"):
            if loc.get(kind):
                entries.append((int(loc[kind], 0), "%s.%s" % (key, kind)))
    entries += regs
    body = ['\t{ 0x%08x, "%s" },' % (off, name)
            for off, name in sorted(entries)]
    src = TPL.replace("@BODY@", "\n".join(body))
    src = src.replace("@FFROWS@", ffmacro.probe_c_source())
    print(src)


if __name__ == "__main__":
    main()
