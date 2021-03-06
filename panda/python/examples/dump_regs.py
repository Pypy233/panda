#!/usr/bin/env python3
# Displays the register state of the cpu in x86 at 10 basic blocks

from time import sleep
from sys import argv
from panda import Panda, blocking
from panda.helper.x86 import *

# Single arg of arch, defaults to i386
arch = "i386" if len(argv) <= 1 else argv[1]
panda = Panda(generic=arch)

@blocking
def run_my_cmd():
    panda.revert_sync("root")
    print(panda.run_serial_cmd("uname -a"))
    panda.end_analysis()

ctr = 0

@panda.cb_before_block_exec()
def before_block_execute(cpu, tb):
    global ctr
    ctr += 1

    print("\n\n===== State after block {} =====".format(ctr))
    dump_state(panda, cpu)

    if ctr > 10: panda.end_analysis()

panda.run()
