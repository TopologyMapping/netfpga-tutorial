#!/bin/env python
#This test is independent of firewall. It only show how to write in  #
#SRAM. The arbiter module write 32bit of data in SRAM and the address#
#sended must be pow of 2.                                            #
#                                                                    #
######################################################################
from NFTest import *

phy2loop0 = ('../connections/conn', 'nf2c0')

nftest_init(sim_loop = [], hw_config = [phy2loop0])
nftest_start()
nftest_fpga_reset()

for i in range(20):
   nftest_regwrite((reg_defines.SRAM_BASE_ADDR()+(i<<2)),i<<4)

for i in range(20):
   nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()+(i<<2)),i<<4)

nftest_finish()
