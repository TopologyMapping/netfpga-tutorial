#!/bin/env python

from NFTest import *
from NFTest import simReg

phy2loop0 = ('../connections/conn', 'nf2c0')

nftest_init(sim_loop = [], hw_config = [phy2loop0])
nftest_start()
#nftest_fpga_reset()

'''for i in range(2**10*2):
   nftest_regwrite((reg_defines.SRAM_BASE_ADDR()+(i<<2)),i<<4)
   #print 'addr: %x\n' %((reg_defines.SRAM_BASE_ADDR()+(i<<2)))

for i in range(2**10*2):
   nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()+(i<<2)),i<<4)
'''
pdrop = [1210, 80, 22, 667]

#Ports to drop 1010, 80, 22, 667 
#1,2,3 and 4 tell to sram_arbiter which 18bit's set it must write the value.
#The memory's address layout is divided by 9bit. So the first address (SRAM_BASE) addresses the 72nd bit of first line, SRAM_BASE+1 addresses the 63rd bit of first line ... and SRAM_BASE+7 addresses the 9th bit of first line. SRAM_BASE+8 addresses the 72nd bit of 2nd line and so on.
nftest_regwrite((reg_defines.SRAM_BASE_ADDR()),pdrop[3]|pdrop[2]<<16)
nftest_regwrite((reg_defines.SRAM_BASE_ADDR()+4),pdrop[1]|pdrop[0]<<16)

nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()),pdrop[3]|pdrop[2]<<16)
nftest_regread_expect((reg_defines.SRAM_BASE_ADDR()+4),pdrop[1]|pdrop[0]<<16)

nftest_barrier()
simReg.regDelay(1000) #1us
HDR=scapy.TCP()
TTL = 64

eth_hdr = 14
ipv4_hdr=20
tcp_hdr=20

LOAD = ''
length = 10
for genr in range (length):
   LOAD += chr(randint(0,255))

DA = "0xD0:0x27:0x88:0xBC:0xA8:0xE9"
SA = "0x0:0x4E:0x46:0x32:0x43:0x0"
DST_IP = '192.168.101.10'
SRC_IP = '192.168.101.20'

PORTS = [567, pdrop[0], 876, pdrop[3], 21, pdrop[2], 37, pdrop[1]]
NUM_PKTS = len(PORTS)

i=0

while(i < NUM_PKTS):
   HDR.dport = PORTS[i]
   HDR.sport = PORTS[NUM_PKTS-1-i]
   HDR.flags = 0b00010
   DA = "0xD0:0x27:0x88:0xBC:0xA8:0x%02x"%(i)
   SA = "0x0:0x4E:0x46:0x32:0x43:0x%02x"%(i)
   DST_IP = '192.168.101.%0.3i'%(i)
   SRC_IP = '192.168.101.%0.3i'%(i+1)

   pkt = scapy.Ether(dst=DA, src=SA)/scapy.IP(dst=DST_IP,
         src=SRC_IP, ttl=TTL)/HDR/LOAD
   pkt.len = (len(LOAD))+eth_hdr+ipv4_hdr+tcp_hdr
   seqn = i*(50)
   pkt.seq = seqn
   nftest_send_phy('nf2c0', pkt)
   # if(PORTS[i] not in pdrop):
   if(PORTS[i] != pdrop[0] and PORTS[i] != pdrop[1] and PORTS[i] != pdrop[2] and PORTS[i] != pdrop[3]):
   #minifirewall module decrement TTL, so we change the packet content
   #to comparision 
      pkt = scapy.Ether(dst=DA, src=SA)/scapy.IP(dst=DST_IP,
            src=SRC_IP, ttl=TTL-1)/HDR/LOAD
      pkt.len = (len(LOAD))+eth_hdr+ipv4_hdr+tcp_hdr
      pkt.seq = i*(50)

      nftest_expect_dma('nf2c0', pkt)
   i = i+1

nftest_barrier()
nftest_finish()
