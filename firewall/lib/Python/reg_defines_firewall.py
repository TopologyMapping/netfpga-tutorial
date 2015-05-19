#!/usr/bin/python
#############################################################
#
# Python register defines
#
# Project: FIREWALL (firewall)
# Description: Firewall to parser packets based in TCP port using register interface
#
#############################################################

# -------------------------------------
#   Version Information
# -------------------------------------
def DEVICE_ID ():
    return 1

def DEVICE_MAJOR ():
    return 1

def DEVICE_MINOR ():
    return 1

def DEVICE_REVISION ():
    return 2

def DEVICE_PROJ_DIR ():
    return "firewall"

def DEVICE_PROJ_NAME ():
    return "FIREWALL"

def DEVICE_PROJ_DESC ():
    return "Firewall to parser packets based in TCP port using register interface"


# -------------------------------------
#   Constants
# -------------------------------------

# ===== File: lib/verilog/core/common/xml/global.xml =====

# Maximum number of phy ports
def MAX_PHY_PORTS ():                     
    return 4

# PCI address bus width
def PCI_ADDR_WIDTH ():                    
    return 32

# PCI data bus width
def PCI_DATA_WIDTH ():                    
    return 32

# PCI byte enable bus width
def PCI_BE_WIDTH ():                      
    return 4

# CPCI--CNET address bus width. This is byte addresses even though bottom bits are zero.
def CPCI_CNET_ADDR_WIDTH ():              
    return 27

# CPCI--CNET data bus width
def CPCI_CNET_DATA_WIDTH ():              
    return 32

# CPCI--Virtex address bus width. This is byte addresses even though bottom bits are zero.
def CPCI_NF2_ADDR_WIDTH ():               
    return 27

# CPCI--Virtex data bus width
def CPCI_NF2_DATA_WIDTH ():               
    return 32

# DMA data bus width
def DMA_DATA_WIDTH ():                    
    return 32

# DMA control bus width
def DMA_CTRL_WIDTH ():                    
    return 4

# CPCI debug bus width
def CPCI_DEBUG_DATA_WIDTH ():             
    return 29

# SRAM address width
def SRAM_ADDR_WIDTH ():                   
    return 19

# SRAM data width
def SRAM_DATA_WIDTH ():                   
    return 36

# DRAM address width
def DRAM_ADDR_WIDTH ():                   
    return 24


# ===== File: lib/verilog/core/common/xml/nf_defines.xml =====

# Clock period of 125 MHz clock in ns
def FAST_CLK_PERIOD ():                   
    return 8

# Clock period of 62.5 MHz clock in ns
def SLOW_CLK_PERIOD ():                   
    return 16

# Header value used by the IO queues
def IO_QUEUE_STAGE_NUM ():                
    return 0xff

# Data path data width
def DATA_WIDTH ():                        
    return 64

# Data path control width
def CTRL_WIDTH ():                        
    return 8


# ===== File: lib/verilog/core/utils/xml/device_id_reg.xml =====

# Total number of registers
def DEV_ID_NUM_REGS ():                   
    return 64

# Number of non string registers
def DEV_ID_NON_STR_REGS ():               
    return 7

# Length of MD5 sum (bits)
def DEV_ID_MD5SUM_LENGTH ():              
    return 128

# Project directory length (in words, not chars)
def DEV_ID_PROJ_DIR_WORD_LEN ():          
    return 16

# Project directory length (in bytes/chars)
def DEV_ID_PROJ_DIR_BYTE_LEN ():          
    return 64

# Project directory length (in bits)
def DEV_ID_PROJ_DIR_BIT_LEN ():           
    return 512

# Project name length (in words, not chars)
def DEV_ID_PROJ_NAME_WORD_LEN ():         
    return 16

# Project name length (in bytes/chars)
def DEV_ID_PROJ_NAME_BYTE_LEN ():         
    return 64

# Project name length (in bits)
def DEV_ID_PROJ_NAME_BIT_LEN ():          
    return 512

# Device description length (in words, not chars)
def DEV_ID_PROJ_DESC_WORD_LEN ():         
    return 25

# Device description length (in bytes/chars)
def DEV_ID_PROJ_DESC_BYTE_LEN ():         
    return 100

# Device description length (in bits)
def DEV_ID_PROJ_DESC_BIT_LEN ():          
    return 800

# MD5 identifier (v1): MD5 sum of the string "device_id.v"
def DEV_ID_MD5_VALUE_V1_0 ():             
    return 0x4071736d

def DEV_ID_MD5_VALUE_V1_1 ():             
    return 0x8a603d2b

def DEV_ID_MD5_VALUE_V1_2 ():             
    return 0x4d55f629

def DEV_ID_MD5_VALUE_V1_3 ():             
    return 0x89a73c95


# MD5 identifier (v2): MD5 sum of the string "device_id.v:v2"
def DEV_ID_MD5_VALUE_V2_0 ():             
    return 0x5e461ffe

def DEV_ID_MD5_VALUE_V2_1 ():             
    return 0x439725c9

def DEV_ID_MD5_VALUE_V2_2 ():             
    return 0x279a22a1

def DEV_ID_MD5_VALUE_V2_3 ():             
    return 0x855f6c53


# Total number of registers (v1)
def DEV_ID_NUM_REGS_V1 ():                
    return 64

# Number of non string registers (v1)
def DEV_ID_NON_STR_REGS_V1 ():            
    return 7

# Project name length (v1: in words, not chars)
def DEV_ID_PROJ_NAME_WORD_LEN_V1 ():      
    return 25

# Project name length (v1: in bytes/chars)
def DEV_ID_PROJ_NAME_BYTE_LEN_V1 ():      
    return 100

# Project name length (v1: in bits)
def DEV_ID_PROJ_NAME_BIT_LEN_V1 ():       
    return 800


# ===== File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml =====

def CPU_QUEUE_REGS_ENABLE ():             
    return 0x00000000

def CPU_QUEUE_REGS_DISABLE ():            
    return 0x00000001


# ===== File: lib/verilog/core/output_queues/bram_output_queues/xml/bram_output_queues.xml =====

def NUM_OUTPUT_QUEUES ():                 
    return 8


# ===== File: lib/verilog/core/io_queues/ethernet_queue/xml/ethernet_mac.xml =====

# TX queue disable bit
def MAC_GRP_TX_QUEUE_DISABLE_BIT_NUM ():  
    return 0

# RX queue disable bit
def MAC_GRP_RX_QUEUE_DISABLE_BIT_NUM ():  
    return 1

# Reset MAC bit
def MAC_GRP_RESET_MAC_BIT_NUM ():         
    return 2

# MAC TX queue disable bit
def MAC_GRP_MAC_DISABLE_TX_BIT_NUM ():    
    return 3

# MAC RX queue disable bit
def MAC_GRP_MAC_DISABLE_RX_BIT_NUM ():    
    return 4

# MAC disable jumbo TX bit
def MAC_GRP_MAC_DIS_JUMBO_TX_BIT_NUM ():  
    return 5

# MAC disable jumbo RX bit
def MAC_GRP_MAC_DIS_JUMBO_RX_BIT_NUM ():  
    return 6

# MAC disable crc check disable bit
def MAC_GRP_MAC_DIS_CRC_CHECK_BIT_NUM (): 
    return 7

# MAC disable crc generate bit
def MAC_GRP_MAC_DIS_CRC_GEN_BIT_NUM ():   
    return 8



## -------------------------------------
##   Modules
## -------------------------------------

# Module tags
def CORE_BASE_ADDR ():        
    return 0x0000000

def DEV_ID_BASE_ADDR ():      
    return 0x0400000

def MDIO_BASE_ADDR ():        
    return 0x0440000

def DMA_BASE_ADDR ():         
    return 0x0500000

def MAC_GRP_0_BASE_ADDR ():   
    return 0x0600000

def MAC_GRP_1_BASE_ADDR ():   
    return 0x0640000

def MAC_GRP_2_BASE_ADDR ():   
    return 0x0680000

def MAC_GRP_3_BASE_ADDR ():   
    return 0x06c0000

def CPU_QUEUE_0_BASE_ADDR (): 
    return 0x0700000

def CPU_QUEUE_1_BASE_ADDR (): 
    return 0x0740000

def CPU_QUEUE_2_BASE_ADDR (): 
    return 0x0780000

def CPU_QUEUE_3_BASE_ADDR (): 
    return 0x07c0000

def SRAM_BASE_ADDR ():        
    return 0x1000000

def UDP_BASE_ADDR ():         
    return 0x2000000

def IN_ARB_BASE_ADDR ():      
    return 0x2000000

def FIREWALL_BASE_ADDR ():    
    return 0x2000100

def BRAM_OQ_BASE_ADDR ():     
    return 0x2000200

def DRAM_BASE_ADDR ():        
    return 0x4000000


def CPU_QUEUE_OFFSET (): 
    return 0x0040000

def MAC_GRP_OFFSET ():   
    return 0x0040000



# -------------------------------------
#   Registers
# -------------------------------------

# Name: device_id (DEV_ID)
# Description: Device identification
# File: lib/verilog/core/utils/xml/device_id_reg.xml
def DEV_ID_MD5_0_REG ():        
    return 0x0400000

def DEV_ID_MD5_1_REG ():        
    return 0x0400004

def DEV_ID_MD5_2_REG ():        
    return 0x0400008

def DEV_ID_MD5_3_REG ():        
    return 0x040000c

def DEV_ID_DEVICE_ID_REG ():    
    return 0x0400010

def DEV_ID_VERSION_REG ():      
    return 0x0400014

def DEV_ID_CPCI_ID_REG ():      
    return 0x0400018

def DEV_ID_PROJ_DIR_0_REG ():   
    return 0x040001c

def DEV_ID_PROJ_DIR_1_REG ():   
    return 0x0400020

def DEV_ID_PROJ_DIR_2_REG ():   
    return 0x0400024

def DEV_ID_PROJ_DIR_3_REG ():   
    return 0x0400028

def DEV_ID_PROJ_DIR_4_REG ():   
    return 0x040002c

def DEV_ID_PROJ_DIR_5_REG ():   
    return 0x0400030

def DEV_ID_PROJ_DIR_6_REG ():   
    return 0x0400034

def DEV_ID_PROJ_DIR_7_REG ():   
    return 0x0400038

def DEV_ID_PROJ_DIR_8_REG ():   
    return 0x040003c

def DEV_ID_PROJ_DIR_9_REG ():   
    return 0x0400040

def DEV_ID_PROJ_DIR_10_REG ():  
    return 0x0400044

def DEV_ID_PROJ_DIR_11_REG ():  
    return 0x0400048

def DEV_ID_PROJ_DIR_12_REG ():  
    return 0x040004c

def DEV_ID_PROJ_DIR_13_REG ():  
    return 0x0400050

def DEV_ID_PROJ_DIR_14_REG ():  
    return 0x0400054

def DEV_ID_PROJ_DIR_15_REG ():  
    return 0x0400058

def DEV_ID_PROJ_NAME_0_REG ():  
    return 0x040005c

def DEV_ID_PROJ_NAME_1_REG ():  
    return 0x0400060

def DEV_ID_PROJ_NAME_2_REG ():  
    return 0x0400064

def DEV_ID_PROJ_NAME_3_REG ():  
    return 0x0400068

def DEV_ID_PROJ_NAME_4_REG ():  
    return 0x040006c

def DEV_ID_PROJ_NAME_5_REG ():  
    return 0x0400070

def DEV_ID_PROJ_NAME_6_REG ():  
    return 0x0400074

def DEV_ID_PROJ_NAME_7_REG ():  
    return 0x0400078

def DEV_ID_PROJ_NAME_8_REG ():  
    return 0x040007c

def DEV_ID_PROJ_NAME_9_REG ():  
    return 0x0400080

def DEV_ID_PROJ_NAME_10_REG (): 
    return 0x0400084

def DEV_ID_PROJ_NAME_11_REG (): 
    return 0x0400088

def DEV_ID_PROJ_NAME_12_REG (): 
    return 0x040008c

def DEV_ID_PROJ_NAME_13_REG (): 
    return 0x0400090

def DEV_ID_PROJ_NAME_14_REG (): 
    return 0x0400094

def DEV_ID_PROJ_NAME_15_REG (): 
    return 0x0400098

def DEV_ID_PROJ_DESC_0_REG ():  
    return 0x040009c

def DEV_ID_PROJ_DESC_1_REG ():  
    return 0x04000a0

def DEV_ID_PROJ_DESC_2_REG ():  
    return 0x04000a4

def DEV_ID_PROJ_DESC_3_REG ():  
    return 0x04000a8

def DEV_ID_PROJ_DESC_4_REG ():  
    return 0x04000ac

def DEV_ID_PROJ_DESC_5_REG ():  
    return 0x04000b0

def DEV_ID_PROJ_DESC_6_REG ():  
    return 0x04000b4

def DEV_ID_PROJ_DESC_7_REG ():  
    return 0x04000b8

def DEV_ID_PROJ_DESC_8_REG ():  
    return 0x04000bc

def DEV_ID_PROJ_DESC_9_REG ():  
    return 0x04000c0

def DEV_ID_PROJ_DESC_10_REG (): 
    return 0x04000c4

def DEV_ID_PROJ_DESC_11_REG (): 
    return 0x04000c8

def DEV_ID_PROJ_DESC_12_REG (): 
    return 0x04000cc

def DEV_ID_PROJ_DESC_13_REG (): 
    return 0x04000d0

def DEV_ID_PROJ_DESC_14_REG (): 
    return 0x04000d4

def DEV_ID_PROJ_DESC_15_REG (): 
    return 0x04000d8

def DEV_ID_PROJ_DESC_16_REG (): 
    return 0x04000dc

def DEV_ID_PROJ_DESC_17_REG (): 
    return 0x04000e0

def DEV_ID_PROJ_DESC_18_REG (): 
    return 0x04000e4

def DEV_ID_PROJ_DESC_19_REG (): 
    return 0x04000e8

def DEV_ID_PROJ_DESC_20_REG (): 
    return 0x04000ec

def DEV_ID_PROJ_DESC_21_REG (): 
    return 0x04000f0

def DEV_ID_PROJ_DESC_22_REG (): 
    return 0x04000f4

def DEV_ID_PROJ_DESC_23_REG (): 
    return 0x04000f8

def DEV_ID_PROJ_DESC_24_REG (): 
    return 0x04000fc


# Name: mdio (MDIO)
# Description: MDIO interface
# File: lib/verilog/core/io/mdio/xml/mdio.xml
def MDIO_PHY_0_CONTROL_REG ():                                
    return 0x0440000

def MDIO_PHY_0_STATUS_REG ():                                 
    return 0x0440004

def MDIO_PHY_0_PHY_ID_HI_REG ():                              
    return 0x0440008

def MDIO_PHY_0_PHY_ID_LO_REG ():                              
    return 0x044000c

def MDIO_PHY_0_AUTONEGOTIATION_ADVERT_REG ():                 
    return 0x0440010

def MDIO_PHY_0_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG (): 
    return 0x0440014

def MDIO_PHY_0_AUTONEG_EXPANSION_REG ():                      
    return 0x0440018

def MDIO_PHY_0_AUTONEG_NEXT_PAGE_TX_REG ():                   
    return 0x044001c

def MDIO_PHY_0_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG ():    
    return 0x0440020

def MDIO_PHY_0_MASTER_SLAVE_CTRL_REG ():                      
    return 0x0440024

def MDIO_PHY_0_MASTER_SLAVE_STATUS_REG ():                    
    return 0x0440028

def MDIO_PHY_0_PSE_CTRL_REG ():                               
    return 0x044002c

def MDIO_PHY_0_PSE_STATUS_REG ():                             
    return 0x0440030

def MDIO_PHY_0_MMD_ACCESS_CTRL_REG ():                        
    return 0x0440034

def MDIO_PHY_0_MMD_ACCESS_STATUS_REG ():                      
    return 0x0440038

def MDIO_PHY_0_EXTENDED_STATUS_REG ():                        
    return 0x044003c

def MDIO_PHY_0_PHY_EXTENDED_CTRL_REG ():                      
    return 0x0440040

def MDIO_PHY_0_PHY_EXTENDED_STATUS_REG ():                    
    return 0x0440044

def MDIO_PHY_0_RX_ERROR_COUNT_REG ():                         
    return 0x0440048

def MDIO_PHY_0_FALSE_CARRIER_SENSE_COUNT_REG ():              
    return 0x044004c

def MDIO_PHY_0_RX_NOT_OK_COUNT_REG ():                        
    return 0x0440050

def MDIO_PHY_0_EXPANSION_1_REG ():                            
    return 0x0440054

def MDIO_PHY_0_EXPANSION_2_REG ():                            
    return 0x0440058

def MDIO_PHY_0_EXPANSION_REG_ACCESS_REG ():                   
    return 0x044005c

def MDIO_PHY_0_SHADOW_18_REG ():                              
    return 0x0440060

def MDIO_PHY_0_AUX_STATUS_REG ():                             
    return 0x0440064

def MDIO_PHY_0_INT_STATUS_REG ():                             
    return 0x0440068

def MDIO_PHY_0_INT_MASK_REG ():                               
    return 0x044006c

def MDIO_PHY_0_SHADOW_1C_REG ():                              
    return 0x0440070

def MDIO_PHY_0_SHADOW_1D_REG ():                              
    return 0x0440074

def MDIO_PHY_0_TEST_REG ():                                   
    return 0x0440078

def MDIO_PHY_0_RESERVED_REG ():                               
    return 0x044007c

def MDIO_PHY_1_CONTROL_REG ():                                
    return 0x0440080

def MDIO_PHY_1_STATUS_REG ():                                 
    return 0x0440084

def MDIO_PHY_1_PHY_ID_HI_REG ():                              
    return 0x0440088

def MDIO_PHY_1_PHY_ID_LO_REG ():                              
    return 0x044008c

def MDIO_PHY_1_AUTONEGOTIATION_ADVERT_REG ():                 
    return 0x0440090

def MDIO_PHY_1_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG (): 
    return 0x0440094

def MDIO_PHY_1_AUTONEG_EXPANSION_REG ():                      
    return 0x0440098

def MDIO_PHY_1_AUTONEG_NEXT_PAGE_TX_REG ():                   
    return 0x044009c

def MDIO_PHY_1_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG ():    
    return 0x04400a0

def MDIO_PHY_1_MASTER_SLAVE_CTRL_REG ():                      
    return 0x04400a4

def MDIO_PHY_1_MASTER_SLAVE_STATUS_REG ():                    
    return 0x04400a8

def MDIO_PHY_1_PSE_CTRL_REG ():                               
    return 0x04400ac

def MDIO_PHY_1_PSE_STATUS_REG ():                             
    return 0x04400b0

def MDIO_PHY_1_MMD_ACCESS_CTRL_REG ():                        
    return 0x04400b4

def MDIO_PHY_1_MMD_ACCESS_STATUS_REG ():                      
    return 0x04400b8

def MDIO_PHY_1_EXTENDED_STATUS_REG ():                        
    return 0x04400bc

def MDIO_PHY_1_PHY_EXTENDED_CTRL_REG ():                      
    return 0x04400c0

def MDIO_PHY_1_PHY_EXTENDED_STATUS_REG ():                    
    return 0x04400c4

def MDIO_PHY_1_RX_ERROR_COUNT_REG ():                         
    return 0x04400c8

def MDIO_PHY_1_FALSE_CARRIER_SENSE_COUNT_REG ():              
    return 0x04400cc

def MDIO_PHY_1_RX_NOT_OK_COUNT_REG ():                        
    return 0x04400d0

def MDIO_PHY_1_EXPANSION_1_REG ():                            
    return 0x04400d4

def MDIO_PHY_1_EXPANSION_2_REG ():                            
    return 0x04400d8

def MDIO_PHY_1_EXPANSION_REG_ACCESS_REG ():                   
    return 0x04400dc

def MDIO_PHY_1_SHADOW_18_REG ():                              
    return 0x04400e0

def MDIO_PHY_1_AUX_STATUS_REG ():                             
    return 0x04400e4

def MDIO_PHY_1_INT_STATUS_REG ():                             
    return 0x04400e8

def MDIO_PHY_1_INT_MASK_REG ():                               
    return 0x04400ec

def MDIO_PHY_1_SHADOW_1C_REG ():                              
    return 0x04400f0

def MDIO_PHY_1_SHADOW_1D_REG ():                              
    return 0x04400f4

def MDIO_PHY_1_TEST_REG ():                                   
    return 0x04400f8

def MDIO_PHY_1_RESERVED_REG ():                               
    return 0x04400fc

def MDIO_PHY_2_CONTROL_REG ():                                
    return 0x0440100

def MDIO_PHY_2_STATUS_REG ():                                 
    return 0x0440104

def MDIO_PHY_2_PHY_ID_HI_REG ():                              
    return 0x0440108

def MDIO_PHY_2_PHY_ID_LO_REG ():                              
    return 0x044010c

def MDIO_PHY_2_AUTONEGOTIATION_ADVERT_REG ():                 
    return 0x0440110

def MDIO_PHY_2_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG (): 
    return 0x0440114

def MDIO_PHY_2_AUTONEG_EXPANSION_REG ():                      
    return 0x0440118

def MDIO_PHY_2_AUTONEG_NEXT_PAGE_TX_REG ():                   
    return 0x044011c

def MDIO_PHY_2_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG ():    
    return 0x0440120

def MDIO_PHY_2_MASTER_SLAVE_CTRL_REG ():                      
    return 0x0440124

def MDIO_PHY_2_MASTER_SLAVE_STATUS_REG ():                    
    return 0x0440128

def MDIO_PHY_2_PSE_CTRL_REG ():                               
    return 0x044012c

def MDIO_PHY_2_PSE_STATUS_REG ():                             
    return 0x0440130

def MDIO_PHY_2_MMD_ACCESS_CTRL_REG ():                        
    return 0x0440134

def MDIO_PHY_2_MMD_ACCESS_STATUS_REG ():                      
    return 0x0440138

def MDIO_PHY_2_EXTENDED_STATUS_REG ():                        
    return 0x044013c

def MDIO_PHY_2_PHY_EXTENDED_CTRL_REG ():                      
    return 0x0440140

def MDIO_PHY_2_PHY_EXTENDED_STATUS_REG ():                    
    return 0x0440144

def MDIO_PHY_2_RX_ERROR_COUNT_REG ():                         
    return 0x0440148

def MDIO_PHY_2_FALSE_CARRIER_SENSE_COUNT_REG ():              
    return 0x044014c

def MDIO_PHY_2_RX_NOT_OK_COUNT_REG ():                        
    return 0x0440150

def MDIO_PHY_2_EXPANSION_1_REG ():                            
    return 0x0440154

def MDIO_PHY_2_EXPANSION_2_REG ():                            
    return 0x0440158

def MDIO_PHY_2_EXPANSION_REG_ACCESS_REG ():                   
    return 0x044015c

def MDIO_PHY_2_SHADOW_18_REG ():                              
    return 0x0440160

def MDIO_PHY_2_AUX_STATUS_REG ():                             
    return 0x0440164

def MDIO_PHY_2_INT_STATUS_REG ():                             
    return 0x0440168

def MDIO_PHY_2_INT_MASK_REG ():                               
    return 0x044016c

def MDIO_PHY_2_SHADOW_1C_REG ():                              
    return 0x0440170

def MDIO_PHY_2_SHADOW_1D_REG ():                              
    return 0x0440174

def MDIO_PHY_2_TEST_REG ():                                   
    return 0x0440178

def MDIO_PHY_2_RESERVED_REG ():                               
    return 0x044017c

def MDIO_PHY_3_CONTROL_REG ():                                
    return 0x0440180

def MDIO_PHY_3_STATUS_REG ():                                 
    return 0x0440184

def MDIO_PHY_3_PHY_ID_HI_REG ():                              
    return 0x0440188

def MDIO_PHY_3_PHY_ID_LO_REG ():                              
    return 0x044018c

def MDIO_PHY_3_AUTONEGOTIATION_ADVERT_REG ():                 
    return 0x0440190

def MDIO_PHY_3_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG (): 
    return 0x0440194

def MDIO_PHY_3_AUTONEG_EXPANSION_REG ():                      
    return 0x0440198

def MDIO_PHY_3_AUTONEG_NEXT_PAGE_TX_REG ():                   
    return 0x044019c

def MDIO_PHY_3_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG ():    
    return 0x04401a0

def MDIO_PHY_3_MASTER_SLAVE_CTRL_REG ():                      
    return 0x04401a4

def MDIO_PHY_3_MASTER_SLAVE_STATUS_REG ():                    
    return 0x04401a8

def MDIO_PHY_3_PSE_CTRL_REG ():                               
    return 0x04401ac

def MDIO_PHY_3_PSE_STATUS_REG ():                             
    return 0x04401b0

def MDIO_PHY_3_MMD_ACCESS_CTRL_REG ():                        
    return 0x04401b4

def MDIO_PHY_3_MMD_ACCESS_STATUS_REG ():                      
    return 0x04401b8

def MDIO_PHY_3_EXTENDED_STATUS_REG ():                        
    return 0x04401bc

def MDIO_PHY_3_PHY_EXTENDED_CTRL_REG ():                      
    return 0x04401c0

def MDIO_PHY_3_PHY_EXTENDED_STATUS_REG ():                    
    return 0x04401c4

def MDIO_PHY_3_RX_ERROR_COUNT_REG ():                         
    return 0x04401c8

def MDIO_PHY_3_FALSE_CARRIER_SENSE_COUNT_REG ():              
    return 0x04401cc

def MDIO_PHY_3_RX_NOT_OK_COUNT_REG ():                        
    return 0x04401d0

def MDIO_PHY_3_EXPANSION_1_REG ():                            
    return 0x04401d4

def MDIO_PHY_3_EXPANSION_2_REG ():                            
    return 0x04401d8

def MDIO_PHY_3_EXPANSION_REG_ACCESS_REG ():                   
    return 0x04401dc

def MDIO_PHY_3_SHADOW_18_REG ():                              
    return 0x04401e0

def MDIO_PHY_3_AUX_STATUS_REG ():                             
    return 0x04401e4

def MDIO_PHY_3_INT_STATUS_REG ():                             
    return 0x04401e8

def MDIO_PHY_3_INT_MASK_REG ():                               
    return 0x04401ec

def MDIO_PHY_3_SHADOW_1C_REG ():                              
    return 0x04401f0

def MDIO_PHY_3_SHADOW_1D_REG ():                              
    return 0x04401f4

def MDIO_PHY_3_TEST_REG ():                                   
    return 0x04401f8

def MDIO_PHY_3_RESERVED_REG ():                               
    return 0x04401fc


def MDIO_PHY_GROUP_BASE_ADDR ():
    return 0x0440000

def MDIO_PHY_GROUP_INST_OFFSET():
    return 0x0000080

# Name: dma (DMA)
# Description: DMA transfer module
# File: lib/verilog/core/dma/xml/dma.xml
def DMA_CTRL_REG ():              
    return 0x0500000

def DMA_NUM_INGRESS_PKTS_REG ():  
    return 0x0500004

def DMA_NUM_INGRESS_BYTES_REG (): 
    return 0x0500008

def DMA_NUM_EGRESS_PKTS_REG ():   
    return 0x050000c

def DMA_NUM_EGRESS_BYTES_REG ():  
    return 0x0500010

def DMA_NUM_TIMEOUTS_REG ():      
    return 0x0500014


# Name: nf2_mac_grp (MAC_GRP_0)
# Description: Ethernet MAC group
# File: lib/verilog/core/io_queues/ethernet_queue/xml/ethernet_mac.xml
def MAC_GRP_0_CONTROL_REG ():                        
    return 0x0600000

def MAC_GRP_0_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x0600004

def MAC_GRP_0_RX_QUEUE_NUM_PKTS_STORED_REG ():       
    return 0x0600008

def MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG (): 
    return 0x060000c

def MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG ():  
    return 0x0600010

def MAC_GRP_0_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():     
    return 0x0600014

def MAC_GRP_0_RX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x0600018

def MAC_GRP_0_RX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x060001c

def MAC_GRP_0_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x0600020

def MAC_GRP_0_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():     
    return 0x0600024

def MAC_GRP_0_TX_QUEUE_NUM_PKTS_SENT_REG ():         
    return 0x0600028

def MAC_GRP_0_TX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x060002c

def MAC_GRP_0_TX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x0600030


# Name: nf2_mac_grp (MAC_GRP_1)
# Description: Ethernet MAC group
# File: lib/verilog/core/io_queues/ethernet_queue/xml/ethernet_mac.xml
def MAC_GRP_1_CONTROL_REG ():                        
    return 0x0640000

def MAC_GRP_1_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x0640004

def MAC_GRP_1_RX_QUEUE_NUM_PKTS_STORED_REG ():       
    return 0x0640008

def MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG (): 
    return 0x064000c

def MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG ():  
    return 0x0640010

def MAC_GRP_1_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():     
    return 0x0640014

def MAC_GRP_1_RX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x0640018

def MAC_GRP_1_RX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x064001c

def MAC_GRP_1_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x0640020

def MAC_GRP_1_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():     
    return 0x0640024

def MAC_GRP_1_TX_QUEUE_NUM_PKTS_SENT_REG ():         
    return 0x0640028

def MAC_GRP_1_TX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x064002c

def MAC_GRP_1_TX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x0640030


# Name: nf2_mac_grp (MAC_GRP_2)
# Description: Ethernet MAC group
# File: lib/verilog/core/io_queues/ethernet_queue/xml/ethernet_mac.xml
def MAC_GRP_2_CONTROL_REG ():                        
    return 0x0680000

def MAC_GRP_2_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x0680004

def MAC_GRP_2_RX_QUEUE_NUM_PKTS_STORED_REG ():       
    return 0x0680008

def MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG (): 
    return 0x068000c

def MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG ():  
    return 0x0680010

def MAC_GRP_2_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():     
    return 0x0680014

def MAC_GRP_2_RX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x0680018

def MAC_GRP_2_RX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x068001c

def MAC_GRP_2_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x0680020

def MAC_GRP_2_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():     
    return 0x0680024

def MAC_GRP_2_TX_QUEUE_NUM_PKTS_SENT_REG ():         
    return 0x0680028

def MAC_GRP_2_TX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x068002c

def MAC_GRP_2_TX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x0680030


# Name: nf2_mac_grp (MAC_GRP_3)
# Description: Ethernet MAC group
# File: lib/verilog/core/io_queues/ethernet_queue/xml/ethernet_mac.xml
def MAC_GRP_3_CONTROL_REG ():                        
    return 0x06c0000

def MAC_GRP_3_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x06c0004

def MAC_GRP_3_RX_QUEUE_NUM_PKTS_STORED_REG ():       
    return 0x06c0008

def MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG (): 
    return 0x06c000c

def MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG ():  
    return 0x06c0010

def MAC_GRP_3_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():     
    return 0x06c0014

def MAC_GRP_3_RX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x06c0018

def MAC_GRP_3_RX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x06c001c

def MAC_GRP_3_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():     
    return 0x06c0020

def MAC_GRP_3_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():     
    return 0x06c0024

def MAC_GRP_3_TX_QUEUE_NUM_PKTS_SENT_REG ():         
    return 0x06c0028

def MAC_GRP_3_TX_QUEUE_NUM_WORDS_PUSHED_REG ():      
    return 0x06c002c

def MAC_GRP_3_TX_QUEUE_NUM_BYTES_PUSHED_REG ():      
    return 0x06c0030


# Name: cpu_dma_queue (CPU_QUEUE_0)
# Description: CPU DMA queue
# File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml
def CPU_QUEUE_0_CONTROL_REG ():                       
    return 0x0700000

def CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x0700004

def CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x0700008

def CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG (): 
    return 0x070000c

def CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x0700010

def CPU_QUEUE_0_RX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x0700014

def CPU_QUEUE_0_RX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x0700018

def CPU_QUEUE_0_RX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x070001c

def CPU_QUEUE_0_RX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x0700020

def CPU_QUEUE_0_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x0700024

def CPU_QUEUE_0_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x0700028

def CPU_QUEUE_0_TX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x070002c

def CPU_QUEUE_0_TX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x0700030

def CPU_QUEUE_0_TX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x0700034

def CPU_QUEUE_0_TX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x0700038

def CPU_QUEUE_0_TX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x070003c


# Name: cpu_dma_queue (CPU_QUEUE_1)
# Description: CPU DMA queue
# File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml
def CPU_QUEUE_1_CONTROL_REG ():                       
    return 0x0740000

def CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x0740004

def CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x0740008

def CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG (): 
    return 0x074000c

def CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x0740010

def CPU_QUEUE_1_RX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x0740014

def CPU_QUEUE_1_RX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x0740018

def CPU_QUEUE_1_RX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x074001c

def CPU_QUEUE_1_RX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x0740020

def CPU_QUEUE_1_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x0740024

def CPU_QUEUE_1_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x0740028

def CPU_QUEUE_1_TX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x074002c

def CPU_QUEUE_1_TX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x0740030

def CPU_QUEUE_1_TX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x0740034

def CPU_QUEUE_1_TX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x0740038

def CPU_QUEUE_1_TX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x074003c


# Name: cpu_dma_queue (CPU_QUEUE_2)
# Description: CPU DMA queue
# File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml
def CPU_QUEUE_2_CONTROL_REG ():                       
    return 0x0780000

def CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x0780004

def CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x0780008

def CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG (): 
    return 0x078000c

def CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x0780010

def CPU_QUEUE_2_RX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x0780014

def CPU_QUEUE_2_RX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x0780018

def CPU_QUEUE_2_RX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x078001c

def CPU_QUEUE_2_RX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x0780020

def CPU_QUEUE_2_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x0780024

def CPU_QUEUE_2_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x0780028

def CPU_QUEUE_2_TX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x078002c

def CPU_QUEUE_2_TX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x0780030

def CPU_QUEUE_2_TX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x0780034

def CPU_QUEUE_2_TX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x0780038

def CPU_QUEUE_2_TX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x078003c


# Name: cpu_dma_queue (CPU_QUEUE_3)
# Description: CPU DMA queue
# File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml
def CPU_QUEUE_3_CONTROL_REG ():                       
    return 0x07c0000

def CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x07c0004

def CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x07c0008

def CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG (): 
    return 0x07c000c

def CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x07c0010

def CPU_QUEUE_3_RX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x07c0014

def CPU_QUEUE_3_RX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x07c0018

def CPU_QUEUE_3_RX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x07c001c

def CPU_QUEUE_3_RX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x07c0020

def CPU_QUEUE_3_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG ():    
    return 0x07c0024

def CPU_QUEUE_3_TX_QUEUE_NUM_PKTS_ENQUEUED_REG ():    
    return 0x07c0028

def CPU_QUEUE_3_TX_QUEUE_NUM_PKTS_DEQUEUED_REG ():    
    return 0x07c002c

def CPU_QUEUE_3_TX_QUEUE_NUM_UNDERRUNS_REG ():        
    return 0x07c0030

def CPU_QUEUE_3_TX_QUEUE_NUM_OVERRUNS_REG ():         
    return 0x07c0034

def CPU_QUEUE_3_TX_QUEUE_NUM_WORDS_PUSHED_REG ():     
    return 0x07c0038

def CPU_QUEUE_3_TX_QUEUE_NUM_BYTES_PUSHED_REG ():     
    return 0x07c003c


# Name: SRAM (SRAM)
# Description: SRAM

# Name: in_arb (IN_ARB)
# Description: Round-robin input arbiter
# File: lib/verilog/core/input_arbiter/rr_input_arbiter/xml/rr_input_arbiter.xml
def IN_ARB_NUM_PKTS_SENT_REG ():      
    return 0x2000000

def IN_ARB_LAST_PKT_WORD_0_HI_REG (): 
    return 0x2000004

def IN_ARB_LAST_PKT_WORD_0_LO_REG (): 
    return 0x2000008

def IN_ARB_LAST_PKT_CTRL_0_REG ():    
    return 0x200000c

def IN_ARB_LAST_PKT_WORD_1_HI_REG (): 
    return 0x2000010

def IN_ARB_LAST_PKT_WORD_1_LO_REG (): 
    return 0x2000014

def IN_ARB_LAST_PKT_CTRL_1_REG ():    
    return 0x2000018

def IN_ARB_STATE_REG ():              
    return 0x200001c


# Name: firewall (FIREWALL)
# Description: Registers for firewall
# File: projects/firewall/include/firewall.xml
def FIREWALL_DPORT1_REG (): 
    return 0x2000100

def FIREWALL_DPORT2_REG (): 
    return 0x2000104

def FIREWALL_DPORT3_REG (): 
    return 0x2000108

def FIREWALL_DPORT4_REG (): 
    return 0x200010c


# Name: bram_output_queues (BRAM_OQ)
# Description: BRAM-based output queues
# File: lib/verilog/core/output_queues/bram_output_queues/xml/bram_output_queues.xml
def BRAM_OQ_DISABLE_QUEUES_REG ():                 
    return 0x2000200

def BRAM_OQ_QUEUE_0_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x2000280

def BRAM_OQ_QUEUE_0_NUM_PKTS_RECEIVED_REG ():      
    return 0x2000284

def BRAM_OQ_QUEUE_0_NUM_PKTS_DROPPED_REG ():       
    return 0x2000288

def BRAM_OQ_QUEUE_0_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x200028c

def BRAM_OQ_QUEUE_1_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x2000290

def BRAM_OQ_QUEUE_1_NUM_PKTS_RECEIVED_REG ():      
    return 0x2000294

def BRAM_OQ_QUEUE_1_NUM_PKTS_DROPPED_REG ():       
    return 0x2000298

def BRAM_OQ_QUEUE_1_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x200029c

def BRAM_OQ_QUEUE_2_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x20002a0

def BRAM_OQ_QUEUE_2_NUM_PKTS_RECEIVED_REG ():      
    return 0x20002a4

def BRAM_OQ_QUEUE_2_NUM_PKTS_DROPPED_REG ():       
    return 0x20002a8

def BRAM_OQ_QUEUE_2_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x20002ac

def BRAM_OQ_QUEUE_3_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x20002b0

def BRAM_OQ_QUEUE_3_NUM_PKTS_RECEIVED_REG ():      
    return 0x20002b4

def BRAM_OQ_QUEUE_3_NUM_PKTS_DROPPED_REG ():       
    return 0x20002b8

def BRAM_OQ_QUEUE_3_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x20002bc

def BRAM_OQ_QUEUE_4_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x20002c0

def BRAM_OQ_QUEUE_4_NUM_PKTS_RECEIVED_REG ():      
    return 0x20002c4

def BRAM_OQ_QUEUE_4_NUM_PKTS_DROPPED_REG ():       
    return 0x20002c8

def BRAM_OQ_QUEUE_4_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x20002cc

def BRAM_OQ_QUEUE_5_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x20002d0

def BRAM_OQ_QUEUE_5_NUM_PKTS_RECEIVED_REG ():      
    return 0x20002d4

def BRAM_OQ_QUEUE_5_NUM_PKTS_DROPPED_REG ():       
    return 0x20002d8

def BRAM_OQ_QUEUE_5_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x20002dc

def BRAM_OQ_QUEUE_6_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x20002e0

def BRAM_OQ_QUEUE_6_NUM_PKTS_RECEIVED_REG ():      
    return 0x20002e4

def BRAM_OQ_QUEUE_6_NUM_PKTS_DROPPED_REG ():       
    return 0x20002e8

def BRAM_OQ_QUEUE_6_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x20002ec

def BRAM_OQ_QUEUE_7_NUM_PKT_BYTES_RECEIVED_REG (): 
    return 0x20002f0

def BRAM_OQ_QUEUE_7_NUM_PKTS_RECEIVED_REG ():      
    return 0x20002f4

def BRAM_OQ_QUEUE_7_NUM_PKTS_DROPPED_REG ():       
    return 0x20002f8

def BRAM_OQ_QUEUE_7_NUM_WORDS_IN_QUEUE_REG ():     
    return 0x20002fc


def BRAM_OQ_QUEUE_GROUP_BASE_ADDR ():
    return 0x2000280

def BRAM_OQ_QUEUE_GROUP_INST_OFFSET():
    return 0x0000010

# Name: DRAM (DRAM)
# Description: DRAM



# -------------------------------------
#   Bitmasks
# -------------------------------------

# Type: dma_iface_ctrl
# Description: DMA interface control register
# File: lib/verilog/core/dma/xml/dma.xml

# Part 1: bit positions
def DMA_IFACE_CTRL_DISABLE_POS():
    return 0

def DMA_IFACE_CTRL_RESET_POS():
    return 1


# Part 2: masks/values
def DMA_IFACE_CTRL_DISABLE():
    return 0x001; 

def DMA_IFACE_CTRL_RESET():
    return 0x002; 


# Type: mii_ctrl
# Description: MII control register
# File: lib/verilog/core/io/mdio/xml/mdio.xml

# Part 1: bit positions
def MII_CTRL_RESET_POS():
    return 15

def MII_CTRL_INTERNAL_LOOPBACK_POS():
    return 14

def MII_CTRL_SPEED_SEL_LO_POS():
    return 13

def MII_CTRL_AUTONEG_ENABLE_POS():
    return 12

def MII_CTRL_PWR_DOWN_POS():
    return 11

def MII_CTRL_ISOLATE_POS():
    return 10

def MII_CTRL_RESTART_AUTONEG_POS():
    return 9

def MII_CTRL_DUPLEX_MODE_POS():
    return 8

def MII_CTRL_COLLISION_TEST_EN_POS():
    return 7

def MII_CTRL_SPEED_SEL_HI_POS():
    return 6


# Part 2: masks/values
def MII_CTRL_RESET():
    return 0x8000; 

def MII_CTRL_INTERNAL_LOOPBACK():
    return 0x4000; 

def MII_CTRL_SPEED_SEL_LO():
    return 0x2000; 

def MII_CTRL_AUTONEG_ENABLE():
    return 0x1000; 

def MII_CTRL_PWR_DOWN():
    return 0x0800; 

def MII_CTRL_ISOLATE():
    return 0x0400; 

def MII_CTRL_RESTART_AUTONEG():
    return 0x0200; 

def MII_CTRL_DUPLEX_MODE():
    return 0x0100; 

def MII_CTRL_COLLISION_TEST_EN():
    return 0x0080; 

def MII_CTRL_SPEED_SEL_HI():
    return 0x0040; 


# Type: mii_status
# Description: MII status register
# File: lib/verilog/core/io/mdio/xml/mdio.xml

# Part 1: bit positions
def MII_STATUS_100BASE_T4_CAPABLE_POS():
    return 15

def MII_STATUS_100BASE_X_FULL_DPLX_CAPABLE_POS():
    return 14

def MII_STATUS_100BASE_X_HALF_DPLX_CAPABLE_POS():
    return 13

def MII_STATUS_10BASE_T_FULL_DPLX_CAPABLE_POS():
    return 12

def MII_STATUS_10BASE_T_HALF_DPLX_CAPABLE_POS():
    return 11

def MII_STATUS_10BASE_T2_FULL_DPLX_CAPABLE_POS():
    return 10

def MII_STATUS_10BASE_T2_HALF_DPLX_CAPABLE_POS():
    return 9

def MII_STATUS_EXTENDED_STATUS_POS():
    return 8

def MII_STATUS_MF_PREAMBLE_SUPPRESS_POS():
    return 6

def MII_STATUS_AUTONEG_COMPLETE_POS():
    return 5

def MII_STATUS_REMOTE_FAULT_POS():
    return 4

def MII_STATUS_AUTONEG_ABILITY_POS():
    return 3

def MII_STATUS_LINK_STATUS_POS():
    return 2

def MII_STATUS_JABBER_DETECT_POS():
    return 1

def MII_STATUS_EXTENDED_CAPABILITY_POS():
    return 0


# Part 2: masks/values
def MII_STATUS_100BASE_T4_CAPABLE():
    return 0x8000; 

def MII_STATUS_100BASE_X_FULL_DPLX_CAPABLE():
    return 0x4000; 

def MII_STATUS_100BASE_X_HALF_DPLX_CAPABLE():
    return 0x2000; 

def MII_STATUS_10BASE_T_FULL_DPLX_CAPABLE():
    return 0x1000; 

def MII_STATUS_10BASE_T_HALF_DPLX_CAPABLE():
    return 0x0800; 

def MII_STATUS_10BASE_T2_FULL_DPLX_CAPABLE():
    return 0x0400; 

def MII_STATUS_10BASE_T2_HALF_DPLX_CAPABLE():
    return 0x0200; 

def MII_STATUS_EXTENDED_STATUS():
    return 0x0100; 

def MII_STATUS_MF_PREAMBLE_SUPPRESS():
    return 0x0040; 

def MII_STATUS_AUTONEG_COMPLETE():
    return 0x0020; 

def MII_STATUS_REMOTE_FAULT():
    return 0x0010; 

def MII_STATUS_AUTONEG_ABILITY():
    return 0x0008; 

def MII_STATUS_LINK_STATUS():
    return 0x0004; 

def MII_STATUS_JABBER_DETECT():
    return 0x0002; 

def MII_STATUS_EXTENDED_CAPABILITY():
    return 0x0001; 


# Type: cpu_queue_control
# Description: DMA queue control register
# File: lib/verilog/core/io_queues/cpu_dma_queue/xml/cpu_dma_queue.xml

# Part 1: bit positions
def CPU_QUEUE_CONTROL_TX_QUEUE_DISABLE_POS():
    return 0

def CPU_QUEUE_CONTROL_RX_QUEUE_DISABLE_POS():
    return 1


# Part 2: masks/values
def CPU_QUEUE_CONTROL_TX_QUEUE_DISABLE():
    return 0x001; 

def CPU_QUEUE_CONTROL_RX_QUEUE_DISABLE():
    return 0x002; 


# Type: mac_grp_control
# Description: MAC group control register
# File: lib/verilog/core/io_queues/ethernet_queue/xml/ethernet_mac.xml

# Part 1: bit positions
def MAC_GRP_CONTROL_TX_QUEUE_DISABLE_POS():
    return 0

def MAC_GRP_CONTROL_RX_QUEUE_DISABLE_POS():
    return 1

def MAC_GRP_CONTROL_RESET_MAC_POS():
    return 2

def MAC_GRP_CONTROL_MAC_DISABLE_TX_POS():
    return 3

def MAC_GRP_CONTROL_MAC_DISABLE_RX_POS():
    return 4

def MAC_GRP_CONTROL_MAC_DISABLE_JUMBO_TX_POS():
    return 5

def MAC_GRP_CONTROL_MAC_DISABLE_JUMBO_RX_POS():
    return 6

def MAC_GRP_CONTROL_MAC_DISABLE_CRC_CHECK_POS():
    return 7

def MAC_GRP_CONTROL_MAC_DISABLE_CRC_GEN_POS():
    return 8


# Part 2: masks/values
def MAC_GRP_CONTROL_TX_QUEUE_DISABLE():
    return 0x001; 

def MAC_GRP_CONTROL_RX_QUEUE_DISABLE():
    return 0x002; 

def MAC_GRP_CONTROL_RESET_MAC():
    return 0x004; 

def MAC_GRP_CONTROL_MAC_DISABLE_TX():
    return 0x008; 

def MAC_GRP_CONTROL_MAC_DISABLE_RX():
    return 0x010; 

def MAC_GRP_CONTROL_MAC_DISABLE_JUMBO_TX():
    return 0x020; 

def MAC_GRP_CONTROL_MAC_DISABLE_JUMBO_RX():
    return 0x040; 

def MAC_GRP_CONTROL_MAC_DISABLE_CRC_CHECK():
    return 0x080; 

def MAC_GRP_CONTROL_MAC_DISABLE_CRC_GEN():
    return 0x100; 




# -------------------------------------
#   Register map
# -------------------------------------

import __main__;
if 'nf_regmap' not in dir(__main__):
    __main__.nf_regmap = {}

__main__.nf_regmap.update({
    0x0400000 : "DEV_ID_MD5_0_REG",
    0x0400004 : "DEV_ID_MD5_1_REG",
    0x0400008 : "DEV_ID_MD5_2_REG",
    0x040000c : "DEV_ID_MD5_3_REG",
    0x0400010 : "DEV_ID_DEVICE_ID_REG",
    0x0400014 : "DEV_ID_VERSION_REG",
    0x0400018 : "DEV_ID_CPCI_ID_REG",
    0x040001c : "DEV_ID_PROJ_DIR_0_REG",
    0x0400020 : "DEV_ID_PROJ_DIR_1_REG",
    0x0400024 : "DEV_ID_PROJ_DIR_2_REG",
    0x0400028 : "DEV_ID_PROJ_DIR_3_REG",
    0x040002c : "DEV_ID_PROJ_DIR_4_REG",
    0x0400030 : "DEV_ID_PROJ_DIR_5_REG",
    0x0400034 : "DEV_ID_PROJ_DIR_6_REG",
    0x0400038 : "DEV_ID_PROJ_DIR_7_REG",
    0x040003c : "DEV_ID_PROJ_DIR_8_REG",
    0x0400040 : "DEV_ID_PROJ_DIR_9_REG",
    0x0400044 : "DEV_ID_PROJ_DIR_10_REG",
    0x0400048 : "DEV_ID_PROJ_DIR_11_REG",
    0x040004c : "DEV_ID_PROJ_DIR_12_REG",
    0x0400050 : "DEV_ID_PROJ_DIR_13_REG",
    0x0400054 : "DEV_ID_PROJ_DIR_14_REG",
    0x0400058 : "DEV_ID_PROJ_DIR_15_REG",
    0x040005c : "DEV_ID_PROJ_NAME_0_REG",
    0x0400060 : "DEV_ID_PROJ_NAME_1_REG",
    0x0400064 : "DEV_ID_PROJ_NAME_2_REG",
    0x0400068 : "DEV_ID_PROJ_NAME_3_REG",
    0x040006c : "DEV_ID_PROJ_NAME_4_REG",
    0x0400070 : "DEV_ID_PROJ_NAME_5_REG",
    0x0400074 : "DEV_ID_PROJ_NAME_6_REG",
    0x0400078 : "DEV_ID_PROJ_NAME_7_REG",
    0x040007c : "DEV_ID_PROJ_NAME_8_REG",
    0x0400080 : "DEV_ID_PROJ_NAME_9_REG",
    0x0400084 : "DEV_ID_PROJ_NAME_10_REG",
    0x0400088 : "DEV_ID_PROJ_NAME_11_REG",
    0x040008c : "DEV_ID_PROJ_NAME_12_REG",
    0x0400090 : "DEV_ID_PROJ_NAME_13_REG",
    0x0400094 : "DEV_ID_PROJ_NAME_14_REG",
    0x0400098 : "DEV_ID_PROJ_NAME_15_REG",
    0x040009c : "DEV_ID_PROJ_DESC_0_REG",
    0x04000a0 : "DEV_ID_PROJ_DESC_1_REG",
    0x04000a4 : "DEV_ID_PROJ_DESC_2_REG",
    0x04000a8 : "DEV_ID_PROJ_DESC_3_REG",
    0x04000ac : "DEV_ID_PROJ_DESC_4_REG",
    0x04000b0 : "DEV_ID_PROJ_DESC_5_REG",
    0x04000b4 : "DEV_ID_PROJ_DESC_6_REG",
    0x04000b8 : "DEV_ID_PROJ_DESC_7_REG",
    0x04000bc : "DEV_ID_PROJ_DESC_8_REG",
    0x04000c0 : "DEV_ID_PROJ_DESC_9_REG",
    0x04000c4 : "DEV_ID_PROJ_DESC_10_REG",
    0x04000c8 : "DEV_ID_PROJ_DESC_11_REG",
    0x04000cc : "DEV_ID_PROJ_DESC_12_REG",
    0x04000d0 : "DEV_ID_PROJ_DESC_13_REG",
    0x04000d4 : "DEV_ID_PROJ_DESC_14_REG",
    0x04000d8 : "DEV_ID_PROJ_DESC_15_REG",
    0x04000dc : "DEV_ID_PROJ_DESC_16_REG",
    0x04000e0 : "DEV_ID_PROJ_DESC_17_REG",
    0x04000e4 : "DEV_ID_PROJ_DESC_18_REG",
    0x04000e8 : "DEV_ID_PROJ_DESC_19_REG",
    0x04000ec : "DEV_ID_PROJ_DESC_20_REG",
    0x04000f0 : "DEV_ID_PROJ_DESC_21_REG",
    0x04000f4 : "DEV_ID_PROJ_DESC_22_REG",
    0x04000f8 : "DEV_ID_PROJ_DESC_23_REG",
    0x04000fc : "DEV_ID_PROJ_DESC_24_REG",

    0x0440000 : "MDIO_PHY_0_CONTROL_REG",
    0x0440004 : "MDIO_PHY_0_STATUS_REG",
    0x0440008 : "MDIO_PHY_0_PHY_ID_HI_REG",
    0x044000c : "MDIO_PHY_0_PHY_ID_LO_REG",
    0x0440010 : "MDIO_PHY_0_AUTONEGOTIATION_ADVERT_REG",
    0x0440014 : "MDIO_PHY_0_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG",
    0x0440018 : "MDIO_PHY_0_AUTONEG_EXPANSION_REG",
    0x044001c : "MDIO_PHY_0_AUTONEG_NEXT_PAGE_TX_REG",
    0x0440020 : "MDIO_PHY_0_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG",
    0x0440024 : "MDIO_PHY_0_MASTER_SLAVE_CTRL_REG",
    0x0440028 : "MDIO_PHY_0_MASTER_SLAVE_STATUS_REG",
    0x044002c : "MDIO_PHY_0_PSE_CTRL_REG",
    0x0440030 : "MDIO_PHY_0_PSE_STATUS_REG",
    0x0440034 : "MDIO_PHY_0_MMD_ACCESS_CTRL_REG",
    0x0440038 : "MDIO_PHY_0_MMD_ACCESS_STATUS_REG",
    0x044003c : "MDIO_PHY_0_EXTENDED_STATUS_REG",
    0x0440040 : "MDIO_PHY_0_PHY_EXTENDED_CTRL_REG",
    0x0440044 : "MDIO_PHY_0_PHY_EXTENDED_STATUS_REG",
    0x0440048 : "MDIO_PHY_0_RX_ERROR_COUNT_REG",
    0x044004c : "MDIO_PHY_0_FALSE_CARRIER_SENSE_COUNT_REG",
    0x0440050 : "MDIO_PHY_0_RX_NOT_OK_COUNT_REG",
    0x0440054 : "MDIO_PHY_0_EXPANSION_1_REG",
    0x0440058 : "MDIO_PHY_0_EXPANSION_2_REG",
    0x044005c : "MDIO_PHY_0_EXPANSION_REG_ACCESS_REG",
    0x0440060 : "MDIO_PHY_0_SHADOW_18_REG",
    0x0440064 : "MDIO_PHY_0_AUX_STATUS_REG",
    0x0440068 : "MDIO_PHY_0_INT_STATUS_REG",
    0x044006c : "MDIO_PHY_0_INT_MASK_REG",
    0x0440070 : "MDIO_PHY_0_SHADOW_1C_REG",
    0x0440074 : "MDIO_PHY_0_SHADOW_1D_REG",
    0x0440078 : "MDIO_PHY_0_TEST_REG",
    0x044007c : "MDIO_PHY_0_RESERVED_REG",
    0x0440080 : "MDIO_PHY_1_CONTROL_REG",
    0x0440084 : "MDIO_PHY_1_STATUS_REG",
    0x0440088 : "MDIO_PHY_1_PHY_ID_HI_REG",
    0x044008c : "MDIO_PHY_1_PHY_ID_LO_REG",
    0x0440090 : "MDIO_PHY_1_AUTONEGOTIATION_ADVERT_REG",
    0x0440094 : "MDIO_PHY_1_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG",
    0x0440098 : "MDIO_PHY_1_AUTONEG_EXPANSION_REG",
    0x044009c : "MDIO_PHY_1_AUTONEG_NEXT_PAGE_TX_REG",
    0x04400a0 : "MDIO_PHY_1_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG",
    0x04400a4 : "MDIO_PHY_1_MASTER_SLAVE_CTRL_REG",
    0x04400a8 : "MDIO_PHY_1_MASTER_SLAVE_STATUS_REG",
    0x04400ac : "MDIO_PHY_1_PSE_CTRL_REG",
    0x04400b0 : "MDIO_PHY_1_PSE_STATUS_REG",
    0x04400b4 : "MDIO_PHY_1_MMD_ACCESS_CTRL_REG",
    0x04400b8 : "MDIO_PHY_1_MMD_ACCESS_STATUS_REG",
    0x04400bc : "MDIO_PHY_1_EXTENDED_STATUS_REG",
    0x04400c0 : "MDIO_PHY_1_PHY_EXTENDED_CTRL_REG",
    0x04400c4 : "MDIO_PHY_1_PHY_EXTENDED_STATUS_REG",
    0x04400c8 : "MDIO_PHY_1_RX_ERROR_COUNT_REG",
    0x04400cc : "MDIO_PHY_1_FALSE_CARRIER_SENSE_COUNT_REG",
    0x04400d0 : "MDIO_PHY_1_RX_NOT_OK_COUNT_REG",
    0x04400d4 : "MDIO_PHY_1_EXPANSION_1_REG",
    0x04400d8 : "MDIO_PHY_1_EXPANSION_2_REG",
    0x04400dc : "MDIO_PHY_1_EXPANSION_REG_ACCESS_REG",
    0x04400e0 : "MDIO_PHY_1_SHADOW_18_REG",
    0x04400e4 : "MDIO_PHY_1_AUX_STATUS_REG",
    0x04400e8 : "MDIO_PHY_1_INT_STATUS_REG",
    0x04400ec : "MDIO_PHY_1_INT_MASK_REG",
    0x04400f0 : "MDIO_PHY_1_SHADOW_1C_REG",
    0x04400f4 : "MDIO_PHY_1_SHADOW_1D_REG",
    0x04400f8 : "MDIO_PHY_1_TEST_REG",
    0x04400fc : "MDIO_PHY_1_RESERVED_REG",
    0x0440100 : "MDIO_PHY_2_CONTROL_REG",
    0x0440104 : "MDIO_PHY_2_STATUS_REG",
    0x0440108 : "MDIO_PHY_2_PHY_ID_HI_REG",
    0x044010c : "MDIO_PHY_2_PHY_ID_LO_REG",
    0x0440110 : "MDIO_PHY_2_AUTONEGOTIATION_ADVERT_REG",
    0x0440114 : "MDIO_PHY_2_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG",
    0x0440118 : "MDIO_PHY_2_AUTONEG_EXPANSION_REG",
    0x044011c : "MDIO_PHY_2_AUTONEG_NEXT_PAGE_TX_REG",
    0x0440120 : "MDIO_PHY_2_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG",
    0x0440124 : "MDIO_PHY_2_MASTER_SLAVE_CTRL_REG",
    0x0440128 : "MDIO_PHY_2_MASTER_SLAVE_STATUS_REG",
    0x044012c : "MDIO_PHY_2_PSE_CTRL_REG",
    0x0440130 : "MDIO_PHY_2_PSE_STATUS_REG",
    0x0440134 : "MDIO_PHY_2_MMD_ACCESS_CTRL_REG",
    0x0440138 : "MDIO_PHY_2_MMD_ACCESS_STATUS_REG",
    0x044013c : "MDIO_PHY_2_EXTENDED_STATUS_REG",
    0x0440140 : "MDIO_PHY_2_PHY_EXTENDED_CTRL_REG",
    0x0440144 : "MDIO_PHY_2_PHY_EXTENDED_STATUS_REG",
    0x0440148 : "MDIO_PHY_2_RX_ERROR_COUNT_REG",
    0x044014c : "MDIO_PHY_2_FALSE_CARRIER_SENSE_COUNT_REG",
    0x0440150 : "MDIO_PHY_2_RX_NOT_OK_COUNT_REG",
    0x0440154 : "MDIO_PHY_2_EXPANSION_1_REG",
    0x0440158 : "MDIO_PHY_2_EXPANSION_2_REG",
    0x044015c : "MDIO_PHY_2_EXPANSION_REG_ACCESS_REG",
    0x0440160 : "MDIO_PHY_2_SHADOW_18_REG",
    0x0440164 : "MDIO_PHY_2_AUX_STATUS_REG",
    0x0440168 : "MDIO_PHY_2_INT_STATUS_REG",
    0x044016c : "MDIO_PHY_2_INT_MASK_REG",
    0x0440170 : "MDIO_PHY_2_SHADOW_1C_REG",
    0x0440174 : "MDIO_PHY_2_SHADOW_1D_REG",
    0x0440178 : "MDIO_PHY_2_TEST_REG",
    0x044017c : "MDIO_PHY_2_RESERVED_REG",
    0x0440180 : "MDIO_PHY_3_CONTROL_REG",
    0x0440184 : "MDIO_PHY_3_STATUS_REG",
    0x0440188 : "MDIO_PHY_3_PHY_ID_HI_REG",
    0x044018c : "MDIO_PHY_3_PHY_ID_LO_REG",
    0x0440190 : "MDIO_PHY_3_AUTONEGOTIATION_ADVERT_REG",
    0x0440194 : "MDIO_PHY_3_AUTONEG_LINK_PARTNER_BASE_PAGE_ABILITY_REG",
    0x0440198 : "MDIO_PHY_3_AUTONEG_EXPANSION_REG",
    0x044019c : "MDIO_PHY_3_AUTONEG_NEXT_PAGE_TX_REG",
    0x04401a0 : "MDIO_PHY_3_AUTONEG_LINK_PARTNER_RCVD_NEXT_PAGE_REG",
    0x04401a4 : "MDIO_PHY_3_MASTER_SLAVE_CTRL_REG",
    0x04401a8 : "MDIO_PHY_3_MASTER_SLAVE_STATUS_REG",
    0x04401ac : "MDIO_PHY_3_PSE_CTRL_REG",
    0x04401b0 : "MDIO_PHY_3_PSE_STATUS_REG",
    0x04401b4 : "MDIO_PHY_3_MMD_ACCESS_CTRL_REG",
    0x04401b8 : "MDIO_PHY_3_MMD_ACCESS_STATUS_REG",
    0x04401bc : "MDIO_PHY_3_EXTENDED_STATUS_REG",
    0x04401c0 : "MDIO_PHY_3_PHY_EXTENDED_CTRL_REG",
    0x04401c4 : "MDIO_PHY_3_PHY_EXTENDED_STATUS_REG",
    0x04401c8 : "MDIO_PHY_3_RX_ERROR_COUNT_REG",
    0x04401cc : "MDIO_PHY_3_FALSE_CARRIER_SENSE_COUNT_REG",
    0x04401d0 : "MDIO_PHY_3_RX_NOT_OK_COUNT_REG",
    0x04401d4 : "MDIO_PHY_3_EXPANSION_1_REG",
    0x04401d8 : "MDIO_PHY_3_EXPANSION_2_REG",
    0x04401dc : "MDIO_PHY_3_EXPANSION_REG_ACCESS_REG",
    0x04401e0 : "MDIO_PHY_3_SHADOW_18_REG",
    0x04401e4 : "MDIO_PHY_3_AUX_STATUS_REG",
    0x04401e8 : "MDIO_PHY_3_INT_STATUS_REG",
    0x04401ec : "MDIO_PHY_3_INT_MASK_REG",
    0x04401f0 : "MDIO_PHY_3_SHADOW_1C_REG",
    0x04401f4 : "MDIO_PHY_3_SHADOW_1D_REG",
    0x04401f8 : "MDIO_PHY_3_TEST_REG",
    0x04401fc : "MDIO_PHY_3_RESERVED_REG",

    0x0500000 : "DMA_CTRL_REG",
    0x0500004 : "DMA_NUM_INGRESS_PKTS_REG",
    0x0500008 : "DMA_NUM_INGRESS_BYTES_REG",
    0x050000c : "DMA_NUM_EGRESS_PKTS_REG",
    0x0500010 : "DMA_NUM_EGRESS_BYTES_REG",
    0x0500014 : "DMA_NUM_TIMEOUTS_REG",

    0x0600000 : "MAC_GRP_0_CONTROL_REG",
    0x0600004 : "MAC_GRP_0_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0600008 : "MAC_GRP_0_RX_QUEUE_NUM_PKTS_STORED_REG",
    0x060000c : "MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG",
    0x0600010 : "MAC_GRP_0_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x0600014 : "MAC_GRP_0_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0600018 : "MAC_GRP_0_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x060001c : "MAC_GRP_0_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x0600020 : "MAC_GRP_0_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0600024 : "MAC_GRP_0_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x0600028 : "MAC_GRP_0_TX_QUEUE_NUM_PKTS_SENT_REG",
    0x060002c : "MAC_GRP_0_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x0600030 : "MAC_GRP_0_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x0640000 : "MAC_GRP_1_CONTROL_REG",
    0x0640004 : "MAC_GRP_1_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0640008 : "MAC_GRP_1_RX_QUEUE_NUM_PKTS_STORED_REG",
    0x064000c : "MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG",
    0x0640010 : "MAC_GRP_1_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x0640014 : "MAC_GRP_1_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0640018 : "MAC_GRP_1_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x064001c : "MAC_GRP_1_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x0640020 : "MAC_GRP_1_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0640024 : "MAC_GRP_1_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x0640028 : "MAC_GRP_1_TX_QUEUE_NUM_PKTS_SENT_REG",
    0x064002c : "MAC_GRP_1_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x0640030 : "MAC_GRP_1_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x0680000 : "MAC_GRP_2_CONTROL_REG",
    0x0680004 : "MAC_GRP_2_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0680008 : "MAC_GRP_2_RX_QUEUE_NUM_PKTS_STORED_REG",
    0x068000c : "MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG",
    0x0680010 : "MAC_GRP_2_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x0680014 : "MAC_GRP_2_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0680018 : "MAC_GRP_2_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x068001c : "MAC_GRP_2_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x0680020 : "MAC_GRP_2_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0680024 : "MAC_GRP_2_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x0680028 : "MAC_GRP_2_TX_QUEUE_NUM_PKTS_SENT_REG",
    0x068002c : "MAC_GRP_2_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x0680030 : "MAC_GRP_2_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x06c0000 : "MAC_GRP_3_CONTROL_REG",
    0x06c0004 : "MAC_GRP_3_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x06c0008 : "MAC_GRP_3_RX_QUEUE_NUM_PKTS_STORED_REG",
    0x06c000c : "MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_FULL_REG",
    0x06c0010 : "MAC_GRP_3_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x06c0014 : "MAC_GRP_3_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x06c0018 : "MAC_GRP_3_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x06c001c : "MAC_GRP_3_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x06c0020 : "MAC_GRP_3_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x06c0024 : "MAC_GRP_3_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x06c0028 : "MAC_GRP_3_TX_QUEUE_NUM_PKTS_SENT_REG",
    0x06c002c : "MAC_GRP_3_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x06c0030 : "MAC_GRP_3_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x0700000 : "CPU_QUEUE_0_CONTROL_REG",
    0x0700004 : "CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0700008 : "CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x070000c : "CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x0700010 : "CPU_QUEUE_0_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0700014 : "CPU_QUEUE_0_RX_QUEUE_NUM_UNDERRUNS_REG",
    0x0700018 : "CPU_QUEUE_0_RX_QUEUE_NUM_OVERRUNS_REG",
    0x070001c : "CPU_QUEUE_0_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x0700020 : "CPU_QUEUE_0_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x0700024 : "CPU_QUEUE_0_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0700028 : "CPU_QUEUE_0_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x070002c : "CPU_QUEUE_0_TX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0700030 : "CPU_QUEUE_0_TX_QUEUE_NUM_UNDERRUNS_REG",
    0x0700034 : "CPU_QUEUE_0_TX_QUEUE_NUM_OVERRUNS_REG",
    0x0700038 : "CPU_QUEUE_0_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x070003c : "CPU_QUEUE_0_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x0740000 : "CPU_QUEUE_1_CONTROL_REG",
    0x0740004 : "CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0740008 : "CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x074000c : "CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x0740010 : "CPU_QUEUE_1_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0740014 : "CPU_QUEUE_1_RX_QUEUE_NUM_UNDERRUNS_REG",
    0x0740018 : "CPU_QUEUE_1_RX_QUEUE_NUM_OVERRUNS_REG",
    0x074001c : "CPU_QUEUE_1_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x0740020 : "CPU_QUEUE_1_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x0740024 : "CPU_QUEUE_1_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0740028 : "CPU_QUEUE_1_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x074002c : "CPU_QUEUE_1_TX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0740030 : "CPU_QUEUE_1_TX_QUEUE_NUM_UNDERRUNS_REG",
    0x0740034 : "CPU_QUEUE_1_TX_QUEUE_NUM_OVERRUNS_REG",
    0x0740038 : "CPU_QUEUE_1_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x074003c : "CPU_QUEUE_1_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x0780000 : "CPU_QUEUE_2_CONTROL_REG",
    0x0780004 : "CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0780008 : "CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x078000c : "CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x0780010 : "CPU_QUEUE_2_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0780014 : "CPU_QUEUE_2_RX_QUEUE_NUM_UNDERRUNS_REG",
    0x0780018 : "CPU_QUEUE_2_RX_QUEUE_NUM_OVERRUNS_REG",
    0x078001c : "CPU_QUEUE_2_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x0780020 : "CPU_QUEUE_2_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x0780024 : "CPU_QUEUE_2_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x0780028 : "CPU_QUEUE_2_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x078002c : "CPU_QUEUE_2_TX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x0780030 : "CPU_QUEUE_2_TX_QUEUE_NUM_UNDERRUNS_REG",
    0x0780034 : "CPU_QUEUE_2_TX_QUEUE_NUM_OVERRUNS_REG",
    0x0780038 : "CPU_QUEUE_2_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x078003c : "CPU_QUEUE_2_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x07c0000 : "CPU_QUEUE_3_CONTROL_REG",
    0x07c0004 : "CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x07c0008 : "CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x07c000c : "CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_DROPPED_BAD_REG",
    0x07c0010 : "CPU_QUEUE_3_RX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x07c0014 : "CPU_QUEUE_3_RX_QUEUE_NUM_UNDERRUNS_REG",
    0x07c0018 : "CPU_QUEUE_3_RX_QUEUE_NUM_OVERRUNS_REG",
    0x07c001c : "CPU_QUEUE_3_RX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x07c0020 : "CPU_QUEUE_3_RX_QUEUE_NUM_BYTES_PUSHED_REG",
    0x07c0024 : "CPU_QUEUE_3_TX_QUEUE_NUM_PKTS_IN_QUEUE_REG",
    0x07c0028 : "CPU_QUEUE_3_TX_QUEUE_NUM_PKTS_ENQUEUED_REG",
    0x07c002c : "CPU_QUEUE_3_TX_QUEUE_NUM_PKTS_DEQUEUED_REG",
    0x07c0030 : "CPU_QUEUE_3_TX_QUEUE_NUM_UNDERRUNS_REG",
    0x07c0034 : "CPU_QUEUE_3_TX_QUEUE_NUM_OVERRUNS_REG",
    0x07c0038 : "CPU_QUEUE_3_TX_QUEUE_NUM_WORDS_PUSHED_REG",
    0x07c003c : "CPU_QUEUE_3_TX_QUEUE_NUM_BYTES_PUSHED_REG",

    0x2000000 : "IN_ARB_NUM_PKTS_SENT_REG",
    0x2000004 : "IN_ARB_LAST_PKT_WORD_0_HI_REG",
    0x2000008 : "IN_ARB_LAST_PKT_WORD_0_LO_REG",
    0x200000c : "IN_ARB_LAST_PKT_CTRL_0_REG",
    0x2000010 : "IN_ARB_LAST_PKT_WORD_1_HI_REG",
    0x2000014 : "IN_ARB_LAST_PKT_WORD_1_LO_REG",
    0x2000018 : "IN_ARB_LAST_PKT_CTRL_1_REG",
    0x200001c : "IN_ARB_STATE_REG",

    0x2000100 : "FIREWALL_DPORT1_REG",
    0x2000104 : "FIREWALL_DPORT2_REG",
    0x2000108 : "FIREWALL_DPORT3_REG",
    0x200010c : "FIREWALL_DPORT4_REG",

    0x2000200 : "BRAM_OQ_DISABLE_QUEUES_REG",
    0x2000280 : "BRAM_OQ_QUEUE_0_NUM_PKT_BYTES_RECEIVED_REG",
    0x2000284 : "BRAM_OQ_QUEUE_0_NUM_PKTS_RECEIVED_REG",
    0x2000288 : "BRAM_OQ_QUEUE_0_NUM_PKTS_DROPPED_REG",
    0x200028c : "BRAM_OQ_QUEUE_0_NUM_WORDS_IN_QUEUE_REG",
    0x2000290 : "BRAM_OQ_QUEUE_1_NUM_PKT_BYTES_RECEIVED_REG",
    0x2000294 : "BRAM_OQ_QUEUE_1_NUM_PKTS_RECEIVED_REG",
    0x2000298 : "BRAM_OQ_QUEUE_1_NUM_PKTS_DROPPED_REG",
    0x200029c : "BRAM_OQ_QUEUE_1_NUM_WORDS_IN_QUEUE_REG",
    0x20002a0 : "BRAM_OQ_QUEUE_2_NUM_PKT_BYTES_RECEIVED_REG",
    0x20002a4 : "BRAM_OQ_QUEUE_2_NUM_PKTS_RECEIVED_REG",
    0x20002a8 : "BRAM_OQ_QUEUE_2_NUM_PKTS_DROPPED_REG",
    0x20002ac : "BRAM_OQ_QUEUE_2_NUM_WORDS_IN_QUEUE_REG",
    0x20002b0 : "BRAM_OQ_QUEUE_3_NUM_PKT_BYTES_RECEIVED_REG",
    0x20002b4 : "BRAM_OQ_QUEUE_3_NUM_PKTS_RECEIVED_REG",
    0x20002b8 : "BRAM_OQ_QUEUE_3_NUM_PKTS_DROPPED_REG",
    0x20002bc : "BRAM_OQ_QUEUE_3_NUM_WORDS_IN_QUEUE_REG",
    0x20002c0 : "BRAM_OQ_QUEUE_4_NUM_PKT_BYTES_RECEIVED_REG",
    0x20002c4 : "BRAM_OQ_QUEUE_4_NUM_PKTS_RECEIVED_REG",
    0x20002c8 : "BRAM_OQ_QUEUE_4_NUM_PKTS_DROPPED_REG",
    0x20002cc : "BRAM_OQ_QUEUE_4_NUM_WORDS_IN_QUEUE_REG",
    0x20002d0 : "BRAM_OQ_QUEUE_5_NUM_PKT_BYTES_RECEIVED_REG",
    0x20002d4 : "BRAM_OQ_QUEUE_5_NUM_PKTS_RECEIVED_REG",
    0x20002d8 : "BRAM_OQ_QUEUE_5_NUM_PKTS_DROPPED_REG",
    0x20002dc : "BRAM_OQ_QUEUE_5_NUM_WORDS_IN_QUEUE_REG",
    0x20002e0 : "BRAM_OQ_QUEUE_6_NUM_PKT_BYTES_RECEIVED_REG",
    0x20002e4 : "BRAM_OQ_QUEUE_6_NUM_PKTS_RECEIVED_REG",
    0x20002e8 : "BRAM_OQ_QUEUE_6_NUM_PKTS_DROPPED_REG",
    0x20002ec : "BRAM_OQ_QUEUE_6_NUM_WORDS_IN_QUEUE_REG",
    0x20002f0 : "BRAM_OQ_QUEUE_7_NUM_PKT_BYTES_RECEIVED_REG",
    0x20002f4 : "BRAM_OQ_QUEUE_7_NUM_PKTS_RECEIVED_REG",
    0x20002f8 : "BRAM_OQ_QUEUE_7_NUM_PKTS_DROPPED_REG",
    0x20002fc : "BRAM_OQ_QUEUE_7_NUM_WORDS_IN_QUEUE_REG",

})




# End of File
