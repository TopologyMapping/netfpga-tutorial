/* ****************************************************************************
 * vim:set shiftwidth=2 softtabstop=2 expandtab:
 * $Id: counterdump.c 5455 2009-05-05 18:18:16Z g9coving $
 *
 * Module:  counterdump.c
 * Project: NetFPGA NIC
 * Description: dumps the MAC Rx/Tx counters to stdout
 * Author: Jad Naous
 *
 * Change history:
 *
 */
/*Testa escrita e leitura na SRAM utilizando interfaces de registradores*/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <ctype.h>
#include <net/if.h>

#include "../lib/C/reg_defines_firewall.h"
#include "../../../lib/C/common/nf2.h"
#include "../../../lib/C/common/nf2util.h"

#define PATHLEN		80

#define DEFAULT_IFACE	"nf2c0"

/* Global vars */
static struct nf2device nf2;

/*Dports will be record in memory to firewall drop pkts with them*/
uint16_t pdrop[4] = {0, 0, 0, 0};

/* Function declarations */
void dumpCounts();
void processArgs (int , char **);
void usage (void);

int main(int argc, char *argv[])
{
  nf2.device_name = DEFAULT_IFACE;

  processArgs(argc, argv);

  // Open the interface if possible
  if (check_iface(&nf2))
    {
      exit(1);
    }
  if (openDescriptor(&nf2))
    {
      exit(1);
    }
  if(argc > 5){
      printf("Numero de argumentos deve ser < 4\n");
      argc=5;
  } 
  for(int i=0; i< argc-1; i++){
     pdrop[i] = atoi(argv[i+1]);
  }
  dumpCounts();

  closeDescriptor(&nf2);

  return 0;
}

void dumpCounts(char **argv)
{
  unsigned val;
 
  /* O sram_arbiter segue a seguinte regra: Os 4 MSB enviados
 * como valor em writeReg dizem qual conjunto de 16bits 
 * da memoria receberá o dado nos 16 LSB do valor. 
 * */ 
  writeReg(&nf2, FIREWALL_DPORT1_REG,pdrop[0]);
  writeReg(&nf2, FIREWALL_DPORT2_REG,pdrop[1]);
  writeReg(&nf2, FIREWALL_DPORT3_REG,pdrop[2]);
  writeReg(&nf2, FIREWALL_DPORT4_REG,pdrop[3]);

  sleep(1);
  /*A memória endereça conjuntos de 9bits (9it) por bit:
 * SRAM_BASE_ADDR -> primeiro 9it. SRAM_BASE_ADDR+0x1->
 * segundo 9it, etc. Os 36 bits da memória são organizados 
 * em 32 bits pelo sram_arbiter.v para ser lido em val.
 * */
  readReg(&nf2, FIREWALL_DPORT1_REG, &val);
  printf("DPORT1: %d\n",val);
  readReg(&nf2, FIREWALL_DPORT2_REG, &val);
  printf("DPORT2: %d\n",val);
  readReg(&nf2, FIREWALL_DPORT3_REG, &val);
  printf("DPORT3: %d\n",val);
  readReg(&nf2, FIREWALL_DPORT4_REG, &val);
  printf("DPORT4: %d\n",val);
  
  printf("Leituras da sram\n");
  readReg(&nf2, SRAM_BASE_ADDR, &val);
  printf("DPORT4: %d\n",val>>16);
  printf("DPORT3: %d\n",val&0xffff);
  readReg(&nf2, SRAM_BASE_ADDR+4, &val);
  printf("DPORT2: %d\n",val>>16);
  printf("DPORT1: %d\n",val&0xffff);
}

/*
 *  Process the arguments.
 */
void processArgs (int argc, char **argv )
{
  char c;

  /* don't want getopt to moan - I can do that just fine thanks! */
  opterr = 0;

  while ((c = getopt (argc, argv, "i:h")) != -1)
    {
      switch (c)
	{
	case 'i':	/* interface name */
	  nf2.device_name = optarg;
	  break;
	case '?':
	  if (isprint (optopt))
	    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
	  else
	    fprintf (stderr,
		     "Unknown option character `\\x%x'.\n",
		     optopt);
	case 'h':
	default:
	  usage();
	  exit(1);
	}
    }
}


/*
 *  Describe usage of this program.
 */
void usage (void)
{
  printf("Usage: ./counterdump <options> \n\n");
  printf("Options: -i <iface> : interface name (default nf2c0)\n");
  printf("         -h : Print this message and exit.\n");
}
