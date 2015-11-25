#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_icmp.h"
#include "sr_utils.h"

void sr_send_icmp(uint8_t *buf, unsigned int len, unsigned int type, unsigned int code){
	printf("TODO: Send ICMP type %d code %d to\n",type, code);
	print_hdr(buf,(uint32_t)len);
}