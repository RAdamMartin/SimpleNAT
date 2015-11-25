/*-----------------------------------------------------------------------------
 * file:  sr_icmp.h 
 *
 * Description:
 *
 * Data structures and methods for handeling ICMP
 *
 *---------------------------------------------------------------------------*/

#ifndef sr_ICMP_H
#define sr_ICMP_H

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#ifdef _SOLARIS_
#include </usr/include/sys/int_types.h>
#endif /* SOLARIS */

#ifdef _DARWIN_
#include <inttypes.h>
#endif

#include "sr_protocol.h"
/*struct sr_instance;*/

void sr_send_icmp(uint8_t *buf, unsigned int len, unsigned int type, unsigned int code);

#endif /* --  sr_ICMP_H -- */
