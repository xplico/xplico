/* dnsdb.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef __DNSDB_H__
#define __DNSDB_H__

#include <time.h>

#include "ftypes.h"

/* dns ip element */
typedef struct _dns_ip dns_ip;
struct _dns_ip {
    ftval ip;           /**< IP value */
    unsigned long idn;  /**< name index */
    unsigned long hash; /**< hash value */
    time_t tins;        /**< insert time */
    dns_ip *inf;        /**< next hash < */
    dns_ip *eq;         /**< next ip with same hash */
    dns_ip *sup;        /**< next hash > */
};


/* dns name element */
typedef struct _dns_name dns_name;
struct _dns_name {
    ftval name;         /**< domain name (string) */
    unsigned short ref; /**< number of reference in dns_ip */
};


int DnsDbInit(void);
int DnsDbInset(ftval *name, enum ftype ntype, ftval *ip, enum ftype itype);
int DnsDbSearch(ftval *ip, enum ftype itype, char *buff, int len);
int DnsDbStatus(unsigned int *ipn, unsigned int *namen, unsigned long *size);


#endif /* __DNSDB_H__ */
