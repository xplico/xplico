/* dnsdb.c
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <arpa/nameser.h>
#include <time.h>
#include <string.h>
#include <pthread.h>

#include "dnsdb.h"
#include "log.h"
#include "dmemory.h"
#include "istypes.h"


/** define */
#define DNSDB_TBL_ELEMENT_DELTA   10000


/** internal variables */
static dns_ip * volatile dns_ipv6_tr;               /* ipv6 tree */
static dns_ip * volatile dns_ipv4_tr;               /* ipv4 tree */
static dns_name * volatile dns_name_tbl;            /* name table */
static volatile unsigned int dns_ipx_num;           /* number of ip elements */
static volatile unsigned long dns_name_dim;         /* table name dim */
static volatile unsigned long dns_name_num;         /* name lements */
static pthread_mutex_t dns_mux;                     /* mutex to access atomicly the tbl */


static int DnsDbTblExtend(void)
{
    unsigned long i, len;
    dns_name *new;

    len = dns_name_dim + DNSDB_TBL_ELEMENT_DELTA;

    /* extend memory(copy) */
    new = xrealloc(dns_name_tbl, sizeof(dns_name)*(len));
    if (new == NULL)
        return -1;

    /* initialize new elements */
    for (i=dns_name_dim; i<len; i++) {
        memset(&new[i], 0, sizeof(dns_name));
    }

    dns_name_tbl = new;
    dns_name_dim = len;

    return 0;
}


int DnsDbInit(void)
{
    dns_ipv4_tr = NULL;
    dns_ipv6_tr = NULL;
    dns_name_tbl = NULL;
    dns_ipx_num = 0;
    dns_name_dim = dns_name_num = 0;
    pthread_mutex_init(&dns_mux, NULL);

    DnsDbTblExtend();

    return 0;
}


int DnsDbInset(ftval *name, enum ftype ntype, ftval *ip, enum ftype itype)
{
    dns_ip *new, *prnt, *nxt;
    unsigned long hash, idn;
    unsigned short i, k;
    bool ins, ins_name;

    pthread_mutex_lock(&dns_mux);

    /* insert name */
    if (dns_name_dim == dns_name_num) {
        if (DnsDbTblExtend() != 0) {
            pthread_mutex_unlock(&dns_mux);
            return -1;
        }
    }
    new = DMemMalloc(sizeof(dns_ip));
    if (new == NULL) {
        pthread_mutex_unlock(&dns_mux);
        return -1;
    }

    /* search name
     * many time a DNS request is sended many time  
    */
    ins_name = FALSE;
    k = dns_name_num;
    for (i=0; i!=k; i++) {
        idn = dns_name_num - i - 1;
        if (strcmp(dns_name_tbl[idn].name.str, name->str) == 0) {
            DMemFree(name->str);
            name->str = NULL;
            break;
        }
    }
    if (i == k) {
        /* insert name */
        ins_name = TRUE;
        dns_name_tbl[dns_name_num].name.str = name->str;
        name->str = NULL;
        dns_name_tbl[dns_name_num].ref = 0;
        idn = dns_name_num;
        dns_name_num++;
    }

    /* search ip node */
    memset(new, 0, sizeof(dns_ip));
    hash = FTHash(ip, itype);
    nxt = prnt = NULL;
    switch (itype) {
    case FT_IPv4:
        if (dns_ipv4_tr == NULL) {
            dns_ipv4_tr = new;
        }
        else {
            nxt = dns_ipv4_tr;
        }
        break;

    case FT_IPv6:
        if (dns_ipv6_tr == NULL) {
            dns_ipv6_tr = new;
        }
        else {
            nxt = dns_ipv6_tr;
        }
        break;
        
    default:
        LogPrintf(LV_ERROR, "Dns DB IP type error");
    }

    while (nxt != NULL) {
        prnt = nxt;
        if (hash > prnt->hash)
            nxt = prnt->sup;
        else if (hash < prnt->hash)
            nxt = prnt->inf;
        else
            nxt = NULL;
    }

    /* insert ip node */
    ins = TRUE;
    if (prnt != NULL) {
        if (hash > prnt->hash)
            prnt->sup = new;
        else if (hash < prnt->hash)
            prnt->inf = new;
        else {
            /* check if ip is real equal */
            nxt = prnt;
            while (nxt != NULL) {
                if (FTCmp(ip, &(nxt->ip), itype, FT_OP_EQ, NULL) == 0) {
                    ins = FALSE;
                    break;
                }
                nxt = nxt->eq;
            }
            if (ins == TRUE) {
                new->eq = prnt->eq;
                prnt->eq = new;
            }
        }
    }
    if (ins == TRUE) {
        FTCopy(&(new->ip), ip, itype);
        new->idn = idn;
        new->hash = hash;
        new->tins = time(NULL);
        dns_name_tbl[idn].ref++;
        dns_ipx_num++;
    }
    else {
        if (ins_name) {
            /* update to last name */
            nxt->idn = idn;
            dns_name_tbl[idn].ref++;
        }
        DMemFree(new);
    }
    pthread_mutex_unlock(&dns_mux);

    return 0;
}


int DnsDbSearch(ftval *ip, enum ftype itype, char *buff, int len)
{
    dns_ip *prnt, *nxt;
    unsigned long hash;
    int ret;

    pthread_mutex_lock(&dns_mux);

    /* search ip node */
    hash = FTHash(ip, itype);
    nxt = prnt = NULL;
    switch (itype) {
    case FT_IPv4:
        if (dns_ipv4_tr == NULL) {
            prnt = NULL;
        }
        else {
            nxt = dns_ipv4_tr;
        }
        break;

    case FT_IPv6:
        if (dns_ipv6_tr == NULL) {
            prnt = NULL;
        }
        else {
            nxt = dns_ipv6_tr;
        }
        break;
        
    default:
        LogPrintf(LV_ERROR, "Dns DB IP type error");
    }

    while (nxt != NULL) {
        prnt = nxt;
        if (hash > prnt->hash) 
            nxt = prnt->sup;
        else if (hash < prnt->hash) 
            nxt = prnt->inf;
        else
            nxt = NULL;
    }
    ret = -1;
    if (prnt != NULL) {
        if (hash == prnt->hash) {
            nxt = prnt;
            while (nxt != NULL) {
                if (FTCmp(ip, &(nxt->ip), itype, FT_OP_EQ, NULL) == 0) {
                    FTString(&(dns_name_tbl[nxt->idn].name), FT_STRING, buff);
                    ret = 0;
                    break;
                }
                nxt = nxt->eq;
            }
        }
    }

    pthread_mutex_unlock(&dns_mux);

#if 0
    if (ret == 0) {
        char ips[126];
        FTString(ip, itype, ips);
        LogPrintf(LV_DEBUG, "DNS IP: %s NAME: %s", ips, buff);
    }
#endif

    return ret;
}


int DnsDbStatus(unsigned int *ipn, unsigned int *namen, unsigned long *size)
{
    *ipn = dns_ipx_num;
    *namen = dns_name_num;
    *size = dns_name_dim * sizeof(dns_name) + dns_ipx_num * sizeof(dns_ip);
    /*LogPrintf(LV_DEBUG, "DNS IP: %i NAME: %i", dns_ipx_num, dns_name_num);*/
    
    return 0;
}
