/* none.c
 * Basic/example dispatcher module
 *
 * $Id:  $
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

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
 
#include "proto.h"
#include "log.h"
#include "pei.h"
#include "dmemory.h"
#include "gearth.h"

#define DNS_TMP_DIR     "dns"
#define DNS_EN          0

#define HOST_ID_ADD         30
typedef struct {
    int id;                  /* DB id */
    ftval ip;                /* IP address */
    enum ftype type;         /* ip type */
} host_id;

static unsigned long geo_id; /* geo session number, in this case we have only one session */

/* ip v4 id */
static int ip_id;
static int ip_src_id;
static int ip_dst_id;
/* ip v6 id */
static int ipv6_id;
static int ipv6_src_id;
static int ipv6_dst_id;

#if DNS_EN
/* dns */
static int dns_id;
static int pei_dns_host_id;
static int pei_dns_ip_id;
static int pei_dns_cname_id;
static int pei_dns_pkt_id;
static FILE *dns_fp;


static volatile host_id * volatile host;
static volatile unsigned long host_num;
static volatile unsigned long host_dim;
static pthread_mutex_t host_mux;


static int DispHostExt(void)
{
    char *new;

    /* the mutex is in already locked */
    new = xrealloc((void *)host, sizeof(host_id)*(host_dim + HOST_ID_ADD));
    if (new == NULL)
        return -1;
    memset(new+sizeof(host_id)*(host_dim), 0, sizeof(host_id)*HOST_ID_ADD);
    
    host = (host_id *)new;
    host_dim += HOST_ID_ADD;
    
    return 0;
}


static int DispHostSrch(ftval *ip, enum ftype type)
{
    int i, ret;

    pthread_mutex_lock(&host_mux);
    for (i=0; i != host_num; i++) {
        if (host[i].type == type) {
            if (FTCmp(ip, (void *)&(host[i].ip), type, FT_OP_EQ, NULL) == 0) {
                ret = host[i].id;
                pthread_mutex_unlock(&host_mux);
                return ret;
            }
        }
    }
    /* mutex unlock at DispHostIns */

    return -1;
}


static int DispHostIns(ftval *ip, enum ftype type, int db_id)
{
    if (host_num == host_dim) {
        if (DispHostExt() != 0) {
            pthread_mutex_unlock(&host_mux);
            return -1;
        }
    }
    if (db_id != -1) {
        host[host_num].id = db_id;
        FTCopy((void *)&(host[host_num].ip), ip, type);
        host[host_num].type = type;
        host_num++;
    }
    
    pthread_mutex_unlock(&host_mux);

    return 0;
}


static int DispDns(pei *ppei)
{
    pei_component *cmpn;
    char *ip_one, *host, *cname, *id;
    
    ip_one = NULL;
    host = NULL;
    cname = NULL;
    id = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dns_host_id) {
            host = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_ip_id && ip_one == NULL) {
            ip_one = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_cname_id && cname == NULL) {
            cname = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_pkt_id) {
            id = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    if (ip_one != NULL || cname != NULL) {
        if (cname == NULL)
            cname = "";
        if (ip_one == NULL)
            ip_one = "";
        if (id == NULL)
            id = "";
        if (dns_fp != NULL) {
            fprintf(dns_fp, "%s, %lld, %s, %s, %s\n", id, (long long)(ppei->time_cap), host, cname, ip_one);
        }
    }
    
    return 0;
}
#endif


int DispInit(const char *cfg_file)
{
    char kml_file[256];
#if DNS_EN
    char dns_dir_file[256];
#endif

    LogPrintf(LV_DEBUG, "None Dispatcher");
    geo_id = 0;
    sprintf(kml_file, "%s/geomap_%lld.kml", ProtTmpDir(), (long long)(time(NULL)/100)*100);
    GearthNew(geo_id, kml_file, NULL, NULL);

#if DNS_EN
    dns_id = ProtId("dns");
    if (dns_id != -1) {
        pei_dns_host_id =  ProtPeiComptId(dns_id, "host");
        pei_dns_ip_id =  ProtPeiComptId(dns_id, "ip");
        pei_dns_cname_id =  ProtPeiComptId(dns_id, "cname");
        pei_dns_pkt_id = ProtPeiComptId(dns_id, "id");
    }
    /* dns tmp directory */
    sprintf(dns_dir_file, "%s/%s", ProtTmpDir(), DNS_TMP_DIR);
    mkdir(dns_dir_file, 0x01FF);
    sprintf(dns_dir_file, "%s/%s/dns_%lu.txt", ProtTmpDir(), DNS_TMP_DIR, time(NULL));
    dns_fp = fopen(dns_dir_file, "w");
    if (dns_fp != NULL) {
        fprintf(dns_fp, "# ID, timestamp [s], host, cname, ip (first IP)\n\n");
    }
#endif

    ip_id = ProtId("ip");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
    }
    ipv6_id = ProtId("ipv6");
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    }

#if DNS_EN
    pthread_mutex_init(&host_mux, NULL);
    host_num = 0;
    host_dim = 0;
    host = NULL;
#endif

    return 0;
}


int DispEnd(void)
{
    GearthClose(geo_id);
#if DNS_EN
    if (dns_fp != NULL)
        fclose(dns_fp);
#endif
    
    return 0;
}


int DispInsPei(pei *ppei)
{
#if 0
    const pstack_f *frame;
    ftval val, ip;
    unsigned long ips_id, ipd_id;
#endif

    if (ppei != NULL) {
#if 0
        frame = ProtStackSearchProt(ppei->stack, ip_id);
        if (frame) {
            ProtGetAttr(frame, ip_src_id, &ip);
            ips_id = DispHostSrch(&ip, FT_IPv4);
            if (ips_id == -1) {
                DispHostIns(&ip, FT_IPv4, ips_id);
            }
            ProtGetAttr(frame, ip_dst_id, &ip);
            ipd_id = DispHostSrch(&ip, FT_IPv4);
            if (ipd_id == -1) {
                DispHostIns(&ip, FT_IPv4, ipd_id);
            }
        }
        else if (ipv6_id != -1) {
            frame = ProtStackSearchProt(ppei->stack, ipv6_id);
            if (frame) {
                ProtGetAttr(frame, ipv6_src_id, &ip);
                ips_id = DispHostSrch(&ip, FT_IPv6);
                if (ips_id == -1) {
                    DispHostIns(&ip, FT_IPv6, ips_id);
                }
                ProtGetAttr(frame, ipv6_dst_id, &ip);
                ipd_id = DispHostSrch(&ip, FT_IPv6);
                if (ipd_id == -1) {
                    DispHostIns(&ip, FT_IPv6, ipd_id);
                }
            }
        }
#endif
        
#if DNS_EN
        if (ppei->prot_id == dns_id) {
            DispDns(ppei);
        }
        else
#endif
        {
#if 0
            PeiPrint(ppei);
            ProtStackFrmDisp(ppei->stack, TRUE);
#endif
            if (PeiGetReturn(ppei) == FALSE)
                PeiDestroy(ppei);
        }
        //GearthPei(geo_id, ppei);
    }
    
    return 0;
}

