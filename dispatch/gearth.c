/* gearth.c
 * Create, from pei the kml file to rappresent all connetcion with Google Earth
 *
 * $Id:$
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <pthread.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>

#include "pei.h"
#include "gearth.h"
#include "gearth_priv.h"
#include "geoiploc.h"
#include "configs.h"
#include "dmemory.h"
#include "dnsdb.h"
#include "proto.h"
#include "log.h"
#include "config_param.h"


#define GEA_PRIVATE_NET    1 /* enable/disable introduction of provate information to kml file */
#define GEA_SOURCE_INFO    0 /* enable/disable source info */
#define GEA_EN_DNS         0 /* enable/disable dns map */
#define GEA_EN_BASE        1 /* enable/disable unknow connections */

static gea_info *volatile gea_list;
static pthread_mutex_t gea_mux;       /* mutex to access at list */
static time_t gea_update;
const static char *gea_header[] = GEA_KML_HEADER;
const static char *gea_linestyle[] = GEA_KML_LINE_STYLE;
const static char *gea_footer[] = GEA_KML_FOOTER;
#if GEA_PRIVATE_NET
static float lat;
static float lon;
#endif
static bool disabled;

/* ipv4, ipv6, tcp and udp id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int tcp_id;
static int tport_src_id;
static int tport_dst_id;
static int udp_id;
static int uport_src_id;
static int uport_dst_id;
/* pop id */
static int pop_id;
static int pei_pop_user_id;
static int pei_pop_pswd_id;
/* smtp id */
static int smtp_id;
static int pei_smtp_to_id;
static int pei_smtp_from_id;
/* imap id */
static int imap_id;
static int pei_imap_user_id;
static int pei_imap_pswd_id;
/* http id */
static int http_id;
static int pei_http_url_id;
static int pei_http_host_id;
/* sip */
static int sip_id;
static int pei_sip_from_id;
static int pei_sip_to_id;
/* ftp */
static int ftp_id;
static int pei_ftp_url_id;
static int pei_ftp_user_id;
static int pei_ftp_pswd_id;
static int pei_ftp_file_in_id;
static int pei_ftp_file_out_id;
/* ipp */
static int ipp_id;
static int pei_ipp_url_id;
/* pjl */
static int pjl_id;
static int pei_pjl_url_id;
/* tftp */
static int tftp_id;
static int pei_tftp_url_id;
static int pei_tftp_file_in_id;
static int pei_tftp_file_out_id;
/* dns */
static int dns_id;
static int pei_dns_host_id;
/* nntp */
static int nntp_id;
static int pei_nntp_url_id;
/* facebook web chat */
static int fbwc_id;
static int pei_fbwc_user_id;
static int pei_fbwc_friend_id;
/* telnet */
static int telnet_id;
static int pei_telnet_host_id;
/* webmail */
static int webmail_id;
static int pei_webmail_to_id;
static int pei_webmail_from_id;
/* garbage tcp */
static int grb_tcp_id;
/* garbage udp */
static int grb_udp_id;

#if XPL_GEO_IP==1
static int GearthFile(const char *src, const char *dst, bool move)
{
    bool del;
    FILE *fp_src, *fp_dst;
    char *buff;
    int size;

    del = FALSE;
    if (move == TRUE) {
        /* move file */
        if (rename(src, dst) != 0)
            move = FALSE;
        del = TRUE;
    }
    
    if (move == FALSE) {
        /* copy file */
        buff = xmalloc(GEA_BUFFER_SIZE);
        if (buff == NULL) {
            LogPrintf(LV_WARNING, "Not memory to copy Google Earth kml file");
            return -1;
        }
        fp_src = fopen(src, "r");
        if (fp_src == NULL) {
            xfree(buff);
            LogPrintf(LV_WARNING, "Unable to open %s file", src);
            return -1;
        }
        fp_dst = fopen(dst, "w");
        if (fp_dst == NULL) {
            xfree(buff);
            fclose(fp_src);
            LogPrintf(LV_WARNING, "Unable to open %s file", dst);
            return -1;
        }
        do {
            size = fread(buff, 1, GEA_BUFFER_SIZE, fp_src);
            if (size > 0) {
                fwrite(buff, 1, size, fp_dst);
            }
        } while (size > 0);
        
        xfree(buff);
        fclose(fp_src);
        fclose(fp_dst);
    }
    
    if (del == TRUE) {
        /* remove file */
        remove(src);
    }

    return 0;
}


static void GearthPoint(gea_info *gea_p, const gea_coord *a, const char *name, const char *desc,
                        const char *t_start, const char *t_end)
{
    pthread_mutex_lock(&gea_p->file_mux);
    fprintf(gea_p->fp, "    <Placemark>\n");
    if (name != NULL)
        fprintf(gea_p->fp, "        <name><![CDATA[%s]]></name>\n", name);
    if (desc != NULL)
        fprintf(gea_p->fp, "        <description><![CDATA[%s]]></description>\n", desc);
    if (t_start != NULL) {
        fprintf(gea_p->fp, "        <TimeSpan>\n");
        fprintf(gea_p->fp, "            <begin>%s</begin>\n", t_start);
        fprintf(gea_p->fp, "            <end>%s</end>\n", t_end);
        fprintf(gea_p->fp, "        </TimeSpan>\n");
    }
    fprintf(gea_p->fp, "        <Point>\n");
    fprintf(gea_p->fp, "            <coordinates>%f,%f,0</coordinates>\n", a->longitude, a->latitude);
    fprintf(gea_p->fp, "        </Point>\n");
    fprintf(gea_p->fp, "    </Placemark>\n");
    pthread_mutex_unlock(&gea_p->file_mux);
}


static void GearthLine(gea_info *gea_p, const gea_coord *a, const gea_coord *b,
                       const char *name, const char *desc,
                       const char *t_start, const char *t_end, const char *style)
{
    pthread_mutex_lock(&gea_p->file_mux);
    fprintf(gea_p->fp, "    <Placemark>\n");
    if (name != NULL)
        fprintf(gea_p->fp, "        <name><![CDATA[%s]]></name>", name);
    if (desc != NULL)
        fprintf(gea_p->fp, "        <description><![CDATA[%s]]></description>\n", desc);
    if (t_start != NULL) {
        fprintf(gea_p->fp, "        <TimeSpan>\n");
        fprintf(gea_p->fp, "            <begin>%s</begin>\n", t_start);
        fprintf(gea_p->fp, "            <end>%s</end>\n", t_end);
        fprintf(gea_p->fp, "        </TimeSpan>\n");
    }
    fprintf(gea_p->fp, "        <styleUrl>#%s</styleUrl>\n", style);
    fprintf(gea_p->fp, "        <LineString>\n");
    fprintf(gea_p->fp, "            <extrude>1</extrude>\n");
    fprintf(gea_p->fp, "            <tessellate>1</tessellate>\n");
    fprintf(gea_p->fp, "            <coordinates>%f,%f,0 %f,%f,0</coordinates>\n", a->longitude, a->latitude, 
            b->longitude, b->latitude);
    fprintf(gea_p->fp, "        </LineString>\n");
    fprintf(gea_p->fp, "    </Placemark>\n");
    pthread_mutex_unlock(&gea_p->file_mux);
}


static inline int GearthCoord(const pstack_f *stk, gea_coord *a, gea_coord *b, int *ca, int *cb)
{
    const pstack_f *ip;
    ftval val;
    
    /* geo ip coordinates */
    ip = ProtStackSearchProt(stk, ip_id);
    if (ip != NULL) {
        ProtGetAttr(ip, ip_src_id, &val);
        *ca = GeoIPLocIP(&val, FT_IPv4, &a->latitude, &a->longitude, NULL);
        FTFree(&val, FT_IPv4);
#if GEA_PRIVATE_NET
        if (*ca == -1) {
            a->latitude = lat;
            a->longitude = lon;
            *ca = 0;
        }
#endif
        ProtGetAttr(ip, ip_dst_id, &val);
        *cb = GeoIPLocIP(&val, FT_IPv4, &b->latitude, &b->longitude, NULL);
        FTFree(&val, FT_IPv4);
    }
    else {
        ip = ProtStackSearchProt(stk, ipv6_id);
        if (ip != NULL) {
            ProtGetAttr(ip, ipv6_src_id, &val);
            *ca = GeoIPLocIP(&val, FT_IPv6, &a->latitude, &a->longitude, NULL);
            FTFree(&val, FT_IPv6);
            ProtGetAttr(ip, ipv6_dst_id, &val);
            *cb = GeoIPLocIP(&val, FT_IPv6, &b->latitude, &b->longitude, NULL);
            FTFree(&val, FT_IPv6);
        }
        else {
            return -1;
        }
    }

    return 0;
}


static inline int GearthTime(const time_t *timep, char *strtime)
{
    struct tm tmp;

    strtime[0] = '\0';
    if (localtime_r(timep, &tmp) != NULL)
        strftime(strtime, GEA_STRTIME_SIZE, "%Y-%m-%dT%H:%M:%SZ", &tmp);
    
    return 0;
}


static int GearthPop(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, NULL, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, "POP", NULL, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, "POP", NULL, time_s, time_e, GEA_KML_LSTYLE_EMAIL);
    }

    return 0;
}


static int GearthSmtp(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, NULL, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, "SMTP", NULL, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, "SMTP", NULL, time_s, time_e, GEA_KML_LSTYLE_EMAIL);
    }

    return 0;
}


static int GearthImap(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, NULL, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, "IMAP", NULL, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, "IMAP", NULL, time_s, time_e, GEA_KML_LSTYLE_EMAIL);
    }

    return 0;
}


static int GearthHttp(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    pei_component *cmpn;
    char url[GEA_URL_SIZE];
    char *host, *host_t, *urlp;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }
    host = host_t = urlp = NULL;

    url[0] = '\0';
    
    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* url info */
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_http_url_id) {
            if (host_t != NULL) {
                snprintf(url, GEA_URL_SIZE, "http://%s%s", host_t, cmpn->strbuf);
                break;
            }
            else {
                urlp = cmpn->strbuf;
            }
        }
        else if (cmpn->eid == pei_http_host_id) {
            host = cmpn->strbuf;
            if (urlp != NULL) {
                snprintf(url, GEA_URL_SIZE, "http://%s%s", cmpn->strbuf, urlp);
                break;
            }
            else {
                host_t = cmpn->strbuf;
            }
        }
        
        cmpn = cmpn->next;
    }
    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, url, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, host, url, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, host, url, time_s, time_e, GEA_KML_LSTYLE_HTTP);
    }

    return 0;
}


static int GearthSip(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, NULL, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, "SIP", NULL, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, "SIP", NULL, time_s, time_e, GEA_KML_LSTYLE_SIP);
    }

    return 0;
}


static int GearthFtp(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    pei_component *cmpn;
    const char *url, *descr;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        PeiPrint(ppei);
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* url info */
    url = "FTP-DATA";
    descr = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ftp_url_id) {
            url = cmpn->strbuf;
            break;
        }
        else if (cmpn->eid == pei_ftp_file_in_id || cmpn->eid == pei_ftp_file_out_id) {
            descr = cmpn->name;
            break;
        }
        cmpn = cmpn->next;
    }

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, url, descr, time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, url, descr, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, url, descr, time_s, time_e, GEA_KML_LSTYLE_FTP);
    }

    return 0;
}


static int GearthTftp(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    pei_component *cmpn;
    const char *url, *descr;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        PeiPrint(ppei);
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* url info */
    url = "TFTP file";
    descr = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ftp_url_id) {
            url = cmpn->strbuf;
            break;
        }
        else if (cmpn->eid == pei_tftp_file_in_id || cmpn->eid == pei_tftp_file_out_id) {
            descr = cmpn->name;
            break;
        }
        cmpn = cmpn->next;
    }

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, url, descr, time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, url, descr, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, url, descr, time_s, time_e, GEA_KML_LSTYLE_TFTP);
    }

    return 0;
}


#if GEA_EN_DNS
static int GearthDns(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    pei_component *cmpn;
    const char *host, *descr;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        PeiPrint(ppei);
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* url info */
    descr = "DNS message";
    host = "...";
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dns_host_id) {
            host = cmpn->strbuf;
            break;
        }
        cmpn = cmpn->next;
    }

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, host, descr, time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, host, descr, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, host, descr, time_s, time_e, GEA_KML_LSTYLE_DNS);
    }

    return 0;
}
#endif /* GEA_EN_DNS */


static int GearthNntp(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    pei_component *cmpn;
    char *url;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }
    url = NULL;
    
    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* url info */
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_nntp_url_id) {
            url = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, url, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, url, url, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, url, url, time_s, time_e, GEA_KML_LSTYLE_NNTP);
    }

    return 0;
}


static int GearthFbwchat(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    pei_component *cmpn;
    char *user, *friend;
    char desc[GEA_URL_SIZE];

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }
    
    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* chat info */
    user = friend = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_fbwc_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_friend_id) {
            friend = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    if (user == NULL || friend == NULL)
        return 0;
    
    /* kml */
    sprintf(desc, "Facebook chat: %s <--> %s", user, friend);
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, user, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, friend, desc, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, friend, desc, time_s, time_e, GEA_KML_LSTYLE_FBCHAT);
    }

    return 0;
}


static int GearthTelnet(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    pei_component *cmpn;
    char *host;
    char desc[GEA_URL_SIZE];

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }
    
    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* host info */
    host = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_telnet_host_id) {
            host = cmpn->strbuf;
            break;
        }
        
        cmpn = cmpn->next;
    }
    if (host == NULL)
        return 0;
    
    /* kml */
    sprintf(desc, "Telnet host: %s", host);
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, user, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, host, desc, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, host, desc, time_s, time_e, GEA_KML_LSTYLE_TELNET);
    }

    return 0;
}


static int GearthWebMail(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, NULL, "Source", time_s, time_e);
    }
#endif
    if (cb != -1) {
        GearthPoint(gea_p, &b, "WebMail", NULL, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, "WebMail", NULL, time_s, time_e, GEA_KML_LSTYLE_EMAIL);
    }

    return 0;
}


static int GearthNone(gea_info *gea_p, const pei *ppei)
{
    return 0;
}


#if GEA_EN_BASE
static int GearthBase(gea_info *gea_p, const pei *ppei)
{
    gea_coord a, b;
    int ca, cb;
    char time_s[GEA_STRTIME_SIZE], time_e[GEA_STRTIME_SIZE];
    time_t et;
    const char *pname;

    /* geo ip coordinates */
    if (GearthCoord(ppei->stack, &a, &b, &ca, &cb) == -1) {
        return -1;
    }

    /* time */
    et = ppei->time_cap + GEA_MIN_DTIME;
    GearthTime(&ppei->time_cap, time_s);
    GearthTime(&et, time_e);

    /* kml */
#if GEA_SOURCE_INFO
    if (ca != -1) {
        GearthPoint(gea_p, &a, "Source", NULL, time_s, time_e);
    }
#endif
    if (grb_tcp_id == ppei->prot_id || grb_udp_id == ppei->prot_id) {
        pname = "Unknown";
    }
    else {
        pname = ProtGetName(ppei->prot_id);
    }
    if (cb != -1) {
        GearthPoint(gea_p, &b, pname, NULL, time_s, time_e);
    }
    if ((ca + cb) == 0) {
        GearthLine(gea_p, &a, &b, pname, NULL, time_s, time_e, GEA_KML_LSTYLE_TCP);
    }
    
    return 0;
}
#endif /* GEA_EN_BASE */
#endif /* XPL_GEO_IP */


int GearthNew(unsigned long id, const char *kml_path, const char *kml_tmp, const char *sem_name)
{
#if XPL_GEO_IP==1
    gea_info *ngea;
    int i, sem_ret;
    struct stat file_stat;

    if (kml_path == NULL) {
        return -1;
    }
    ngea = xmalloc(sizeof(gea_info));
    if (ngea == NULL) {
        return -1;
    }
    
    memset(ngea, 0, sizeof(gea_info));
    ngea->id = id;
    /* end file */
    strncpy(ngea->kml_file, kml_path, GEA_PATH_SIZE);
    /* temporary file */
    if (kml_tmp != NULL) {
        strncpy(ngea->tmp_file, kml_tmp, GEA_PATH_SIZE);
    }
    else {
        snprintf(ngea->tmp_file, GEA_PATH_SIZE, "%s_tmp", kml_path);
        ngea->tmp_file[GEA_PATH_SIZE - 1] = '\0';
    }
    /* semaphore to access files (xplico & manipulators) */
    if (sem_name != NULL) {
        strncpy(ngea->sem_name, sem_name, GEA_PATH_SIZE);
        ngea->sem = sem_open(sem_name , O_CREAT, O_RDWR | S_IRWXU | S_IRWXG, 1);
        if (ngea->sem == SEM_FAILED) {
            perror("");
            exit(-1);
            xfree(ngea);
            return -1;
        }
        do {
            sem_ret = sem_wait(ngea->sem);
        } while (sem_ret == -1 && errno == EINTR);
        ngea->fp = NULL;
        if (stat(ngea->tmp_file, &file_stat) != 0) {
            ngea->fp = fopen(ngea->tmp_file, "w");
        }
        else {
            sem_post(ngea->sem);
        }
    }
    else {
        ngea->fp = fopen(ngea->tmp_file, "w");
        if (ngea->fp == NULL) {
            xfree(ngea);
            return -1;
        }
    }
    pthread_mutex_init(&(ngea->file_mux), NULL);
    pthread_mutex_lock(&gea_mux);
    ngea->nxt = gea_list;
    gea_list = ngea;
    pthread_mutex_unlock(&gea_mux);

    if (ngea->fp != NULL) {
        /* kml header */
        i = 0;
        while (gea_header[i] != NULL) {
            if (strstr(gea_header[i], "longitude")) {
                fprintf(ngea->fp, gea_header[i++], lon);
                fprintf(ngea->fp, "\n");
            }
            else if (strstr(gea_header[i], "latitude")) {
                fprintf(ngea->fp, gea_header[i++], lat);
                fprintf(ngea->fp, "\n");
            }
            else
                fprintf(ngea->fp, "%s\n", gea_header[i++]);
        }
        
        /* line style */
        i = 0;
        while (gea_linestyle[i] != NULL) {
            fprintf(ngea->fp, "%s\n", gea_linestyle[i++]);
        }
        if (sem_name != NULL) {
            fclose(ngea->fp);
            ngea->fp = NULL;
            sem_post(ngea->sem);
        }
    }
#endif

    return 0;
}


int GearthPei(unsigned long id, const pei *ppei)
{
#if XPL_GEO_IP==1
    gea_info *gea_p;
    int ret, i;
    FILE *fp;
    int sem_ret;
    struct stat file_stat;

    if (ppei == NULL || ppei->ret == TRUE || disabled) {
        return 0;
    }

    /* find index */
    pthread_mutex_lock(&gea_mux);
    gea_p = gea_list;
    while (gea_p != NULL) {
        if (gea_p->id == id) {
            /* kml file found */
            break;
        }
        gea_p = gea_p->nxt;
    }
    if (gea_p == NULL) {
        pthread_mutex_unlock(&gea_mux);
        LogPrintf(LV_ERROR, "Kml file does not exist");
        return -1;
    }
    pthread_mutex_unlock(&gea_mux);

    /* sem */
    if (gea_p->sem != NULL) {
        do {
            sem_ret = sem_wait(gea_p->sem);
        } while (sem_ret == -1 && errno == EINTR);
        gea_p->fp = NULL;
        if (stat(gea_p->tmp_file, &file_stat) == 0)
            gea_p->fp = fopen(gea_p->tmp_file, "a");
        if (gea_p->fp == NULL) {
            sem_post(gea_p->sem);
            return -1;
        }
    }

    /* kml info */
    if (ppei->prot_id == pop_id) {
        ret = GearthPop(gea_p, ppei);
    }
    else if (ppei->prot_id == smtp_id) {
        ret = GearthSmtp(gea_p, ppei);
    }
    else if (ppei->prot_id == imap_id) {
        ret = GearthImap(gea_p, ppei);
    }
    else if (ppei->prot_id == http_id) {
        ret = GearthHttp(gea_p, ppei);
    }
    else if (ppei->prot_id == sip_id) {
        ret = GearthSip(gea_p, ppei);
    }
    else if (ppei->prot_id == ftp_id) {
        ret = GearthFtp(gea_p, ppei);
    }
    else if (ppei->prot_id == ipp_id) {
        ret = GearthNone(gea_p, ppei);
    }
    else if (ppei->prot_id == pjl_id) {
        ret = GearthNone(gea_p, ppei);
    }
    else if (ppei->prot_id == tftp_id) {
        ret = GearthTftp(gea_p, ppei);
    }
    else if (ppei->prot_id == dns_id) {
#if GEA_EN_DNS
        ret = GearthDns(gea_p, ppei);
#else
        ret = GearthNone(gea_p, ppei);
#endif
    }
    else if (ppei->prot_id == nntp_id) {
        ret = GearthNntp(gea_p, ppei);
    }
    else if (ppei->prot_id == fbwc_id) {
        ret = GearthFbwchat(gea_p, ppei);
    }
    else if (ppei->prot_id == telnet_id) {
        ret = GearthTelnet(gea_p, ppei);
    }
    else if (ppei->prot_id == webmail_id) {
        ret = GearthWebMail(gea_p, ppei);
    }
#if GEA_EN_BASE
    else {
        ret = GearthBase(gea_p, ppei);
    }
#endif
    /* every GEA_UPDATE_KML sec there are an update of kml file */
    if (gea_update < time(NULL)) {
        pthread_mutex_lock(&gea_p->file_mux);
        fflush(NULL);
        GearthFile(gea_p->tmp_file, gea_p->kml_file, FALSE);
        pthread_mutex_unlock(&gea_p->file_mux);
        fp = fopen(gea_p->kml_file, "a");
        if (fp != NULL) {
            i = 0;
            while (gea_footer[i] != NULL) {
                fprintf(fp, "%s\n", gea_footer[i++]);
            }
            fclose(fp);
        }
        gea_update = time(NULL) + GEA_UPDATE_KML;
    }
    if (gea_p->sem != NULL) {
        fclose(gea_p->fp);
        gea_p->fp = NULL;
        sem_post(gea_p->sem);
    }
#endif
    return ret;
}


int GearthClose(unsigned long id)
{
#if XPL_GEO_IP==1
    gea_info *gea_p, *pre_gea;
    int i;
    int sem_ret;
    struct stat file_stat;

    /* find index */
    pre_gea = NULL;
    pthread_mutex_lock(&gea_mux);
    gea_p = gea_list;
    while (gea_p != NULL) {
        if (gea_p->id == id) {
            /* kml file found */
            break;
        }
        pre_gea = gea_p;
        gea_p = gea_p->nxt;
    }
    if (gea_p == NULL) {
        pthread_mutex_unlock(&gea_mux);
        LogPrintf(LV_ERROR, "Kml file does not exist");
        return -1;
    }
    /* remove gea from list */
    if (pre_gea == NULL) {
        gea_list = gea_p->nxt;
    }
    else {
        pre_gea->nxt = gea_p->nxt;
    }
    gea_p->nxt = NULL;
    pthread_mutex_unlock(&gea_mux);

    /* close and move file */
    if (gea_p->sem != NULL) {
        do {
            sem_ret = sem_wait(gea_p->sem);
        } while (sem_ret == -1 && errno == EINTR);
        gea_p->fp = NULL;
        GearthFile(gea_p->tmp_file, gea_p->kml_file, FALSE);
        if (stat(gea_p->kml_file, &file_stat) == 0) {
            gea_p->fp = fopen(gea_p->kml_file, "a");
        }
    }
    if (gea_p->fp != NULL) {
        i = 0;
        while (gea_footer[i] != NULL) {
            fprintf(gea_p->fp, "%s\n", gea_footer[i++]);
        }
        fclose(gea_p->fp);
    }
    if (gea_p->sem != NULL) {
        sem_post(gea_p->sem);
        sem_close(gea_p->sem);
        sem_unlink(gea_p->sem_name);
    }
    pthread_mutex_destroy(&(gea_p->file_mux));

    /* free memory */
    xfree(gea_p);
#endif

    return 0;
}


int GearthEnd(void)
{
#if XPL_GEO_IP==1
    unsigned long id;

    pthread_mutex_lock(&gea_mux); /* it is not necessary */
    while (gea_list != NULL) {
        id = gea_list->id;
        pthread_mutex_unlock(&gea_mux); /* it is not necessary */
        GearthClose(id);
        pthread_mutex_lock(&gea_mux); /* it is not necessary */
    }
    pthread_mutex_unlock(&gea_mux); /* it is not necessary */
#endif

    return 0;
}


int GearthInit(const char *file_cfg)
{
#if XPL_GEO_IP == 1
    char gea_dir[256];
#if GEA_PRIVATE_NET
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char *param;
    float val;
    int res;
    FILE *fp;
#endif

    disabled = FALSE;

#if GEA_PRIVATE_NET
    lat = 0;
    lon = 0;
    /* read from cfg file latitude and longitude */
    fp = fopen(file_cfg, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = strstr(buffer, CFG_PAR_GEO_LAT);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_GEO_LAT"=%f %s", &val, bufcpy);
                if (res > 0) {
                    lat = val;
                }
            }
            param = strstr(buffer, CFG_PAR_GEO_LONG);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_GEO_LONG"=%f %s", &val, bufcpy);
                if (res > 0) {
                    lon = val;
                }
            }
        }
    }
    fclose(fp);
    if (lat == 0 && lon == 0)
        disabled = TRUE;
#endif

    /* gea tmp directory */
    sprintf(gea_dir, "%s/%s", ProtTmpDir(), GEA_TMP_DIR);
    mkdir(gea_dir, 0x01FF);
    gea_update = time(NULL);

    gea_list = NULL;
    pthread_mutex_init(&gea_mux, NULL);

    /* ip, ipv6, tcp and udp */
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    tcp_id = ProtId("tcp");
    tport_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    tport_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    udp_id = ProtId("udp");
    uport_dst_id = ProtAttrId(udp_id, "udp.dstport");
    uport_src_id = ProtAttrId(udp_id, "udp.srcport");

    /* pei id */
    pop_id = ProtId("pop");
    if (pop_id != -1) {
        pei_pop_user_id = ProtPeiComptId(pop_id, "user");
        pei_pop_pswd_id = ProtPeiComptId(pop_id, "password");
    }

    smtp_id = ProtId("smtp");
    if (smtp_id != -1) {
        pei_smtp_to_id = ProtPeiComptId(smtp_id, "to");
        pei_smtp_from_id = ProtPeiComptId(smtp_id, "from");
    }

    imap_id = ProtId("imap");
    if (imap_id != -1) {
        pei_imap_user_id = ProtPeiComptId(imap_id, "user");
        pei_imap_pswd_id = ProtPeiComptId(imap_id, "password");
    }
    
    http_id = ProtId("http");
    if (http_id != -1) {
        pei_http_url_id = ProtPeiComptId(http_id, "url");
        pei_http_host_id = ProtPeiComptId(http_id, "host");
    }

    sip_id = ProtId("sip");
    if (sip_id != -1) {
        pei_sip_from_id = ProtPeiComptId(sip_id, "from");
        pei_sip_to_id = ProtPeiComptId(sip_id, "to");
    }

    ftp_id = ProtId("ftp");
    if (ftp_id != -1) {
        pei_ftp_url_id = ProtPeiComptId(ftp_id, "url");
        pei_ftp_user_id = ProtPeiComptId(ftp_id, "user");
        pei_ftp_pswd_id = ProtPeiComptId(ftp_id, "password");
        pei_ftp_file_in_id = ProtPeiComptId(ftp_id, "file_in");
        pei_ftp_file_out_id = ProtPeiComptId(ftp_id, "file_out");
    }

    ipp_id = ProtId("ipp");
    if (ipp_id != -1) {
        pei_ipp_url_id = ProtPeiComptId(ipp_id, "url");
    }

    pjl_id = ProtId("pjl");
    if (pjl_id != -1) {
        pei_pjl_url_id = ProtPeiComptId(pjl_id, "url");
    }

    tftp_id = ProtId("tftp");
    if (ftp_id != -1) {
        pei_tftp_url_id = ProtPeiComptId(tftp_id, "url");
        pei_tftp_file_in_id = ProtPeiComptId(tftp_id, "file_in");
        pei_tftp_file_out_id = ProtPeiComptId(tftp_id, "file_out");
    }

    dns_id = ProtId("dns");
    if (dns_id != -1) {
        pei_dns_host_id =  ProtPeiComptId(dns_id, "host");
    }

    nntp_id = ProtId("nntp");
    if (nntp_id != -1) {
        pei_nntp_url_id =  ProtPeiComptId(nntp_id, "url");
    }

    fbwc_id = ProtId("fbwchat");
    if (fbwc_id != -1) {
        pei_fbwc_user_id = ProtPeiComptId(fbwc_id, "user");
        pei_fbwc_friend_id = ProtPeiComptId(fbwc_id, "friend");
    }
    
    telnet_id = ProtId("telnet");
    if (telnet_id != -1) {
        pei_telnet_host_id = ProtPeiComptId(telnet_id, "host");
    }

    webmail_id = ProtId("webmail");
    if (webmail_id != -1) {
        pei_webmail_to_id = ProtPeiComptId(webmail_id, "to");
        pei_webmail_from_id = ProtPeiComptId(webmail_id, "from");
    }

    grb_tcp_id = ProtId("tcp-grb");
    
    grb_udp_id = ProtId("udp-grb");
#endif

    return 0;
}

