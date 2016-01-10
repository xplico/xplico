/* pcap2wav.c
 * Xplico System dispatcher for pcap2wav
 *
 * $Id:  $
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>

#include "proto.h"
#include "log.h"
#include "pei.h"
#include "dmemory.h"
#include "pcap2wav.h"
#include "dnsdb.h"
#include "gearth.h"
#include "fileformat.h"
#include "config_param.h"


/* ip v4 id */
static int ip_id;
static int ip_src_id;
static int ip_dst_id;
/* ip v6 id */
static int ipv6_id;
static int ipv6_src_id;
static int ipv6_dst_id;
/* rtp voip */
static int rtp_id;
static int pei_rtp_from;
static int pei_rtp_to;
static int pei_rtp_audio_from;
static int pei_rtp_audio_to;
static int pei_rtp_audio_mix;
static int pei_rtp_duration;

static time_t tstart;
static unsigned long nrtp;

/* decode dir */
static char xdecode[CFG_LINE_MAX_SIZE];


static int DispRtp(pei *ppei)
{
    pei_component *cmpn;
    char new_path[XCLI_STR_DIM];
    char *from, *to, *name;
    bool cmt, cmnt;

    from = to = NULL;
    cmt = cmnt = FALSE;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_rtp_audio_mix) {
            remove(cmpn->file_path);
        }
        else if (cmpn->eid == pei_rtp_audio_from) {
            if (cmt)
                remove(cmpn->file_path);
            else
                from = cmpn->file_path;
            cmt = TRUE;
        }
        else if (cmpn->eid == pei_rtp_audio_to) {
            if (cmnt)
                remove(cmpn->file_path);
            else
                to = cmpn->file_path;
            cmnt = TRUE;
        }
        
        cmpn = cmpn->next;
    }

    /* move file */
    if (from != NULL || to != NULL) {
        /* new path */
        if (from != NULL) {
            name = strrchr(from, '/');
            name++;
            sprintf(new_path, "%s/%s", xdecode, name);
            rename(from, new_path);
        }
        if (to != NULL) {
            name = strrchr(to, '/');
            name++;
            sprintf(new_path, "%s/%s", xdecode, name);
            rename(to, new_path);
        }
    }
    
    return 0;
}



int DispInit(const char *cfg_file)
{
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char *param;
    FILE *fp;
    int res, i;

    LogPrintf(LV_DEBUG, "PCAP2WAV Dispatcher");

    nrtp = 0;

    /* read configuration file */
    fp = fopen(cfg_file, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }
    res = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = strstr(buffer, CFG_PAR_XDECODE);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_XDECODE"=%s %s", xdecode, bufcpy);
                if (res > 0) {
                    break;
                }
            }
        }
    }
    fclose(fp);
    if (!res) {
        strcpy(xdecode, XCLI_BASE_DIR);
    }
    else {
        i = 0;
        while (xdecode[i] != '\0' && xdecode[i] != '\0')
            i++;
        xdecode[i] = '\0';
    }
    
    tstart = time(NULL);
    
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

    /* pei id */
    rtp_id = ProtId("rtp");
    if (rtp_id != -1) {
        pei_rtp_from = ProtPeiComptId(rtp_id, "from");
        pei_rtp_to = ProtPeiComptId(rtp_id, "to");
        pei_rtp_audio_from = ProtPeiComptId(rtp_id, "audio_from");
        pei_rtp_audio_to = ProtPeiComptId(rtp_id, "audio_to");
        pei_rtp_audio_mix = ProtPeiComptId(rtp_id, "audio_mix");
        pei_rtp_duration = ProtPeiComptId(rtp_id, "duration");
    }
    
    /* directory for repository */
    mkdir(xdecode, 0x01FF);

    return 0;
}


int DispEnd()
{
    /* PEI protcols statistics (for debug) */
#if 1
    printf("PEIs:\n");
    printf("\trtp: %lu\n", nrtp);
#endif

    return 0;
}


int DispInsPei(pei *ppei)
{
    int ret;
    
    if (ppei != NULL) {
        /* pei */
        if (ppei->prot_id == rtp_id) {
            PeiPrint(ppei);
            if (ppei->ret == FALSE)
                nrtp++;
            ret = DispRtp(ppei);
        }
    }
    
    return 0;
}

