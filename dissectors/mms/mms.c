/* mms.c
 * Routines for MMS Message Encapsulation packet disassembly
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
 *
 */

#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <zlib.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "pei.h"
#include "http.h"
#include "mms.h"
#include "mms_decode.h"

#define MMS_TMP_DIR       "mms"

static char tmp_dir[MMS_BUFFER_SIZE];
/* info id */
static int mms_id;

/* pei id */
static int pei_url_id;
static int pei_from_id;
static int pei_to_id;
static int pei_cc_id;
static int pei_bcc_id;
static int pei_part_id;
static int pei_raw_id;

static volatile unsigned int incr;
static PktDissector HttpPktDis;  /* this functions create the http pei for all http packets */

static int MmsToPei(const mms_message *mms, const http_msg *msg, const pstack_f *stk, const char *mms_raw, unsigned long size)
{
    pei *ppei;
    pei_component *comp;
    short i;

    if (PeiNew(&ppei, mms_id) == -1) {
        return -1;
    }
    PeiCapTime(ppei, msg->start_cap);
    PeiDecodeTime(ppei, time(NULL));
    PeiStackFlow(ppei, stk);
    PeiMarker(ppei, msg->serial);
    if (mms->from != NULL) {
        if (PeiNewComponent(&comp, pei_from_id) == -1) {
            LogPrintf(LV_WARNING, "Pei component of from failed");
        }
        else {
            PeiCompCapTime(comp, msg->start_cap);
            PeiCompCapEndTime(comp, msg->end_cap);
            PeiCompAddStingBuff(comp, mms->from);
            PeiAddComponent(ppei, comp);
        }
    }
    if (mms->to != NULL) {
        if (PeiNewComponent(&comp, pei_to_id) == -1) {
            LogPrintf(LV_WARNING, "Pei component of to failed");
        }
        else {
            PeiCompCapTime(comp, msg->start_cap);
            PeiCompCapEndTime(comp, msg->end_cap);
            PeiCompAddStingBuff(comp, mms->to);
            PeiAddComponent(ppei, comp);
        }
    }
    if (mms->cc != NULL) {
        if (PeiNewComponent(&comp, pei_cc_id) == -1) {
            LogPrintf(LV_WARNING, "Pei component of cc failed");
        }
        else {
            PeiCompCapTime(comp, msg->start_cap);
            PeiCompCapEndTime(comp, msg->end_cap);
            PeiCompAddStingBuff(comp, mms->cc);
            PeiAddComponent(ppei, comp);
        }
    }
    if (mms->bcc != NULL) {
        if (PeiNewComponent(&comp, pei_bcc_id) == -1) {
            LogPrintf(LV_WARNING, "Pei component of bcc failed");
        }
        else {
            PeiCompCapTime(comp, msg->start_cap);
            PeiCompCapEndTime(comp, msg->end_cap);
            PeiCompAddStingBuff(comp, mms->bcc);
            PeiAddComponent(ppei, comp);
        }
    }
    if (mms->part != NULL) {
        for (i=0; i!=mms->nparts; i++) {
            if (PeiNewComponent(&comp, pei_part_id) == -1) {
                LogPrintf(LV_WARNING, "Pei component of part failed");
                break;
            }
            PeiCompCapTime(comp, msg->start_cap);
            PeiCompCapEndTime(comp, msg->end_cap);
            PeiCompAddFile(comp, mms->part[i].name, mms->part[i].path, mms->part[i].size);
            if (mms->part[i].ctype != NULL) {
                PeiCompAddStingBuff(comp, mms->part[i].ctype);
            }
            PeiAddComponent(ppei, comp);
        }
    }
    if (PeiNewComponent(&comp, pei_raw_id) == -1) {
        LogPrintf(LV_WARNING, "Pei component of raw failed");
    }
    else {
        PeiCompCapTime(comp, msg->start_cap);
        PeiCompCapEndTime(comp, msg->end_cap);
        PeiCompAddFile(comp,  "binary.mms", mms_raw, size);
        PeiAddComponent(ppei, comp);
    }

    /* insert pei */
    PeiIns(ppei);

    return 0;
}


static unsigned char *MmsUncompress(const http_msg *msg, unsigned char *raw, ssize_t *len)
{
    bool decode;
    z_stream zbuff;
    unsigned char *buff;
    unsigned char *new_raw;
    ssize_t new_len;
    ssize_t size;
    int ret;
    size_t wsize;

    if (msg->content_encoding[1] != NULL) {
        decode = FALSE;
        memset(&zbuff, 0, sizeof(z_stream));
        if (strcasecmp(msg->content_encoding[1], "gzip") == 0) {
            if (inflateInit2(&zbuff, 15 + 32) == Z_OK) {
                decode = TRUE;
            }
        }
        else if (strcasecmp(msg->content_encoding[1], "deflate") == 0) {
            if (inflateInit2(&zbuff, -15) == Z_OK) {
                decode = TRUE;
            }
        }
        if (decode) {
            zbuff.next_in = raw;
            zbuff.avail_in = *len;
            size = *len * 2;
            buff = xmalloc(size);
            new_raw = xmalloc(*len * 10);
            new_len = 0;
            if (new_raw != NULL) {
                do {
                    zbuff.next_out = buff;
                    zbuff.avail_out = size;
                    ret = inflate(&zbuff, Z_SYNC_FLUSH);
                    if (ret == Z_OK || ret == Z_STREAM_END) {
                        wsize = size - zbuff.avail_out;
                        memcpy(new_raw + new_len, buff, wsize);
                        new_len += wsize;
			if (ret == Z_STREAM_END) {
                            inflateEnd(&zbuff);
                            break;
			}
                    }
                    else {
                        inflateEnd(&zbuff);
                        xfree(buff);
                        xfree(new_raw);
                        return raw;
                    }
                } while (zbuff.avail_in);

                xfree(raw);
                raw = new_raw;
                *len = new_len;
            }
            else {
                LogPrintf(LV_ERROR, "No memory");
            }
            if (buff != NULL) {
                xfree(buff);
            }
        }
    }
    
    return raw;
}


static packet* MmsDissector(packet *pkt)
{
    http_msg *msg;
    char newname[MMS_BUFFER_SIZE];
    ssize_t len;
    mms_message mms;
    unsigned char *mms_raw;
    FILE *fp;

    /* display info */
    msg = (http_msg *)pkt->data;
    LogPrintf(LV_DEBUG, "MMS Dissector");
    
#ifdef XPL_CHECK_CODE
    if (msg->serial == 0) {
        LogPrintf(LV_FATAL, "MMS Dissector serial error");
        exit(-1);
    }
#endif
    if (msg->error != ELMT_ER_NONE) {
        /* http pei generation and insertion */
        HttpPktDis(pkt);
        return NULL;
    }
    
    /* open body file */
    if (msg->req_body_file != NULL && msg->req_body_size != 0) {
        sprintf(newname, "%s/%s/mms_req_%lld_%i.mms", ProtTmpDir(), MMS_TMP_DIR, (long long)time(NULL), incr++);
        rename(msg->req_body_file, newname);
        /* decode */
        MMSInit(&mms);
        fp = fopen(newname, "r");
        if (fp != NULL) {
            mms_raw = xmalloc(msg->req_body_size);
            if (mms_raw != NULL) {
                len = fread(mms_raw, 1, msg->req_body_size, fp);
                mms_raw = MmsUncompress(msg, mms_raw, &len);
                if (len != msg->req_body_size) {
                    /* new file... decompressed */
                    fclose(fp);
                    fp = fopen(newname, "w");
                    fwrite(mms_raw, 1, len, fp);
                }
                MMSDecode(&mms, mms_raw, len, tmp_dir);
                /*MMSPrint(&mms);*/
                MmsToPei(&mms, msg, pkt->stk, newname, msg->req_body_size);
                xfree(mms_raw);
            }
            fclose(fp);
        }
        MMSFree(&mms);
    }
    if (msg->res_body_file != NULL && msg->res_body_size != 0) {
        sprintf(newname, "%s/%s/mms_res_%lld_%i.mms", ProtTmpDir(), MMS_TMP_DIR, (long long)time(NULL), incr++);
        rename(msg->res_body_file, newname);
        /* decode */
        MMSInit(&mms);
        fp = fopen(newname, "r");
        if (fp != NULL) {
            mms_raw = xmalloc(msg->res_body_size);
            if (mms_raw != NULL) {
                len = fread(mms_raw, 1, msg->res_body_size, fp);
                mms_raw = MmsUncompress(msg, mms_raw, &len);
                if (len != msg->req_body_size) {
                    /* new file... decompressed */
                    fclose(fp);
                    fp = fopen(newname, "w");
                    fwrite(mms_raw, 1, len, fp);
                }
                MMSDecode(&mms, mms_raw, len, tmp_dir);
                /*MMSPrint(&mms);*/
                MmsToPei(&mms, msg, pkt->stk, newname, msg->res_body_size);
                xfree(mms_raw);
            }
            fclose(fp);
        }
        MMSFree(&mms);
    }

    /* free memory */
    HttpMsgRemove(msg);
    HttpMsgFree(msg);
    PktFree(pkt);

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("MMS Message Encapsulation", "mms");

    /* http dependence */
    dep.name = "http";
    dep.attr = "http.content_type";
    dep.type = FT_STRING;
    dep.op = FT_OP_CNTD;
    dep.val.str =  DMemMalloc(32);
    strcpy(dep.val.str, "application/vnd.wap.mms-message");
    ProtDep(&dep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);
    peic.abbrev = "from";
    peic.desc = "Source telephon number";
    ProtPeiComponent(&peic);
    peic.abbrev = "to";
    peic.desc = "Destinaton telephon number";
    ProtPeiComponent(&peic);
    peic.abbrev = "cc";
    peic.desc = "Destinaton telephon number (cc)";
    ProtPeiComponent(&peic);
    peic.abbrev = "bcc";
    peic.desc = "Destinaton telephon number (bcc)";
    ProtPeiComponent(&peic);
    peic.abbrev = "part";
    peic.desc = "Content part";
    ProtPeiComponent(&peic);
    peic.abbrev = "raw";
    peic.desc = "Binary raw fromat";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(MmsDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    int http_id;
    
    /* part of file name */
    incr = 0;

    /* Http pei generator */
    HttpPktDis = NULL;
    http_id = ProtId("http");
    if (http_id != -1) {
        HttpPktDis = ProtPktDefaultDis(http_id);
    }

    /* protocols and attributes */
    mms_id = ProtId("mms");

    /* pei id */
    pei_url_id = ProtPeiComptId(mms_id, "url");
    pei_from_id = ProtPeiComptId(mms_id, "from");
    pei_to_id = ProtPeiComptId(mms_id, "to");
    pei_cc_id = ProtPeiComptId(mms_id, "cc");
    pei_bcc_id = ProtPeiComptId(mms_id, "bcc");
    pei_part_id = ProtPeiComptId(mms_id, "part");
    pei_raw_id = ProtPeiComptId(mms_id, "raw");

    /* ipp tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), MMS_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);

    return 0;
}
