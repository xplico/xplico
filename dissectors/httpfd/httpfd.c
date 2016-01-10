/* httpfd.c
 * HTTP file download dissector
 *
 * $Id: $
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

#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "pei.h"
#include "http.h"
#include "config_file.h"
#include "fileformat.h"

#define  HTTPFD_FILE_PATH          512

static bool insert_http;

static int prot_id;
static int pei_url_id;
static int pei_file_id;
static int pei_range_id;
static int pei_content_type;

static PktDissector HttpPktDis;  /* this functions create the http pei for all http packets */


static int HttpFdRange(const char *range, unsigned long *rbase, unsigned long *rend, unsigned long *rsize)
{
    /* parse */
    if (sscanf(range, "bytes %lu-%lu/%lu", rbase, rend, rsize) == 3) {
        return 0;
    }

    return -1;
}


static packet* HttpFdDissector(packet *pkt)
{
    http_msg *msg;
    packet *httppkt;
    pei *ppei;
    pei_component *cmpn;
    char strbuf[HTTPFD_FILE_PATH];
    char new_path[HTTPFD_FILE_PATH];
    char *orig_file, *file_save, *content_type;
    const char *bnd;
    multipart_f *mpfile;
    multipart_f *nxt;
    bool nend;
    unsigned long rbase, rend, rsize;
    
    ppei = NULL;
    mpfile = nxt = NULL;
    nend = FALSE;
    content_type = NULL;
    
    /* display info */
    msg = (http_msg *)pkt->data;
    LogPrintf(LV_DEBUG, "HTTPfd HttpFdDissector");

#ifdef XPL_CHECK_CODE
    if (msg->serial == 0) {
        LogPrintf(LV_FATAL, "HTTPfd HttpFdDissector serial error");
        exit(-1);
    }
#endif

    /* make the HTTP-PEI also for this message */
    if (insert_http == TRUE) {
        httppkt = HttpMsgPktCpy(pkt);
        if (httppkt != NULL) {
            HttpPktDis(httppkt);
        }
    }

    orig_file = msg->res_body_file;
    /* encoding */
    if (msg->content_encoding[1] != NULL) {
        /* compressed */
        sprintf(new_path, "%s.dec", msg->res_body_file);
        FFormatUncompress(msg->content_encoding[1], msg->res_body_file, new_path);
        remove(msg->res_body_file);
        DMemFree(orig_file);
        orig_file = new_path;
    }
    msg->res_body_file = NULL;

    bnd = HttpMsgBodyBoundary(msg, FALSE);
    if (bnd != NULL) {
        mpfile = FFormatMultipart(orig_file, bnd);
        if (orig_file == new_path)
            remove(orig_file);
        //FFormatMultipartPrint(mpfile);
        nxt = mpfile;
        if (mpfile != NULL && mpfile->content_range != NULL)
            nend = TRUE;
    }
    else {
        rbase = msg->rbase;
        rend = msg->rend;
        rsize = msg->rsize;
        file_save = orig_file;
    }
    do {
        if (nxt != NULL) {
            file_save = nxt->file_path;
            nxt->file_path = NULL;
            HttpFdRange(nxt->content_range, &rbase, &rend, &rsize);
            ppei = NULL;
            if (nxt->content_type)
                content_type = nxt->content_type;
            else
                content_type = NULL;
        }
        /* compose pei (to send to manipulator) */
        PeiNew(&ppei, prot_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, pkt->stk);
        
        /*   url */
        PeiNewComponent(&cmpn, pei_url_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddStingBuff(cmpn, msg->uri);
        PeiAddComponent(ppei, cmpn);
        
        /*   file */
        PeiNewComponent(&cmpn, pei_file_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddFile(cmpn, "Http file", file_save, 0);
        if (msg->error)
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        PeiAddComponent(ppei, cmpn);
        
        /*   range */
        if (rsize != 0) {
            PeiNewComponent(&cmpn, pei_range_id);
            PeiCompCapTime(cmpn, msg->start_cap);
            PeiCompCapEndTime(cmpn, msg->end_cap);
            sprintf(strbuf, "%lu-%lu/%lu", rbase, rend, rsize);
            PeiCompAddStingBuff(cmpn, strbuf);
            PeiAddComponent(ppei, cmpn);
        }
        
        /* content_type */
        if (content_type != NULL) {
            PeiNewComponent(&cmpn, pei_content_type);
            PeiCompCapTime(cmpn, msg->start_cap);
            PeiCompCapEndTime(cmpn, msg->end_cap);
            PeiCompAddStingBuff(cmpn, content_type);
            PeiAddComponent(ppei, cmpn);
        }
        else {
            if (msg->content_type[1] != NULL) {
                PeiNewComponent(&cmpn, pei_content_type);
                PeiCompCapTime(cmpn, msg->start_cap);
                PeiCompCapEndTime(cmpn, msg->end_cap);
                PeiCompAddStingBuff(cmpn, msg->content_type[1]);
                PeiAddComponent(ppei, cmpn);
            }
            else if (msg->content_type[0] != NULL) {
                PeiNewComponent(&cmpn, pei_content_type);
                PeiCompCapTime(cmpn, msg->start_cap);
                PeiCompCapEndTime(cmpn, msg->end_cap);
                PeiCompAddStingBuff(cmpn, msg->content_type[0]);
                PeiAddComponent(ppei, cmpn);
            }
        }
    
        /* insert pei */
        PeiIns(ppei);
        if (nxt != NULL) {
            do {
                nxt = nxt->nxt;
                if (nxt == NULL) {
                    nend = FALSE;
                    break;
                }
            } while (nxt != NULL && nxt->content_range == NULL);
        }
    } while (nend);

    /* remove file */
    HttpMsgRemove(msg);
    if (mpfile != NULL) {
        FFormatMultipartFree(mpfile);
    }

    /* free memory */
    if (orig_file != new_path)
        msg->res_body_file = orig_file;
    HttpMsgFree(msg);
    PktFree(pkt);

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    pei_cmpt peic;
    bool hins;
    
    insert_http = FALSE;
    if (file_cfg != NULL) {
        if (CfgParamBool(file_cfg, "HTTPFD_HTTP_INSERT", &hins) == 0) {
            if (hins) {
                insert_http = TRUE;
            }
        }
    }

    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Http file download", "httpfd");

    /* http dependence */
    dep.name = "http";
    dep.attr = "http.content_range";
    dep.type = FT_STRING;
    dep.op = FT_OP_CNTD;
    dep.val.str =  DMemMalloc(2);
    strcpy(dep.val.str, "-");
    ProtDep(&dep);

    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);

    peic.abbrev = "file";
    peic.desc = "File";
    ProtPeiComponent(&peic);

    peic.abbrev = "range";
    peic.desc = "File range";
    ProtPeiComponent(&peic);

    peic.abbrev = "content_type";
    peic.desc = "Content Type";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(HttpFdDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    int http_id;
    
    prot_id = ProtId("httpfd");

    /* Http pei generator */
    HttpPktDis = NULL;
    http_id = ProtId("http");
    if (http_id != -1) {
        HttpPktDis = ProtPktDefaultDis(http_id);
    }
    else {
        insert_http = FALSE;
    }

    /* pei id */
    pei_url_id = ProtPeiComptId(prot_id, "url");
    pei_file_id = ProtPeiComptId(prot_id, "file");
    pei_range_id = ProtPeiComptId(prot_id, "range");
    pei_content_type = ProtPeiComptId(prot_id, "content_type");

    return 0;
}
