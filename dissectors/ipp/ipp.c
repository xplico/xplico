/* ipp.c
 * Routines for IPP packet disassembly
 * RFC2911
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on: packet-ipp.c of Wireshark
 *   Copyright 1998 Gerald Combs
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
 *
 *
 * This module use GhostPCL:  http://www.artifex.com/downloads/
 *
 *
 */

#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "pei.h"
#include "http.h"
#include "ipp.h"

#define IPP_TMP_DIR       "ipp"

/* info id */
static int prot_id;

/* pei id */
static int pei_url_id;
static int pei_pdffile_id;
static int pei_pclfile_id;


static volatile unsigned int incr;
static char pcl6_path[] = "/opt/xplico/bin/pcl6";

static unsigned int ParseAttributes(unsigned char *buff, unsigned int offset, ssize_t len)
{
    unsigned char tag;
    unsigned int name_length, value_length;

    while (offset < len) {
        tag = buff[offset];
        if (TAG_TYPE(tag) == TAG_TYPE_DELIMITER) {
                
            offset++;
            if (tag == TAG_END_OF_ATTRIBUTES) {
                /*
                 * No more attributes.
                 */
                break;
            }
        } else {
            /*
             * Value tag - get the name length.
             */
            name_length = ntohs(*((unsigned short *)(buff + offset + 1)));
                
            /*
             * OK, get the value length.
             */
            value_length = ntohs(*((unsigned short *)(buff + offset + 1 + 2 + name_length)));

                
            switch (TAG_TYPE(tag)) {
            case TAG_TYPE_INTEGER:
                break;
                    
            case TAG_TYPE_OCTETSTRING:
                break;
                    
            case TAG_TYPE_CHARSTRING:
                break;
            }
            offset += 1 + 2 + name_length + 2 + value_length;
        }
    }
    if (offset >= len) {
        LogPrintf(LV_ERROR, "Buffer to small");
    }

    return offset;
}


static packet* IppDissector(packet *pkt)
{
    http_msg *msg;
    pei *ppei;
    pei_component *cmpn;
    int ind, fd;
    unsigned char buff[IPP_BUFFER_SIZE];
    char *pcl_file, *pdf_file;
    char cmd[IPP_FILENAME_PATH_SIZE*2];
    ssize_t len;
    unsigned int offset;
    ipp_ver ver;
    FILE *pcl;
    struct stat fst;

    ppei = NULL;

    /* display info */
    msg = (http_msg *)pkt->data;
    LogPrintf(LV_DEBUG, "IPP Dissector");
    
#ifdef XPL_CHECK_CODE
    if (msg->serial == 0) {
        LogPrintf(LV_FATAL, "IPP Dissector serial error");
        exit(-1);
    }
#endif

    /* check if post and if PCL file */
    if (msg->mtd != HTTP_MT_POST || msg->req_body_size == 0) {
        /* free memory */
        HttpMsgRemove(msg);
        HttpMsgFree(msg);
        PktFree(pkt);
        
        return NULL;
    }
    
    /* open body file */
    fd = open(msg->req_body_file, O_RDONLY);
    if (fd == 0) {
        LogPrintf(LV_ERROR, "Can't open file:%s", msg->req_body_file);
        /* free memory */
        HttpMsgRemove(msg);
        HttpMsgFree(msg);
        PktFree(pkt);
        
        return NULL;
    }
    len = read(fd, buff, IPP_BUFFER_SIZE);
    offset = 0;

    /* IPP version */
    if (buff[0] == 1) {
        if (buff[1] == 0) {
            ver = IPP_1_0;
        }
        else if (buff[1] == 1) {
            ver = IPP_1_1;
        }
        else {
            LogPrintf(LV_WARNING, "Unknow version: %u.%u", buff[0], buff[1]);
            close(fd);
            /* free memory */
            HttpMsgRemove(msg);
            HttpMsgFree(msg);
            PktFree(pkt);
            
            return NULL;
        }
    }
    else {
        LogPrintf(LV_WARNING, "Unknow version: %u.%u", buff[0], buff[1]);
        close(fd);
        /* free memory */
        HttpMsgRemove(msg);
        HttpMsgFree(msg);
        PktFree(pkt);
        
        return NULL;
    }
    offset += 2;
    /* check if print job */
    if (ntohs(*((unsigned short *)(buff+offset))) != PRINT_JOB) {
        close(fd);
        /* free memory */
        HttpMsgRemove(msg);
        HttpMsgFree(msg);
        PktFree(pkt);
        
        return NULL;
    }
    offset += 2;
    offset += 4; /* skeep request id */
#warning "to improve"
    offset = ParseAttributes(buff, offset, len); /* i hope that IPP_BUFFER_SIZE is alwayse correct */

    /* create PCL file */
    pcl_file = DMemMalloc(IPP_FILENAME_PATH_SIZE);
    pdf_file = DMemMalloc(IPP_FILENAME_PATH_SIZE);
    sprintf(pcl_file, "%s/%s/ipp_%lld_%p_%i.pcl", ProtTmpDir(), IPP_TMP_DIR,
            (long long)time(NULL), msg, incr);
    sprintf(pdf_file, "%s/%s/ipp_%lld_%p_%i.pdf", ProtTmpDir(), IPP_TMP_DIR,
            (long long)time(NULL), msg, incr);
    incr++;
               
    pcl = fopen(pcl_file, "w+");
    fwrite(buff+offset, 1, len-offset, pcl);
    len = read(fd, buff, IPP_BUFFER_SIZE);
    while (len != 0) {
        fwrite(buff, 1, len, pcl);
        len = read(fd, buff, IPP_BUFFER_SIZE);
    }
    fclose(pcl);
    close(fd);

    /* pdf conversion */
    sprintf(cmd, "%s -dNOPAUSE -sDEVICE=pdfwrite -sOutputFile=%s %s", pcl6_path, pdf_file, pcl_file);
    system(cmd);
    fst.st_size = 0;
    stat(pdf_file, &fst);

    /* compose pei */
    ppei = DMemMalloc(sizeof(pei));
    PeiInit(ppei);
    ppei->prot_id = prot_id;
    ppei->serial = pkt->serial;
    ppei->time_cap = pkt->cap_sec;
    ppei->stack = ProtCopyFrame(pkt->stk, TRUE);
    /*   url */
    ind = 0;
    cmpn = DMemMalloc(sizeof(pei_component));
    memset(cmpn, 0, sizeof(pei_component));
    cmpn->eid = pei_url_id;
    cmpn->id = ind;
    cmpn->time_cap = msg->start_cap;
    cmpn->time_cap_end = msg->end_cap;
    cmpn->strbuf = msg->uri;
    msg->uri = NULL;
    ppei->components = cmpn;
    /*   pdf */
    ind++;
    cmpn->next = DMemMalloc(sizeof(pei_component));
    cmpn = cmpn->next;
    memset(cmpn, 0, sizeof(pei_component));
    cmpn->eid = pei_pdffile_id;
    cmpn->id = ind;
    cmpn->time_cap = msg->start_cap;
    cmpn->time_cap_end = msg->end_cap;
    cmpn->file_path = pdf_file;
    cmpn->file_size = fst.st_size;
    if (msg->error)
        cmpn->err = ELMT_ER_PARTIAL;
    /*   pcl */
    ind++;
    cmpn->next = DMemMalloc(sizeof(pei_component));
    cmpn = cmpn->next;
    memset(cmpn, 0, sizeof(pei_component));
    cmpn->eid = pei_pclfile_id;
    cmpn->id = ind;
    cmpn->time_cap = msg->start_cap;
    cmpn->time_cap_end = msg->end_cap;
    cmpn->file_path = pcl_file;
    cmpn->file_size = msg->req_body_size - offset;
    if (msg->error)
        cmpn->err = ELMT_ER_PARTIAL;

    /* free memory */
    HttpMsgRemove(msg);
    HttpMsgFree(msg);
    PktFree(pkt);
    
    /* insert pei */
    PeiIns(ppei);

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Internet Printing Protocol", "ipp");

    /* http dependence */
    dep.name = "http";
    dep.attr = "http.content_type";
    dep.type = FT_STRING;
    dep.op = FT_OP_CNTD;
    dep.val.str =  DMemMalloc(16);
    strcpy(dep.val.str, "application/ipp");
    ProtDep(&dep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);

    peic.abbrev = "pdf";
    peic.desc = "pdf file";
    ProtPeiComponent(&peic);

    peic.abbrev = "pcl";
    peic.desc = "pcl file";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(IppDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char ipp_dir[256];
    struct stat st;

    /* part of file name */
    incr = 0;

    /* check local pcl6 */
    if (stat("./pcl6", &st) == 0) {
        /* there is a local pcl6 application */
        strcpy(pcl6_path, "./pcl6");
    }
    
    /* protocols and attributes */
    prot_id = ProtId("ipp");

    /* pei id */
    pei_url_id = ProtPeiComptId(prot_id, "url");
    pei_pdffile_id = ProtPeiComptId(prot_id, "pdf");
    pei_pclfile_id = ProtPeiComptId(prot_id, "pcl");

    /* ipp tmp directory */
    sprintf(ipp_dir, "%s/%s", ProtTmpDir(), IPP_TMP_DIR);
    mkdir(ipp_dir, 0x01FF);

    return 0;
}
