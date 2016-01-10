/* tftp.c
 * Dissector of TFTP protocol
 *
 * $Id:$
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009-2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

/* Documentation:
 * RFC 1350: TFTP protocol REVISION 2
 * RFC 2347: TFTP Option Extension
 * RFC 2348: TFTP Blocksize Option
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <ctype.h>

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "tftp.h"
#include "pei.h"
#include "grp_flows.h"
#include "dnsdb.h"

#define TFTP_TMP_DIR    "tftp"

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int udp_id;
static int port_src_id;
static int port_dst_id;
static int tftp_id;

/* pei id */
static int pei_url_id;
static int pei_cmd_id;
static int pei_file_in_id;
static int pei_file_out_id;
static int pei_down_n_id;
static int pei_up_n_id;

static volatile unsigned int incr;
static char *msg_str[] = TFTP_MSG_STRING;

static void TftpConInit(tftp_con *tftp)
{
    memset(tftp, 0, sizeof(tftp_con));
    tftp->file_cmd = DMemMalloc(TFTP_FILENAME_PATH_SIZE);
    tftp->file_cmd[0] = '\0';
    tftp->up_n = 0;
    tftp->down_n = 0;
    tftp->rule = -1;
}


static void TftpConFree(tftp_con *tftp)
{
    if (tftp->file_cmd != NULL)
        DMemFree(tftp->file_cmd);
    tftp->file_cmd = NULL;

    if (tftp->rule != -1)
        GrpRuleRm(tftp->rule);
    tftp->rule = -1;
}


static int TftpDataInit(tftp_data *tftpd)
{
    memset(tftpd, 0, sizeof(tftp_data));
    tftpd->file = DMemMalloc(TFTP_FILENAME_PATH_SIZE);
    tftpd->fid = -1;
    tftpd->fp = NULL;
    tftpd->lost = FALSE;
    tftpd->nxt = NULL;
    tftpd->blk = 0;
    tftpd->convert = FALSE;

    return 0;
}


static int TftpDataFree(tftp_data *tftpd)
{
    if (tftpd->fp != NULL) {
        LogPrintf(LV_ERROR, "File (%s) not closed", tftpd->file);
        fclose(tftpd->fp);
        tftpd->fp = NULL;
    }
    if (tftpd->filename != NULL) {
        DMemFree(tftpd->filename);
        tftpd->filename = NULL;
    }
    if (tftpd->file != NULL) {
        DMemFree(tftpd->file);
        tftpd->file = NULL;
    }
    if (tftpd->stack != NULL) {
        ProtDelFrame(tftpd->stack);
        tftpd->stack = NULL;
    }
    if (tftpd->gstack != NULL) {
        ProtDelFrame(tftpd->gstack);
        tftpd->gstack = NULL;
    }

    return 0;
}


static int TftpMsgInit(tftp_msg *msg)
{
    memset(msg, 0, sizeof(tftp_msg));
    msg->oc = TFTP_OC_NONE;
    
    return 0;
}


static int TftpMsgFree(tftp_msg *msg)
{
    optn *opt, *nopt;

    switch (msg->oc) {
    case TFTP_OC_RRQ:
    case TFTP_OC_WRQ:
    case TFTP_OC_OACK:
        if (msg->m.rq.file != NULL) {
            DMemFree(msg->m.rq.file);
            msg->m.rq.file = NULL;
        }
        if (msg->m.rq.mode != NULL) {
            DMemFree(msg->m.rq.mode);
            msg->m.rq.mode = NULL;
        }
        if (msg->m.rq.options != NULL) {
            opt = msg->m.rq.options;
            do {
                nopt = opt->nxt;
                if (opt->option != NULL)
                    DMemFree(opt->option);
                if (opt->val != NULL)
                    DMemFree(opt->val);
                DMemFree(opt);
                opt = nopt;
            } while(opt != NULL);
            msg->m.rq.options = NULL;
        }
        break;

    case TFTP_OC_DATA:
    case TFTP_OC_ACK:
    case TFTP_OC_ERROR:
    case TFTP_OC_NONE:
        break;

    case TFTP_OC_INFO:
        break;
    }

    return 0;
}


static int TftpMsgStr(tftp_msg *msg, FILE *fp)
{
    optn *opt;

    fprintf(fp, "%s", msg_str[msg->oc]);

    switch (msg->oc) {
    case TFTP_OC_RRQ:
    case TFTP_OC_WRQ:
    case TFTP_OC_OACK:
        if (msg->m.rq.file != NULL) {
            fprintf(fp, " %s", msg->m.rq.file);
        }
        if (msg->m.rq.mode != NULL) {
            fprintf(fp, " %s", msg->m.rq.mode);
        }
        if (msg->m.rq.options != NULL) {
            opt = msg->m.rq.options;
            do {
                if (opt->option != NULL) {
                    fprintf(fp, " %s", opt->option);
                }
                if (opt->val != NULL) {
                    fprintf(fp, " %s", opt->val);
                }
                opt = opt->nxt;
            } while(opt != NULL);
        }
        break;

    case TFTP_OC_DATA:
        fprintf(fp, " %i", msg->m.data.block);
        break;

    case TFTP_OC_ACK:
        fprintf(fp, " %i", msg->m.ack.block);
        break;

    case TFTP_OC_ERROR:
        fprintf(fp, " %i %s", msg->m.err.error, msg->m.err.msg);
        break;

    case TFTP_OC_INFO:
        break;

    case TFTP_OC_NONE:
        break;
    }
    fprintf(fp, "\n");

    return 0;
}


static int TftpAscii(char *dat, unsigned short len)
{
    int i;
    
    for (i=0; i!=len; i++) {
        if (dat[i] == '\0')
            break;
        if (isascii(dat[i]) == 0)
            return -1;
    }
    if (i == len)
        return -1;
    
    return i;
}


static int TftpReq(char *dat, int len, tftp_msg *msg, bool oack)
{
    int l, offset;
    oreq *rq;
    optn **opt;

    rq = &(msg->m.rq);

    if (oack == FALSE) {
        /* file name */
        l = TftpAscii(dat, len);
        if (l == -1)
            return -1;
        rq->file = DMemMalloc(l+1);
        memcpy(rq->file, dat, l);
        rq->file[l] = '\0';
        
        /* mode */
        len = len - l - 1;
        if (len <= 0) {
            TftpMsgFree(msg);
            return -1;
        }
        offset = l + 1;
        l = TftpAscii(dat+offset, len);
        if (l == -1) {
            TftpMsgFree(msg);
            return -1;
        }
        rq->mode = DMemMalloc(l+1);
        memcpy(rq->mode, dat+offset, l);
        rq->mode[l] = '\0';
    }
    else {
        l = -1;
        offset = 0;
    }
    
    opt = &(rq->options);
    do {
        len = len - l - 1;
        if (len == 0)
            return 0;
        
        /* options */
        if (len < 0) {
            TftpMsgFree(msg);
            return -1;
        }
        offset += l + 1;

        *opt = DMemMalloc(sizeof(optn));
        memset(*opt, 0, sizeof(optn));
        /* opt */
        l = TftpAscii(dat+offset, len);
        if (l == -1) {
            TftpMsgFree(msg);
            return -1;
        }
        (*opt)->option = DMemMalloc(l+1);
        memcpy((*opt)->option, dat+offset, l);
        (*opt)->option[l] = '\0';
        len = len - l - 1;
        if (len <= 0) {
            TftpMsgFree(msg);
            return -1;
        }
        offset += l + 1;
        /* val */
        l = TftpAscii(dat+offset, len);
        if (l == -1) {
            TftpMsgFree(msg);
            return -1;
        }
        (*opt)->val = DMemMalloc(l+1);
        memcpy((*opt)->val, dat+offset, l);
        (*opt)->val[l] = '\0';
        
        opt = &((*opt)->nxt);
    } while (1);

    return 0;
}


static int TftpMsg(packet *pkt, tftp_msg *msg)
{
    unsigned short op;
    int l;

    msg->oc = TFTP_OC_NONE;

    if (pkt->len == 0) {
        return 0;
    }
    if (pkt->len < 3) {
        return -1;
    }
    /* op code */
    op = ntohs(*((unsigned short*)(pkt->data)));
    switch (op) {
    case TFTP_RRQ:
        msg->oc = TFTP_OC_RRQ;
        if (TftpReq(pkt->data+2, pkt->len-2, msg, FALSE) != 0) {
            return -1;
        }
        break;
        
    case TFTP_WRQ:
        msg->oc = TFTP_OC_WRQ;
        if (TftpReq(pkt->data+2, pkt->len-2, msg, FALSE) != 0) {
            return -1;
        }
        break;

    case TFTP_DATA:
        msg->oc = TFTP_OC_DATA;
        if (pkt->len > 3) {
            msg->m.data.block = ntohs(*((unsigned short*)(pkt->data+2)));
        }
        else {
            return -1;
        }
        break;

    case TFTP_ACK:
        msg->oc = TFTP_OC_ACK;
        if (pkt->len != 4) {
            return -1;
        }
        msg->m.data.block = ntohs(*((unsigned short*)(pkt->data+2)));
        break;

    case TFTP_ERROR:
        msg->oc = TFTP_OC_ERROR;
        if (pkt->len > 4) {
            msg->m.err.error = ntohs(*((unsigned short*)(pkt->data+2)));
            l = TftpAscii(pkt->data+4, pkt->len-4);
            if (l == -1) {
                return -1;
            }
            msg->m.err.msg = DMemMalloc(l+1);
            memcpy(msg->m.err.msg, pkt->data+4, l);
            msg->m.err.msg[l] = '\0';
        }
        else {
            return -1;
        }
        break;

    case TFTP_OACK:
        msg->oc = TFTP_OC_OACK;
        if (TftpReq(pkt->data+2, pkt->len-2, msg, TRUE) != 0) {
            return -1;
        }
        break;
        
    case TFTP_INFO:
        msg->oc = TFTP_OC_INFO;
        return -1;
        break;
        
    default:
        return -1;
        break;
    }

    return 0;
}


static int TftpPeiCmd(tftp_con *tftp, pei *ppei)
{
    pei_component *cmpn, *tmpn;
    int len;
    char *url, *tmp;

    tmp = DMemMalloc(TFTP_FILENAME_PATH_SIZE);
    if (ppei->components == NULL) {
        /* new pei */
        cmpn = tmpn = NULL;
        /* url */
        url = tmp;
        len = 0;
        sprintf(url, "tftp://");
        len = 7;
        if (tftp->ipv_id == ip_id) {
            if (DnsDbSearch(&(tftp->ip), FT_IPv4, url+len, TFTP_FILENAME_PATH_SIZE - len) != 0) {
                FTString(&(tftp->ip), FT_IPv4, url+len);
            }
        }
        else {
            if (DnsDbSearch(&(tftp->ip), FT_IPv6, url+len, TFTP_FILENAME_PATH_SIZE - len) != 0) {
                FTString(&(tftp->ip), FT_IPv6, url+len);
            }
        }
        len = strlen(url);
        url[len] = ':';
        len++;
        sprintf(url+len, "%i", tftp->port);
        PeiNewComponent(&cmpn, pei_url_id);
        PeiCompCapTime(cmpn, ppei->time_cap);
        PeiCompAddStingBuff(cmpn, url);
        PeiAddComponent(ppei, cmpn);

        /* cmd */
        PeiNewComponent(&tmpn, pei_cmd_id);
        PeiCompCapTime(tmpn, ppei->time_cap);
        PeiCompAddFile(tmpn, "cmd.txt", tftp->file_cmd, 0);
        PeiAddComponent(ppei, tmpn);

        /* upload */
        sprintf(tmp, "%d", tftp->up_n);
        PeiNewComponent(&cmpn, pei_up_n_id);
        PeiCompCapTime(cmpn, ppei->time_cap);
        PeiCompAddStingBuff(cmpn, tmp);
        PeiAddComponent(ppei, cmpn);
            
        /* download */
        sprintf(tmp, "%d", tftp->down_n);
        PeiNewComponent(&cmpn, pei_down_n_id);
        PeiCompCapTime(cmpn, ppei->time_cap);
        PeiCompAddStingBuff(cmpn, tmp);
        PeiAddComponent(ppei, cmpn);
    }
    else {
        /* update components */
        if ((cmpn = PeiCompSearch(ppei, pei_cmd_id)) != NULL) {
            PeiCompCapEndTime(cmpn, tftp->cap_end);
            PeiCompAddFile(cmpn, "cmd.txt", tftp->file_cmd, 0);
            PeiCompUpdated(cmpn);
        }
        if ((cmpn = PeiCompSearch(ppei, pei_up_n_id)) != NULL) {
            PeiCompCapEndTime(cmpn, tftp->cap_end);
            sprintf(tmp, "%d", tftp->up_n);
            PeiCompAddStingBuff(cmpn, tmp);
            PeiCompUpdated(cmpn);
        }
        if ((cmpn = PeiCompSearch(ppei, pei_down_n_id)) != NULL) {
            PeiCompCapEndTime(cmpn, tftp->cap_end);
            sprintf(tmp, "%d", tftp->down_n);
            PeiCompAddStingBuff(cmpn, tmp);
            PeiCompUpdated(cmpn);
        }
    }
    /* free tmp buffer */
    DMemFree(tmp);

    return 0;
}


static int TftpPeiData(tftp_data *td, pei *npei, pei *ppei)
{
    pei_component *comp;

    PeiParent(npei, ppei);
    PeiCapTime(npei, td->cap_start);
    PeiMarker(npei, td->serial);
    PeiStackFlow(npei, td->gstack);
    /* file */
    if (td->download == TRUE)
        PeiNewComponent(&comp, pei_file_in_id);
    else
        PeiNewComponent(&comp, pei_file_out_id);
    PeiCompAddFile(comp, td->filename, td->file, 0);
    PeiCompCapTime(comp, td->cap_start);
    PeiCompCapEndTime(comp, td->cap_end);
    if (td->lost == TRUE)
        PeiCompError(comp, ELMT_ER_PARTIAL);
    PeiAddComponent(npei, comp);
    
    return 0;
}


static int FtpDataRule(int flow_id, tftp_con *tftp, tpkt_con *con, tftp_oc oc)
{
    cmp_val rip, rport;
    int rid;

    /* delete last rule */
    if (tftp->rule != -1) {
        GrpRuleRm(tftp->rule);
        tftp->rule = -1;
    }

    rid = GrpRuleNew(flow_id);
    if (con->ipv6 == FALSE) {
        rip.prot = ip_id;
        rip.att = ip_dst_id;
        if (oc == TFTP_OC_RRQ) {
            FTCopy(&(rip.val), &(con->ip_s), FT_IPv4);
        }
        else {
            FTCopy(&(rip.val), &(con->ip_s), FT_IPv4);
        }
        rport.val.uint16 = con->port_s;
        LogPrintf(LV_DEBUG, "Rule %i, port:%i", rid, con->port_s);
    }
    else {
        rip.prot = ipv6_id;
        rip.att = ipv6_dst_id;
        if (oc == TFTP_OC_RRQ) {
            FTCopy(&(rip.val), &(con->ip_s), FT_IPv6);
        }
        else {
            FTCopy(&(rip.val), &(con->ip_s), FT_IPv6);
        }
        rport.val.int16 = con->port_s;
    }
    rport.prot = udp_id;
    rport.att = port_dst_id;
    GrpRule(rid, 2, &rip, &rport);
    if (con->ipv6 == FALSE) {
        rip.att = ip_src_id;
    }
    else {
        rip.att = ipv6_src_id;
    }
    rport.att = port_src_id;
    GrpRule(rid, 2, &rip, &rport);
    GrpRuleCmplt(rid);

    tftp->rule = rid;

    return 0;
}


static int TftpPktInfo(tpkt_con *tcon, const packet *pkt)
{
    const pstack_f *udp, *ip;
    ftval port_src, port_dst;
    
    udp = pkt->stk;
    ip = ProtGetNxtFrame(udp);    
    ProtGetAttr(udp, port_src_id, &port_src);
    ProtGetAttr(udp, port_dst_id, &port_dst);
    tcon->port_s = port_src.uint16;
    tcon->port_d = port_dst.uint16;
    if (ProtFrameProtocol(ip) == ip_id) {
        tcon->ipv6 = FALSE;
        ProtGetAttr(ip, ip_src_id, &tcon->ip_s);
        ProtGetAttr(ip, ip_dst_id, &tcon->ip_d);
    }
    else {
        tcon->ipv6 = TRUE;
        ProtGetAttr(ip, ipv6_src_id, &tcon->ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &tcon->ip_d);
    }
    
    return 0;
}


static int TftpDataConv(const char *data, int size, char *conv, tftp_data *tdt)
{
    int i, j;
    char c, pre;
    
    i = 0;
    j = 0;
    pre = tdt->conv_c;
    if (pre == '\r')
        conv[j++] = pre;
    while (size--) {
        c = data[i++];
        if (pre == '\r') {
            if (c == '\n' && j != 0)
                j--;
            else if (c == '\0') {
                pre = c;
                continue;
            }
        }
        conv[j++] = c;
        pre = c;
    }
    tdt->conv_c = pre;
    if (pre == '\r')
        j--;

    return j;
}


static int TftpDataWr(tftp_data *tdt, tftp_msg *msg, packet *pkt)
{
    long offset;
    char *dummy, *data, *conv;
    int size, ret;
    
    ret = 0;
    data = pkt->data + TFTP_DATA_HEADER;
    if (msg->oc == TFTP_OC_DATA) {
        if (tdt->convert)
            conv = xmalloc(tdt->blk_size + 1);
        size = tdt->blk_size;
        if (msg->m.data.block == tdt->blk + 1) {
            if (size != pkt->len - TFTP_DATA_HEADER) {
                size = pkt->len - TFTP_DATA_HEADER;
                
                ret = -1;
            }
            if (tdt->convert) {
                size = TftpDataConv(data, size, conv, tdt);
                data = conv;
            }
            fwrite(data, 1, size, tdt->fp);
            tdt->blk = msg->m.data.block;
        }
        else {
            if (msg->m.data.block > tdt->blk) {
                /* data lost */
                tdt->lost = TRUE;
                dummy = xmalloc(tdt->blk_size);
                memset(dummy, 0, tdt->blk_size);
                for (; tdt->blk != msg->m.data.block-1; tdt->blk++) {
                    fwrite(dummy, 1, tdt->blk_size, tdt->fp);
                }
                xfree(dummy);
                if (size != pkt->len - TFTP_DATA_HEADER) {
                    size = pkt->len - TFTP_DATA_HEADER;
                    ret = -1;
                }
                tdt->conv_c = 0; /* not \r */
                if (tdt->convert) {
                    size = TftpDataConv(data, size, conv, tdt);
                    data = conv;
                }
                fwrite(data, 1, size, tdt->fp);
                tdt->blk = msg->m.data.block;
            }
            else {
                offset = msg->m.data.block - 1;
                offset *= tdt->blk_size;
                fseek(tdt->fp, offset, SEEK_SET);
                tdt->conv_c = 0; /* not \r */
                if (tdt->convert) {
                    size = TftpDataConv(data, size, conv, tdt);
                    data = conv;
                }
                fwrite(data, 1, size, tdt->fp);
                tdt->conv_c = 0; /* not \r */
                fseek(tdt->fp, 0, SEEK_END);
            }
        }
        if (tdt->convert)
            xfree(conv);
    }
    else if (msg->oc == TFTP_OC_ERROR) {
        /* data lost */
        tdt->lost = TRUE;
        return -1;
    }
    
    return ret;
}


static int TftpBlockSize(tftp_msg *msg)
{
    int blk_size;
    optn *opt;

    blk_size = TFTP_DATA_SIZE;
    
    opt = msg->m.rq.options;
    while (opt != NULL) {
        if (strcasecmp(opt->option, "blksize") == 0) {
            blk_size = strtol(opt->val, NULL, 10);
            if (blk_size < 8 || blk_size > 65464) {
                LogPrintf(LV_WARNING, "Block size out of range");
                blk_size = TFTP_DATA_SIZE;
            }
            break;
        }
        opt = opt->nxt;
    }

    return blk_size;
}


static int TftpConnec(int flow_id, tftp_priv *priv)
{
    packet *pkt, *mpkt;
    tftp_msg msg;
    pei *mpei, *dpei;
    tftp_con tftp;
    int gid, data_id, i;
    tftp_data *tftp_dt, *predt, *tdt, *nxtt;
    tftp_data *new_data, *mdata;
    FILE *fp;
    tpkt_con pktc;
    bool nodata;

    /* init */
    mpei = dpei = NULL;
    memset(&pktc, 0, sizeof(pktc));
    TftpConInit(&tftp);
    gid = FlowGrpId(flow_id);
    data_id = -1;
    tftp_dt = NULL;
    new_data = NULL;
    mdata = NULL;
    i = 0;
    mpkt = NULL;

    pkt = FlowGetPkt(flow_id);
    if (pkt != NULL) { /* useless */
        TftpMsgInit(&msg);
        TftpMsg(pkt, &msg);
        /* connection type (first packet always is correct) */
        if (msg.oc == TFTP_OC_RRQ || msg.oc == TFTP_OC_WRQ) {
            /* main flow */
            TftpPktInfo(&pktc, pkt);
            /* create master pei */
            PeiNew(&mpei, tftp_id);
            PeiCapTime(mpei, pkt->cap_sec);
            PeiMarker(mpei, pkt->serial);
            PeiStackFlow(mpei, FlowStack(flow_id));
            PeiSetReturn(mpei, TRUE); /* neccesary */
            tftp.cap_end = pkt->cap_sec;
            if (priv->ipv6 == TRUE) {
                tftp.ipv_id = ipv6_id;
                FTCopy(&(tftp.ip), &(pktc.ip_d), FT_IPv6);
            }
            else {
                tftp.ipv_id = ip_id;
                FTCopy(&(tftp.ip), &(pktc.ip_d), FT_IPv4);
            }
            tftp.port = pktc.port_d;
            /* cmd file path and name */
            sprintf(tftp.file_cmd, "%s/%s/tftp_%lld_%p_%i.txt", ProtTmpDir(), TFTP_TMP_DIR, (long long)time(NULL), &tftp, incr);
            incr++;
            /* compose pei and insert it */
            TftpPeiCmd(&tftp, mpei);
            PeiIns(mpei);
            /* open file to report command sended to server */
            fp = fopen(tftp.file_cmd, "w");
            TftpMsgFree(&msg);
            do {
                nodata = TRUE;
                if (pkt != NULL) {
                    /* main flow */
                    //ProtStackFrmDisp(pkt->stk, TRUE);
                    nodata = FALSE;
                    TftpMsgInit(&msg);
                    TftpMsg(pkt, &msg);
                    /* check message taht define new transfer */
                    if (msg.oc == TFTP_OC_RRQ || msg.oc == TFTP_OC_WRQ) {
                        /* rule */
                        TftpPktInfo(&pktc, pkt);
                        FtpDataRule(flow_id, &tftp, &pktc, msg.oc);
                        
                        /* main flow with small timeout */
                        FlowSetTimeOut(flow_id, TFTP_PKT_TIMEOUT);
                        if (new_data == NULL) {
                            new_data = DMemMalloc(sizeof(tftp_data));
                            TftpDataInit(new_data);
                        }
                        else {
                            TftpDataFree(new_data);
                            TftpDataInit(new_data);
                        }
                        /* mode */
                        if (strcasecmp(msg.m.rq.mode, "netascii") == 0) {
                            new_data->convert = TRUE;
                        }
                        new_data->filename = DMemMalloc(strlen(msg.m.rq.file)+1);
                        strcpy(new_data->filename, msg.m.rq.file);
                        if (msg.oc == TFTP_OC_RRQ) {
                            new_data->download = TRUE;
                            tftp.down_n++;
                        }
                        else {
                            new_data->download = FALSE;
                            tftp.up_n++;
                        }

                        new_data->blk_size = TftpBlockSize(&msg);
                        if (mdata != NULL) {
                            /* data end */
                            mdata->lost = TRUE;
                            fclose(mdata->fp);
                            mdata->fp = NULL;
                            /* data pei */
                            PeiNew(&dpei, tftp_id);
                            TftpPeiData(mdata, dpei, mpei);
                            PeiIns(dpei);
                            TftpDataFree(mdata);
                            mdata = NULL;
                        }
                        /* put command in command file */
                        if (fp != NULL) {
                            TftpMsgStr(&msg, fp);
                        }
                    }
                    else {
                        /* if the data file come from main flow... */
                        if (mdata != NULL) {
                            mdata->cap_end = pkt->cap_sec;
                            if (TftpDataWr(mdata, &msg, pkt) != 0) {
                                /* last packet.. close data file */
                                fclose(mdata->fp);
                                mdata->fp = NULL;
                                /* data pei */
                                PeiNew(&dpei, tftp_id);
                                TftpPeiData(mdata, dpei, mpei);
                                PeiIns(dpei);
                                TftpDataFree(mdata);
                                mdata = NULL;
                            }
                            if (msg.oc != TFTP_OC_DATA && msg.oc != TFTP_OC_ACK && fp != NULL)
                                TftpMsgStr(&msg, fp);
                        }
                        else if (tftp.rule != -1 && (msg.oc == TFTP_OC_DATA || msg.oc == TFTP_OC_ACK)) {
                            /* data in main flow */
                            GrpRuleRm(tftp.rule);
                            tftp.rule = -1;
                            new_data->stack = ProtCopyFrame(FlowStack(flow_id), TRUE);
                            new_data->gstack = ProtCopyFrame(FlowGrpStack(gid), TRUE);
                            /* file path and name */
                            sprintf(new_data->file, "%s/%s/tftp_data_%lld_%p_%i_%i.txt", ProtTmpDir(), TFTP_TMP_DIR, (long long)time(NULL), &tftp, incr, i);
                            /* open file */
                            new_data->fp = fopen(new_data->file, "w");
                            mdata = new_data;
                            new_data = NULL;
                            
                            /* first packet... */
                            mdata->cap_start = pkt->cap_sec;
                            mdata->cap_end = pkt->cap_sec;
                            mdata->serial = pkt->serial;
                            TftpDataWr(mdata, &msg, pkt);
                        }
                        else if (fp != NULL) {
                            TftpMsgStr(&msg, fp);
                        }
                    }
                    TftpMsgFree(&msg);
                    tftp.cap_end = pkt->cap_sec;
                    PktFree(pkt);
                }
                else {
                    if (tftp_dt != NULL) {
                        /* tftp data */
                        tdt = tftp_dt;
                        while (tdt) {
                            do {
                                pkt = FlowGetPkt(tdt->fid);
                                if (pkt != NULL && tdt->end == FALSE) {
                                    nodata = FALSE;
                                    if (tdt->serial == 0) {
                                        /* first packet... */
                                        FlowSyncr(tdt->fid, FALSE); /* it is not neccesary synchronization data, it is neccesary only for first packet to enable tracing errors in cmd file */
                                        tdt->cap_start = pkt->cap_sec;
                                        tdt->serial = pkt->serial;
                                    }
                                    tdt->cap_end = pkt->cap_sec;

                                    TftpMsgInit(&msg);
                                    TftpMsg(pkt, &msg);
                                    if (TftpDataWr(tdt, &msg, pkt) != 0) {
                                        /* last packet.. close data file */
                                        FlowSyncr(tdt->fid, TRUE); /* there is a possibility that another file come from diss connection  */
                                        fclose(tdt->fp);
                                        tdt->fp = NULL;
                                        tdt->end = TRUE;
                                        /* data pei */
                                        PeiNew(&dpei, tftp_id);
                                        TftpPeiData(tdt, dpei, mpei);
                                        PeiIns(dpei);
                                    }
                                    if (msg.oc != TFTP_OC_DATA && msg.oc != TFTP_OC_ACK && fp != NULL)
                                        TftpMsgStr(&msg, fp);
                                    PktFree(pkt);
                                    TftpMsgFree(&msg);
                                }
                                else if (pkt != NULL) {
                                    /* verify if there is a new 'new_data' and if this packet is a data packet */
#warning "to do"
                                    PktFree(pkt);
                                }
                            } while (pkt != NULL);
                            tdt = tdt->nxt;
                        }
                        /* check flow closed */
                        predt = NULL;
                        tdt = tftp_dt;
                        while (tdt) {
                            if (FlowIsEmpty(tdt->fid) == TRUE) {
                                if (tdt->end == FALSE) {
                                    /*.. close data file */
                                    fclose(tdt->fp);
                                    tdt->fp = NULL;
                                    /* data lost */
                                    tdt->lost = TRUE;
                                    /* data pei */
                                    PeiNew(&dpei, tftp_id);
                                    TftpPeiData(tdt, dpei, mpei);
                                    PeiIns(dpei);
                                }
                                if (predt == NULL)
                                    tftp_dt = tdt->nxt;
                                else
                                    predt->nxt = tdt->nxt;
                                nxtt = tdt->nxt;
                                TftpDataFree(tdt);
                                tdt = nxtt;
                            }
                            else {
                                predt = tdt;
                                tdt = tdt->nxt;
                            }
                        }
                        if (nodata == TRUE) {
                            /* main flow with small timeout */
                            FlowSetTimeOut(flow_id, TFTP_PKT_TIMEOUT);
                        }
                        else {
                            /* main flow without timeout */
                            FlowSetTimeOut(flow_id, 0);
                        }
                    }
                    else if (tftp.rule == -1) {
                        /* no waiting any data connection */
                        FlowSetTimeOut(flow_id, -1);
                    }
                }
                /* next packet of main flow, necessay before GrpLink */
                if (mpkt != NULL) {
                    /* to syncronize with the last data connection */
                    pkt = mpkt;
                    mpkt = NULL;
                }
                else
                    pkt = FlowGetPkt(flow_id);

                /* wait data connection */
                data_id = GrpLink(gid);
                if (data_id != -1) {
                    i++;
                    GrpRuleRm(tftp.rule);
                    tftp.rule = -1;
                    /* setup timeout */
                    FlowSetTimeOut(data_id, 0);
                    /* main flow without timeout */
                    FlowSetTimeOut(flow_id, 0);
                    if (new_data == NULL) {
                        LogPrintf(LV_OOPS, "Data without request!?");
                        return -1;
                    }
                    
                    /* new data file transfer */
                    new_data->fid = data_id;
                    new_data->stack = ProtCopyFrame(FlowStack(data_id), TRUE);
                    new_data->gstack = ProtCopyFrame(FlowGrpStack(gid), TRUE);
                    /* file path and name */
                    sprintf(new_data->file, "%s/%s/tftp_data_%lld_%p_%i_%i_.txt", ProtTmpDir(), TFTP_TMP_DIR, (long long)time(NULL), &tftp, incr, i);
                    /* open file */
                    new_data->fp = fopen(new_data->file, "w");
                    new_data->nxt = tftp_dt;
                    tftp_dt = new_data;
                    new_data = NULL;

                    /* if also a new main packet suspend elaboration of master flow */
                    mpkt = pkt;
                    pkt = NULL;
                }
            } while (pkt != NULL || tftp_dt != NULL || FlowGrpIsEmpty(flow_id) == FALSE);
            /* end */
            if (mdata != NULL) {
                /* data end */
                mdata->lost = TRUE;
                fclose(mdata->fp);
                mdata->fp = NULL;
                /* data pei */
                PeiNew(&dpei, tftp_id);
                TftpPeiData(mdata, dpei, mpei);
                PeiIns(dpei);
                TftpDataFree(mdata);
                mdata = NULL;
            }
            /* close file and update pei */
            fclose(fp);
            TftpPeiCmd(&tftp, mpei);
            PeiSetReturn(mpei, FALSE);
            PeiIns(mpei); /* update */
            TftpConFree(&tftp);
        }
        else {
            /* data flow... main flow lost */
            FlowSyncr(flow_id, FALSE); /* it is not neccesary synchronization in this case */
#warning "to do"
            LogPrintf(LV_WARNING, "Tftp data transfer without master connection");
            return -1;
        }
    }
    
    return 0;
}


static packet* TftpDissector(int flow_id)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    const pstack_f *udp, *ip;
    ftval port_src, port_dst;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    tftp_priv *priv;
    packet *pkt;

    LogPrintf(LV_DEBUG, "TFTP id: %d", flow_id);
    priv = DMemMalloc(sizeof(tftp_priv));
    memset(priv, 0, sizeof(tftp_priv));
    udp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(udp);
    ProtGetAttr(udp, port_src_id, &port_src);
    ProtGetAttr(udp, port_dst_id, &port_dst);
    priv->port = port_src.uint16;
    priv->portd = port_dst.uint16;
    if (priv->port != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    if (ProtFrameProtocol(ip) == ip_id) {
        priv->ipv6 = FALSE;
        ProtGetAttr(ip, ip_src_id, &priv->ip);
        ProtGetAttr(ip, ip_dst_id, &priv->ipd);
        ip_addr.s_addr = priv->ip.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = priv->ipd.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip);
        ProtGetAttr(ip, ipv6_dst_id, &priv->ipd);
        memcpy(ipv6_addr.s6_addr, priv->ip.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, priv->ipd.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
    
    if (TftpConnec(flow_id, priv) != 0) {
        /* raw tftp file */
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }
    /* free */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "TFTP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool TftpVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    bool ret;
    ftval ips;
    bool ipv4;
    int cnt;
    tftp_msg *msg;

    ipv4 = FALSE;
    ret = FALSE;
    cnt = 0;
    pkt = FlowGetPktCp(flow_id);
    if (pkt != NULL) {
        /* check ip */
        ip = ProtGetNxtFrame(pkt->stk);
        if (ProtFrameProtocol(ip) == ip_id)
            ipv4 = TRUE;
        if (ipv4 == TRUE)
            ProtGetAttr(ip, ip_src_id, &ips);
        else
            ProtGetAttr(ip, ipv6_src_id, &ips);
        while (pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL)
                break;
        }
    }
    if (pkt != NULL) {
        msg = DMemMalloc(sizeof(tftp_msg));
        TftpMsgInit(msg);
        do {
            if (pkt->len != 0) {
                ip = ProtGetNxtFrame(pkt->stk);
                if (ipv4 == TRUE) {
                    if (TftpMsg(pkt, msg) != 0) {
                        cnt = 0;
                        break;
                    }
                }
                else {
                    if (TftpMsg(pkt, msg) != 0) {
                        cnt = 0;
                        break;
                    }
                }
                TftpMsgFree(msg);
                TftpMsgInit(msg);
                cnt++;
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
        } while (cnt != TFTP_PKT_CHECK && pkt != NULL);
        TftpMsgFree(msg);
        DMemFree(msg);
        msg = NULL;
    }
    
    if (pkt != NULL) {
        PktFree(pkt);
        pkt = NULL;
    }
    
    if (cnt == TFTP_PKT_CHECK || (cnt != 0 && check == FALSE))
        ret = TRUE;

    return ret;
}


static bool TftpVerify(int flow_id)
{
    return TftpVerifyCheck(flow_id, FALSE);
}


static bool TftpCheck(int flow_id)
{
    return TftpVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Trivial File Transfer Protocol", "tftp");
    
    /* dep: tcp */
    dep.name = "udp";
    dep.attr = "udp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = UDP_PORT_TFTP;
    dep.ProtCheck = TftpVerify;
    dep.pktlim = TFTP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: udp */
    hdep.name = "udp";
    hdep.ProtCheck = TftpCheck;
    hdep.pktlim = TFTP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);

    peic.abbrev = "cmd";
    peic.desc = "User commands";
    ProtPeiComponent(&peic);

    peic.abbrev = "file_in";
    peic.desc = "Received file";
    ProtPeiComponent(&peic);

    peic.abbrev = "file_out";
    peic.desc = "Transmited file";
    ProtPeiComponent(&peic);

    peic.abbrev = "down_n";
    peic.desc = "Number of file downloaded";
    ProtPeiComponent(&peic);

    peic.abbrev = "up_n";
    peic.desc = "Number of file uploaded";
    ProtPeiComponent(&peic);

    /* group protocol (master flow) */
    ProtGrpEnable();

    /* dissectors registration */
    ProtDissectors(NULL, TftpDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char tftp_dir[256];

    /* part of file name */
    incr = 0;
    
    /* info id */
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    udp_id = ProtId("udp");
    port_dst_id = ProtAttrId(udp_id, "udp.dstport");
    port_src_id = ProtAttrId(udp_id, "udp.srcport");
    tftp_id = ProtId("tftp");

    /* pei id */
    pei_url_id = ProtPeiComptId(tftp_id, "url");
    pei_cmd_id = ProtPeiComptId(tftp_id, "cmd");
    pei_file_in_id = ProtPeiComptId(tftp_id, "file_in");
    pei_file_out_id = ProtPeiComptId(tftp_id, "file_out");
    pei_down_n_id = ProtPeiComptId(tftp_id, "down_n");
    pei_up_n_id = ProtPeiComptId(tftp_id, "up_n");

    /* tftp tmp directory */
    sprintf(tftp_dir, "%s/%s", ProtTmpDir(), TFTP_TMP_DIR);
    mkdir(tftp_dir, 0x01FF);

    return 0;
}
