/* nntp.c
 * NNTP packet dissection
 * RFC 3977
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

#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "etypes.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "nntp.h"
#include "strutil.h"
#include "pei.h"
#include "dnsdb.h"

#define NNTP_EN_PEI     1
#define NNTP_TMP_DIR    "nntp"

#define INCOMPLETE      0    /* commands not completed */


/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int tcp_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int clnt_id;
static int nntp_id;

/* pei id */
static int pei_url_id;
static int pei_grp_id;
static int pei_article_id;
static int pei_header_id;
static int pei_body_id;
static int pei_post_id;


static volatile unsigned int incr;

static int NntpRpl(nntp_msg *msg, packet *pkt);
static int NntpMuli(nntp_msg *msg, packet *pkt);
static int NntpData(nntp_msg *msg, packet *pkt);

static nntp_rep_code rep_code[] = {
    {100, NNTP_REP_100},
    {101, NNTP_REP_101},
    {111, NNTP_REP_111},
    {200, NNTP_REP_200},
    {201, NNTP_REP_201},
    {205, NNTP_REP_205},
    {211, NNTP_REP_211},
    {215, NNTP_REP_215},
    {218, NNTP_REP_218},
    {220, NNTP_REP_220},
    {221, NNTP_REP_221},
    {222, NNTP_REP_222},
    {223, NNTP_REP_223},
    {224, NNTP_REP_224},
    {225, NNTP_REP_225},
    {230, NNTP_REP_230},
    {231, NNTP_REP_231},
    {235, NNTP_REP_235},
    {239, NNTP_REP_239},
    {240, NNTP_REP_240},
    {282, NNTP_REP_282},
    {335, NNTP_REP_335},
    {340, NNTP_REP_340},
    {400, NNTP_REP_400},
    {401, NNTP_REP_401},
    {403, NNTP_REP_403},
    {411, NNTP_REP_411},
    {412, NNTP_REP_412},
    {418, NNTP_REP_418},
    {420, NNTP_REP_420},
    {421, NNTP_REP_421},
    {422, NNTP_REP_422},
    {423, NNTP_REP_423},
    {430, NNTP_REP_430},
    {435, NNTP_REP_435},
    {436, NNTP_REP_436},
    {437, NNTP_REP_437},
    {439, NNTP_REP_439},
    {440, NNTP_REP_440},
    {441, NNTP_REP_441},
    {480, NNTP_REP_480},
    {483, NNTP_REP_483},
    {500, NNTP_REP_500},
    {501, NNTP_REP_501},
    {502, NNTP_REP_502},
    {503, NNTP_REP_503},
    {504, NNTP_REP_504},
};


static nntp_cmd NntpCommand(const char *line, int linelen)
{
    const char *ptr;
    int	index = 0;

    ptr = (const char *)line;
    /* Look for the space following the command */
    while (index < linelen) {
        if (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
            break;
        else {
            ptr++;
            index++;
        }
    }

    /* Check the commands that have same length */
    if (index == 3) {
        if (strncasecmp(line, "HDR", index) == 0) {
            return NNTP_CMD_HDR;
        }
    }
    else {
        switch (line[0]) {
        case 'A':
        case 'a':
            if (strncasecmp(line, "ARTICLE", index) == 0) {
                return NNTP_CMD_ARTICLE;
            }
#if INCOMPLETE
            else if (strncasecmp(line, "AUTHINFO", index) == 0) {
                return NNTP_CMD_AUTHINFO;
            }
#endif
            break;

        case 'B':
        case 'b':
            if (strncasecmp(line, "BODY", index) == 0) {
                return NNTP_CMD_BODY;
            }
            break;

        case 'C':
        case 'c':
            if (strncasecmp(line, "CAPABILITIES", index) == 0) {
                return NNTP_CMD_CAPABILITIES;
            }
            else if (strncasecmp(line, "CHECK", index) == 0) {
                return NNTP_CMD_CHECK;
            }
            break;

        case 'D':
        case 'd':
            if (strncasecmp(line, "DATE", index) == 0) {
                return NNTP_CMD_DATE;
            }
            break;

        case 'G':
        case 'g':
            if (strncasecmp(line, "GROUP", index) == 0) {
                return NNTP_CMD_GROUP;
            }
            break;

        case 'H':
        case 'h':
            if (strncasecmp(line, "HEAD", index) == 0) {
                return NNTP_CMD_HEAD;
            }
            else if (strncasecmp(line, "HELP", index) == 0) {
                return NNTP_CMD_HELP;
            }
            break;

        case 'I':
        case 'i':
            if (strncasecmp(line, "IHAVE", index) == 0) {
                return NNTP_CMD_IHAVE;
            }
            break;

        case 'L':
        case 'l':
            if (strncasecmp(line, "LAST", index) == 0) {
                return NNTP_CMD_LAST;
            }
            else if (strncasecmp(line, "LIST", index) == 0) {
                return NNTP_CMD_LIST;
            }
            else if (strncasecmp(line, "LISTGROUP", index) == 0) {
                return NNTP_CMD_LISTGROUP;
            }
            break;

        case 'M':
        case 'm':
            if (strncasecmp(line, "MODE", index) == 0) {
                return NNTP_CMD_MODE;
            }
            break;

        case 'N':
        case 'n':
            if (strncasecmp(line, "NEWGROUPS", index) == 0) {
                return NNTP_CMD_NEWGROUPS;
            }
            else if (strncasecmp(line, "NEWNEWS", index) == 0) {
                return NNTP_CMD_NEWNEWS;
            }
            else if (strncasecmp(line, "NEXT", index) == 0) {
                return NNTP_CMD_NEXT;
            }
            break;

        case 'O':
        case 'o':
            if (strncasecmp(line, "OVER", index) == 0) {
                return NNTP_CMD_OVER;
            }
            break;

        case 'P':
        case 'p':
            if (strncasecmp(line, "POST", index) == 0) {
                return NNTP_CMD_POST;
            }
            break;

        case 'Q':
        case 'q':
            if (strncasecmp(line, "QUIT", index) == 0) {
                return NNTP_CMD_QUIT;
            }
            break;

        case 'S':
        case 's':
            if (strncasecmp(line, "STAT", index) == 0) {
                return NNTP_CMD_STAT;
            }
#if INCOMPLETE
            else if (strncasecmp(line, "SLAVE", index) == 0) {
                return NNTP_CMD_SLAVE;
            }
#endif
            break;

        case 'T':
        case 't':
            if (strncasecmp(line, "TAKETHIS", index) == 0) {
                return NNTP_CMD_TAKETHIS;
            }
            break;

        case 'X':
        case 'x':
            if (strncasecmp(line, "XHDR", index) == 0) {
                return NNTP_CMD_XHDR;
            }
            else if (strncasecmp(line, "XOVER", index) == 0) {
                return NNTP_CMD_XOVER;
            }
            else if (strncasecmp(line, "XGTITLE", index) == 0) {
                return NNTP_CMD_XGTITLE;
            }
#if INCOMPLETE
            else if (strncasecmp(line, "XINDEX", index) == 0) {
                return NNTP_CMD_XINDEX;
            }
            else if (strncasecmp(line, "XPAT", index) == 0) {
                return NNTP_CMD_XPAT;
            }
            else if (strncasecmp(line, "XTHREAD", index) == 0) {
                return NNTP_CMD_XTHREAD;
            }
            else if (strncasecmp(line, "XROVER", index) == 0) {
                return NNTP_CMD_XROVER;
            }
            else if (strncasecmp(line, "XREPLIC", index) == 0) {
                return NNTP_CMD_XREPLIC;
            }
#endif
            break;

        case 'W':
        case 'w':
#if INCOMPLETE
            if (strncasecmp(line, "WILDMAT", index) == 0) {
                return NNTP_CMD_WILDMAT;
            }
#endif
            break;

        default:
            break;
        }

    }

    return NNTP_CMD_NONE;
}


static nntp_repl NntpReply(const char *line, int len)
{
    const char *ptr;
    int index, val;
    nntp_repl rep = NNTP_REP_NONE;
    int i, dim = sizeof(rep_code);

    index = 0;
    val = 0;
    ptr = (const char *)line;
    /* Look for the space pr '-' following the code replay */
    while (index < len) {
        if (*ptr == ' ' || *ptr == '-')
            break;
        else {
            ptr++;
            index++;
        }
    }

    /* The first token is the code reply */
    if (*ptr == ' ') {
        if (sscanf(line, "%i", &val) == 0) {
            return rep;
        }
    }
    else {
        return rep;
    }

    /* search enum */
    for (i=0; i!=dim; i++) {
        if (rep_code[i].num == val) {
            rep = rep_code[i].rep;
            break;
        }
    }

    return rep;
}


static bool NntpClientPkt(nntp_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port);
        if (port.uint16 == priv->port_s)
            ret = TRUE;
    }
    else {
        if (priv->ipv6 == TRUE) {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ipv6_src_id, &ip);
            type = FT_IPv6;
        }
        else {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ip_src_id, &ip);
            type = FT_IPv4;
        }
        if (FTCmp(&priv->ip_s, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }

    /* first time, the verify function verify that first pkt is a server pkt */
    if (priv->dir == NNTP_CLT_DIR_NONE) {
        if (ret == TRUE) {
            priv->dir = NNTP_CLT_DIR_OK;
            LogPrintf(LV_WARNING, "Acqusition file has an error!");
            if (pkt != NULL)
                ProtStackFrmDisp(pkt->stk, TRUE);
        }
        else {
            priv->dir = NNTP_CLT_DIR_REVERS;
        }
    }
    else {
        if (priv->dir == NNTP_CLT_DIR_OK)
            ret = !ret;
    }
    
    return ret;
}


static void NntpMsgInit(nntp_msg *msg)
{
    memset(msg, 0, sizeof(nntp_msg));
    msg->file_data = DMemMalloc(NNTP_FILENAME_PATH_SIZE);
    msg->file_data[0] = '\0';
    msg->cmdt = NNTP_CMD_NONE;
    msg->st = NNTP_REP_NONE;
    msg->fp_data = NULL;
    msg->auth_cont = FALSE;
}


static void NntpMsgFree(nntp_msg *msg)
{
    nntp_msg *next, *tmp;

    next = msg;
    while (next != NULL) {
        if (next->file_data != NULL) {
            if (next->file_data[0] != '\0' && next->fp_data != NULL && next->dsize != 0) {
                LogPrintf(LV_WARNING, "File '%s' dosn't insert in a PEI", next->file_data);
                //exit(-1);
            }
        }
        if (next->cmd != NULL)
            xfree(next->cmd);
        if (next->repl != NULL)
            xfree(next->repl);
        if (next->multp_resp != NULL) {
            xfree(next->multp_resp);
        }
        if (next->fp_data != NULL) {
            fclose(next->fp_data);
            LogPrintf(LV_WARNING, "File '%s' not closed", next->file_data);
        }
        if (next->file_data != NULL) {
            DMemFree(next->file_data);
        }
        tmp = next;
        next = next->nxt;
        DMemFree(tmp);
    }
}


static int NntpPeiUrl(pei *ppei, nntp_priv *priv)
{
    pei_component *cmpn, *tmpn;
    int len;
    char *url, *tmp;
    ftval *ip;

    if (ppei->components == NULL) {
        tmp = DMemMalloc(NNTP_FILENAME_PATH_SIZE);
        /* new pei */
        cmpn = tmpn = NULL;
        /* url */
        url = tmp;
        len = 0;
        sprintf(url, "nntp://");
        len = 7;
        if (priv->dir == NNTP_CLT_DIR_REVERS)
            ip = &(priv->ip_d);
        else
            ip = &(priv->ip_s);
                
        if (priv->ipv6 == FALSE) {
            if (DnsDbSearch(ip, FT_IPv4, url+len, NNTP_FILENAME_PATH_SIZE - len) != 0) {
                FTString(ip, FT_IPv4, url+len);
            }
        }
        else {
            if (DnsDbSearch(ip, FT_IPv6, url+len, NNTP_FILENAME_PATH_SIZE - len) != 0) {
                FTString(ip, FT_IPv6, url+len);
            }
        }
        len = strlen(url);
        url[len] = ':';
        len++;
        if (priv->dir == NNTP_CLT_DIR_REVERS)
            sprintf(url+len, "%i", priv->port_d);
        else
            sprintf(url+len, "%i", priv->port_s);
        PeiNewComponent(&cmpn, pei_url_id);
        PeiCompCapTime(cmpn, ppei->time_cap);
        PeiCompAddStingBuff(cmpn, url);
        PeiAddComponent(ppei, cmpn);
        /* free tmp buffer */
        DMemFree(tmp);
    }

    return 0;
}


static int NntpPei(pei *ppei, nntp_msg *msg)
{
    pei_component *cmpn;
    char *grpname, *tmp;

    switch (msg->cmdt) {
    case NNTP_CMD_ARTICLE:
        PeiNewComponent(&cmpn, pei_article_id);
        PeiCompCapTime(cmpn, msg->capt_start);
        PeiCompCapEndTime(cmpn, msg->capt_end);
        PeiCompAddFile(cmpn, "article", msg->file_data, 0);
        PeiCompAddStingBuff(cmpn, msg->multp_resp);
        if (msg->complete != TRUE)
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        PeiAddComponent(ppei, cmpn);
        break;

    case NNTP_CMD_BODY:
        PeiNewComponent(&cmpn, pei_body_id);
        PeiCompCapTime(cmpn, msg->capt_start);
        PeiCompCapEndTime(cmpn, msg->capt_end);
        PeiCompAddFile(cmpn, "body", msg->file_data, 0);
        if (msg->complete != TRUE)
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        PeiAddComponent(ppei, cmpn);
        break;

    case NNTP_CMD_HEAD:
        PeiNewComponent(&cmpn, pei_header_id);
        PeiCompCapTime(cmpn, msg->capt_start);
        PeiCompCapEndTime(cmpn, msg->capt_end);
        PeiCompAddStingBuff(cmpn, msg->multp_resp);
        if (msg->complete != TRUE)
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        PeiAddComponent(ppei, cmpn);
        break;
        
    case NNTP_CMD_POST:
    case NNTP_CMD_IHAVE:
    case NNTP_CMD_TAKETHIS:
        PeiNewComponent(&cmpn, pei_post_id);
        PeiCompAddFile(cmpn, "post message", msg->file_data, 0);
        PeiCompCapTime(cmpn, msg->capt_start);
        PeiCompCapEndTime(cmpn, msg->capt_end);
        if (msg->complete != TRUE)
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        PeiAddComponent(ppei, cmpn);
        break;

    case NNTP_CMD_GROUP:
        cmpn = PeiCompSearch(ppei, pei_grp_id);
        if (cmpn == NULL) {
            PeiNewComponent(&cmpn, pei_grp_id);
            PeiCompCapTime(cmpn, msg->capt_start);
            PeiCompCapEndTime(cmpn, msg->capt_end);
            grpname = DMemMalloc(NNTP_FILENAME_PATH_SIZE);
            strcpy(grpname, msg->cmd+5);
            tmp = strchr(grpname, '\r');
            if (tmp == NULL) {
                tmp = strchr(grpname, '\n');
            }
            if (tmp != NULL) {
                *tmp = '\0';
            }
            PeiCompAddStingBuff(cmpn, grpname);
            DMemFree(grpname);
            if (msg->complete != TRUE)
                PeiCompError(cmpn, ELMT_ER_PARTIAL);
            PeiAddComponent(ppei, cmpn);
        }
        else {
            PeiCompCapTime(cmpn, msg->capt_start);
            PeiCompCapEndTime(cmpn, msg->capt_end);
            grpname = DMemMalloc(NNTP_FILENAME_PATH_SIZE);
            strcpy(grpname, msg->cmd+5);
            tmp = strchr(grpname, '\r');
            if (tmp == NULL) {
                tmp = strchr(grpname, '\n');
            }
            if (tmp != NULL) {
                *tmp = '\0';
            }
            PeiCompAddStingBuff(cmpn, grpname);
            DMemFree(grpname);
            if (msg->complete != TRUE)
                PeiCompError(cmpn, ELMT_ER_PARTIAL);
            PeiCompUpdated(cmpn);
        }
        break;
        
    default:
        break;
    }

    return 0;
}


static int NntpCmd(nntp_msg *msg, packet *pkt)
{
    const char *end, *eol;
    char *lineend;
    int dim;
    bool new;

    msg->cmd = xrealloc(msg->cmd, msg->cmd_size + pkt->len + 1);
    memcpy(msg->cmd+msg->cmd_size, pkt->data, pkt->len);
    msg->cmd_size += pkt->len;
    msg->cmd[msg->cmd_size] = '\0';
    
    /* seach line and command */
    do {
        new = FALSE;
        end = msg->cmd + msg->cmd_size;
        lineend = (char *)find_line_end(msg->cmd, end, &eol);
        if (*eol == '\r' || *eol == '\n') {
            dim = lineend - msg->cmd;
            msg->cmdt = NntpCommand(msg->cmd, dim);
            if (msg->cmdt == NNTP_CMD_TAKETHIS) {
                msg->nxt = DMemMalloc(sizeof(nntp_msg));
                NntpMsgInit(msg->nxt);
                dim = msg->cmd_size - dim;
                memcpy(msg->data, lineend, dim);
                msg->dsize = dim;
                msg->data[msg->dsize] = '\0';
                NntpData(msg, NULL);
            }
            else if (msg->cmdt != NNTP_CMD_NONE) {
                msg->nxt = DMemMalloc(sizeof(nntp_msg));
                NntpMsgInit(msg->nxt);
                dim = msg->cmd_size - dim;
                /* copy cmd */
                if (dim > 0) {
                    msg->nxt->cmd = xmalloc(dim + 1);
                    memcpy(msg->nxt->cmd, lineend, dim);
                    lineend[0] = '\0';
                    msg->cmd_size = lineend - msg->cmd;
                    msg->nxt->cmd[dim] = '\0';
                    msg->nxt->cmd_size = dim;
                    new = TRUE;
                    msg = msg->nxt;
                }
            }
            else {
                /* possible auth continuation command */
                if (msg->auth_cont == TRUE) {
#if 0
                    msg->cmdt = NNTP_CMD_AUTH_CONT;
                    msg->nxt = DMemMalloc(sizeof(nntp_msg));
                    NntpMsgInit(msg->nxt);
                    dim = msg->cmd_size - dim;
                    /* copy cmd */
                    if (dim > 0) {
                        msg->nxt->cmd = xmalloc(dim + 1);
                        memcpy(msg->nxt->cmd, lineend, dim);
                        lineend[0] = '\0';
                        msg->cmd_size = lineend - msg->cmd;
                        msg->nxt->cmd[dim] = '\0';
                        msg->nxt->cmd_size = dim;
                        new = TRUE;
                        msg = msg->nxt;
                    }
#endif
                }
                else {
                    LogPrintf(LV_WARNING, "Command unknow");
                    //ProtStackFrmDisp(pkt->stk, TRUE);
                    //exit(-1);
                    return -1;
                }
            }
        }
    } while (new);

    return 0;
}


static int NntpData(nntp_msg *msg, packet *pkt)
{
    char *check, *end;
    int dim, scheck, cmp;

    scheck = 0;
    if (msg->dsize > 5)
        scheck = msg->dsize - 5;

    /* put data in buffer */
    if (pkt != NULL) {
        memcpy(msg->data+msg->dsize, pkt->data, pkt->len);
        msg->dsize += pkt->len;
        msg->data[msg->dsize] = '\0';
    }
    end = msg->data + msg->dsize;

#ifdef XPL_CHECK_CODE
    if (msg->dsize > sizeof(msg->data)) {
        LogPrintf(LV_OOPS, "Data buffer to small (%s)", __FUNCTION__);
        exit(-1);
    }
#endif

    /* search  <CR><LF>.<CR><LF> */
    cmp = 1;
    check = msg->data + scheck;
    check = memchr(check, '\r', end - check);
    while (check != NULL) {
        check++;
        cmp = memcmp(check, "\n.\r\n", 4); /* \r alredy verified */
        if (cmp == 0)
            break;
        check = memchr(check, '\r', end - check);
    }
    if (cmp == 0) {
        msg->complete = TRUE;
        dim = check - msg->data + 4;
        fwrite(msg->data, 1, dim-5, msg->fp_data);
        fclose(msg->fp_data);
        msg->fp_data = NULL;
        if (msg->dsize > dim) {
            /* pipeline */
            if (msg->nxt == NULL) {
                LogPrintf(LV_WARNING, "Reply whitout cmd");
                if (pkt != NULL)
                    ProtStackFrmDisp(pkt->stk, TRUE);
                return -1;
            }
            dim = msg->dsize - dim;
            msg->nxt->repl = xmalloc(dim + 1);
            memcpy(msg->nxt->repl, check+4, dim);
            msg->nxt->repl[dim] = '\0';
            msg->nxt->repl_size = dim;
            msg->data[0] = '\0';
            msg->dsize = 0;
            return NntpRpl(msg->nxt, NULL);
        }
        msg->data[0] = '\0';
        msg->dsize = 0;
    }
    else if (msg->dsize > NNTP_DATA_BUFFER) {
        dim = msg->dsize - 5;
        fwrite(msg->data, 1, dim, msg->fp_data);
        xmemcpy(msg->data, msg->data+dim, 5);
        msg->data[5] = '\0';
        msg->dsize = 5;
    }

    return 0;
}


static int NntpMuli(nntp_msg *msg, packet *pkt)
{
    char *check, *end;
    int dim, scheck, cmp;

    scheck = 0;
    if (msg->mlp_res_size > 5)
        scheck = msg->mlp_res_size - 5;

    /* put data in buffer */
    if (pkt != NULL) {
        msg->multp_resp = xrealloc(msg->multp_resp, msg->mlp_res_size + pkt->len + 1);
        memcpy(msg->multp_resp+msg->mlp_res_size, pkt->data, pkt->len);
        msg->mlp_res_size += pkt->len;
        msg->multp_resp[msg->mlp_res_size] = '\0';
    }
    end = msg->multp_resp + msg->mlp_res_size;

    /* search  <CR><LF>.<CR><LF> */
    cmp = 1;
    check = msg->multp_resp + scheck;
    check = memchr(check, '\r', end - check);
    while (check != NULL) {
        check++;
        cmp = memcmp(check, "\n.\r\n", 4); /* \r alredy verified */
        if (cmp == 0)
            break;
        check = memchr(check, '\r', end - check);
    }
    if (cmp == 0) {
        msg->complete = TRUE;
        dim = check - msg->multp_resp + 4;
        if (msg->mlp_res_size > dim) {
            /* pipeline */
            if (msg->nxt == NULL) {
                LogPrintf(LV_WARNING, "Reply whitout cmd");
                if (pkt != NULL)
                    ProtStackFrmDisp(pkt->stk, TRUE);
                return -1;
            }
            dim = msg->mlp_res_size - dim;
            msg->nxt->repl = xmalloc(dim + 1);
            memcpy(msg->nxt->repl, check+4, dim);
            msg->nxt->repl[dim] = '\0';
            msg->nxt->repl_size = dim;
            check[3] = '\0';
            return NntpRpl(msg->nxt, NULL);
        }
    }

    return 0;
}


static int NntpRpl(nntp_msg *msg, packet *pkt)
{
    const char *end, *eol, *repl;
    char *lineend;
    int dim;
    bool new;

    /* attach data */
    if (pkt != NULL) {
        msg->repl = xrealloc(msg->repl, msg->repl_size + pkt->len + 1);
        memcpy(msg->repl+msg->repl_size, pkt->data, pkt->len);
        msg->repl_size += pkt->len;
        msg->repl[msg->repl_size] = '\0';
    }

    /* seach line and command */
    end = msg->repl + msg->repl_size;
    repl = msg->repl;
    do {
        new = FALSE;
        lineend = (char *)find_line_end(repl, end, &eol);
        if (*eol == '\r' || *eol == '\n') {
            dim = lineend - repl;
            msg->st = NntpReply(repl, dim);
            repl = lineend;
            if (msg->st != NNTP_REP_NONE) {
                switch (msg->cmdt) {
                case NNTP_CMD_MODE: /* one line cmd */
                case NNTP_CMD_QUIT:
                case NNTP_CMD_GROUP:
                case NNTP_CMD_LAST:
                case NNTP_CMD_NEXT:
                case NNTP_CMD_STAT:
                case NNTP_CMD_DATE:
                case NNTP_CMD_CHECK:
                    msg->complete = TRUE;
                    break;

                case NNTP_CMD_CAPABILITIES: /* multiline cmd */
                case NNTP_CMD_HELP:
                case NNTP_CMD_NEWGROUPS:
                case NNTP_CMD_NEWNEWS:
                    dim = end - lineend;
                    msg->multp_resp = xmalloc(dim+1);
                    msg->multp_resp[dim] = '\0';
                    if (dim > 0) {
                        memcpy(msg->multp_resp, lineend, dim);
                        msg->mlp_res_size = dim;
                        lineend[0] = '\0';
                        return NntpMuli(msg, NULL);
                    }
                    break;
                    
                case NNTP_CMD_ARTICLE:
                    if (msg->st != NNTP_REP_220) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->data[dim] = '\0';
                    /* file path and name */
                    sprintf(msg->file_data, "%s/%s/nntp_%lld_%p_%i.eml", ProtTmpDir(), NNTP_TMP_DIR, (long long)time(NULL), msg, incr);
                    incr++;
                    /* open */
                    msg->fp_data = fopen(msg->file_data, "w");
                    if (msg->fp_data == NULL) {
                        LogPrintf(LV_ERROR, "Unable to open file %s", msg->file_data);
                        return -1;
                    }
                    if (dim > 0) {
                        memcpy(msg->data, lineend, dim);
                        msg->dsize = dim;
                        return NntpData(msg, NULL);
                    }
                    break;

                case NNTP_CMD_BODY:
                    if (msg->st != NNTP_REP_222) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->data[dim] = '\0';
                    /* file path and name */
                    sprintf(msg->file_data, "%s/%s/nntp_%lld_%p_%i.eml", ProtTmpDir(), NNTP_TMP_DIR, (long long)time(NULL), msg, incr);
                    incr++;
                    /* open */
                    msg->fp_data = fopen(msg->file_data, "w");
                    if (msg->fp_data == NULL) {
                        LogPrintf(LV_ERROR, "Unable to open file %s", msg->file_data);
                        return -1;
                    }
                    if (dim > 0) {
                        memcpy(msg->data, lineend, dim);
                        msg->dsize = dim;
                        return NntpData(msg, NULL);
                    }
                    break;
                    
                case NNTP_CMD_XHDR:
                case NNTP_CMD_HDR:
                    if (msg->st != NNTP_REP_225) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->multp_resp = xmalloc(dim+1);
                    msg->multp_resp[dim] = '\0';
                    if (dim > 0) {
                        memcpy(msg->multp_resp, lineend, dim);
                        msg->mlp_res_size = dim;
                        lineend[0] = '\0';
                        return NntpMuli(msg, NULL);
                    }
                    break;

                case NNTP_CMD_HEAD:
                    if (msg->st != NNTP_REP_221) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->multp_resp = xmalloc(dim+1);
                    msg->multp_resp[dim] = '\0';
                    if (dim > 0) {
                        memcpy(msg->multp_resp, lineend, dim);
                        msg->mlp_res_size = dim;
                        lineend[0] = '\0';
                        return NntpMuli(msg, NULL);
                    }
                    break;

                case NNTP_CMD_IHAVE:
                    if (msg->st != NNTP_REP_335) {
                        msg->complete = TRUE;
                        break;
                    }
                    if (msg->post == FALSE) {
                        msg->post = TRUE;
                        /* data file */
                        msg->data[0] = '\0';
                        /* file path and name */
                        sprintf(msg->file_data, "%s/%s/nntp_ihave%lld_%p_%i.eml", ProtTmpDir(), NNTP_TMP_DIR, (long long)time(NULL), msg, incr);
                        incr++;
                        /* open */
                        msg->fp_data = fopen(msg->file_data, "w");
                        if (msg->fp_data == NULL) {
                            LogPrintf(LV_ERROR, "Unable to open file %s", msg->file_data);
                            return -1;
                        }
                    }
                    else {
                        // it can be improved if we remove the response completed from msg->repl
                        new = TRUE;
                    }
                    break;

                case NNTP_CMD_LIST:
                    if (msg->st != NNTP_REP_215) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->multp_resp = xmalloc(dim+1);
                    msg->multp_resp[dim] = '\0';
                    if (dim > 0) {
                        memcpy(msg->multp_resp, lineend, dim);
                        msg->mlp_res_size = dim;
                        lineend[0] = '\0';
                        return NntpMuli(msg, NULL);
                    }
                    break;

                case NNTP_CMD_XGTITLE:
                    if (msg->st != NNTP_REP_282) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->multp_resp = xmalloc(dim+1);
                    msg->multp_resp[dim] = '\0';
                    if (dim > 0) {
                        memcpy(msg->multp_resp, lineend, dim);
                        msg->mlp_res_size = dim;
                        lineend[0] = '\0';
                        return NntpMuli(msg, NULL);
                    }
                    break;

                case NNTP_CMD_LISTGROUP:
                    if (msg->st != NNTP_REP_211) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->multp_resp = xmalloc(dim+1);
                    msg->multp_resp[dim] = '\0';
                    if (dim > 0) {
                        memcpy(msg->multp_resp, lineend, dim);
                        msg->mlp_res_size = dim;
                        lineend[0] = '\0';
                        return NntpMuli(msg, NULL);
                    }
                    break;
                    
                case NNTP_CMD_XOVER:
                case NNTP_CMD_OVER:
                    if (msg->st != NNTP_REP_224) {
                        msg->complete = TRUE;
                        break;
                    }
                    dim = end - lineend;
                    msg->multp_resp = xmalloc(dim+1);
                    msg->multp_resp[dim] = '\0';
                    if (dim > 0) {
                        memcpy(msg->multp_resp, lineend, dim);
                        msg->mlp_res_size = dim;
                        lineend[0] = '\0';
                        return NntpMuli(msg, NULL);
                    }
                    break;

                case NNTP_CMD_POST:
                    if (msg->st != NNTP_REP_340) {
                        msg->complete = TRUE;
                        break;
                    }
                    if (msg->post == FALSE) {
                        msg->post = TRUE;
                        /* data file */
                        msg->data[0] = '\0';
                        /* file path and name */
                        sprintf(msg->file_data, "%s/%s/nntp_post%lld_%p_%i.eml", ProtTmpDir(), NNTP_TMP_DIR, (long long)time(NULL), msg, incr);
                        incr++;
                        /* open */
                        msg->fp_data = fopen(msg->file_data, "w");
                        if (msg->fp_data == NULL) {
                            LogPrintf(LV_ERROR, "Unable to open file %s", msg->file_data);
                            return -1;
                        }
                    }
                    else {
                        // it can be improved if we remove the response completed from msg->repl
                        new = TRUE;
                    }
                    break;

                case NNTP_CMD_TAKETHIS:
                    msg->complete = TRUE;
                    break;
                    
                case NNTP_CMD_NONE:
                    if (msg->first)
                        msg->complete = TRUE;
                    else
                        return -1;
                    break;
#if INCOMPLETE == 0
                default:
                    break;
#endif
                }
            }
            else {
#if 0
                /* possible AUTH command */
                if (msg->cmdt == POP_CMD_AUTH || msg->cmdt == POP_CMD_AUTH_CONT) {
                    if (PopRespAuth(msg->repl, dim) == POP_ST_CONT) {
                        msg->nxt->auth_cont = TRUE;
                        msg->complete = TRUE;
                    }
                }
                else {
                    LogPrintf(LV_WARNING, "Reply status unknow");
                    if (pkt != NULL)
                        ProtStackFrmDisp(pkt->stk, TRUE);
                    return -1;
                }
#else
                LogPrintf(LV_WARNING, "Reply status unknow");
                if (pkt != NULL)
                    ProtStackFrmDisp(pkt->stk, TRUE);
                return -1;
#endif
            }
        }
    } while (new);

    return 0;
}


static int NntpConnec(int flow_id, nntp_priv *priv)
{
    packet *pkt;
    ftval lost;
    nntp_msg *clt_msg, *srv_msg, *tmp;
    nntp_msg *post_msg;
    pei *ppei;
    int ret;
    unsigned long serial;
    time_t cap_sec;

    /* setup */
    srv_msg = DMemMalloc(sizeof(nntp_msg));
    NntpMsgInit(srv_msg);
    clt_msg = DMemMalloc(sizeof(nntp_msg));
    NntpMsgInit(clt_msg);
    srv_msg->nxt = clt_msg;
    srv_msg->first = TRUE;
    ret = -1;
    
    post_msg = NULL;
    ppei = NULL;

    /* first tcp packet */
    pkt = FlowGetPkt(flow_id);
    do {
        if (pkt != NULL && pkt->len != 0) {
            /* check if there are packet lost */
            ProtGetAttr(pkt->stk, lost_id, &lost);
            //ProtStackFrmDisp(pkt->stk, TRUE);
            if (lost.uint8 == TRUE) {
                /* packet lost */
                ret = -1;
                break;
            }
            if (NntpClientPkt(priv, pkt)) {
                /* client */
                /* check if a post */
                if (post_msg != NULL) {
                    ret = NntpData(post_msg, pkt);
                }
                else {
                    ret = NntpCmd(clt_msg, pkt);
                    /* if post */
                    if (clt_msg->post) {
                        post_msg = clt_msg;
                    }
                }
                if (ret == 0) {
                    /* check pipeline cmd */
                    while (clt_msg->cmdt != NNTP_CMD_NONE) {
                        clt_msg->capt_start = pkt->cap_sec;
                        clt_msg = clt_msg->nxt;
                    }
                }
            }
            else {
                /* server */
                if (srv_msg->fp_data != NULL && srv_msg->post == FALSE) {
                    /* eml data */
                    ret = NntpData(srv_msg, pkt);
                    if (ret == 0) {
                        /* check pipeline cmd */
                        while (srv_msg->complete == TRUE) {
                            /* pei components insert */
                            srv_msg->capt_end = pkt->cap_sec;
#if NNTP_EN_PEI
                            if (ppei == NULL) {
                                PeiNew(&ppei, nntp_id);
                                PeiCapTime(ppei, srv_msg->capt_start);
                                PeiMarker(ppei, serial);
                                PeiStackFlow(ppei, priv->stack);
                                NntpPeiUrl(ppei, priv);
                                if (priv->grp != NULL) {
                                    NntpPei(ppei, priv->grp);
                                }
                            }
                            NntpPei(ppei, srv_msg);
                            if (srv_msg->cmdt == NNTP_CMD_ARTICLE || 
                                srv_msg->cmdt == NNTP_CMD_BODY) {
                                /* insert PEI */
                                PeiIns(ppei);
                                ppei = NULL;
                            }
#endif
                            /* next command */
                            tmp = srv_msg;
                            srv_msg = srv_msg->nxt;
                            tmp->nxt = NULL;
                            NntpMsgFree(tmp);
                        }
                    }
                }
                else if (srv_msg->multp_resp != NULL) {
                    /* multi line */
                    ret = NntpMuli(srv_msg, pkt);
                    if (ret == 0) {
                        /* check pipeline cmd */
                        while (srv_msg->complete == TRUE) {
                            /* pei components insert */
                            srv_msg->capt_end = pkt->cap_sec;
#if NNTP_EN_PEI
                            if (ppei == NULL) {
                                PeiNew(&ppei, nntp_id);
                                PeiCapTime(ppei, srv_msg->capt_start);
                                PeiMarker(ppei, serial);
                                PeiStackFlow(ppei, priv->stack);
                                NntpPeiUrl(ppei, priv);
                                if (priv->grp != NULL) {
                                    NntpPei(ppei, priv->grp);
                                }
                            }
                            NntpPei(ppei, srv_msg);
                            if (srv_msg->cmdt == NNTP_CMD_ARTICLE || 
                                srv_msg->cmdt == NNTP_CMD_BODY    ||
                                srv_msg->cmdt == NNTP_CMD_HEAD) {
                                /* insert PEI */
                                PeiIns(ppei);
                                ppei = NULL;
                            }
#endif
                            /* next command */
                            tmp = srv_msg;
                            srv_msg = srv_msg->nxt;
                            tmp->nxt = NULL;
                            NntpMsgFree(tmp);
                        }
                    }
                }
                else {
                    /* reply */
                    ret = NntpRpl(srv_msg, pkt);
                    if (ret == 0) {
                        /* if post */
                        if (srv_msg->post) {
                            post_msg = srv_msg;
                        }
                        /* check pipeline cmd */
                        while (srv_msg != NULL && srv_msg->complete == TRUE) {
                            /* pei components insert */
                            srv_msg->capt_end = pkt->cap_sec;
                            if (ppei == NULL) {
                                PeiNew(&ppei, nntp_id);
                                PeiCapTime(ppei, srv_msg->capt_start);
                                PeiMarker(ppei, serial);
                                PeiStackFlow(ppei, priv->stack);
                                NntpPeiUrl(ppei, priv);
                                if (priv->grp != NULL) {
                                    NntpPei(ppei, priv->grp);
                                }
                            }
                            NntpPei(ppei, srv_msg);
                            if (srv_msg->cmdt == NNTP_CMD_POST  ||
                                srv_msg->cmdt == NNTP_CMD_IHAVE ||
                                srv_msg->cmdt == NNTP_CMD_ARTICLE || 
                                srv_msg->cmdt == NNTP_CMD_BODY    ||
                                srv_msg->cmdt == NNTP_CMD_HEAD) {
                                /* insert PEI */
                                PeiIns(ppei);
                                ppei = NULL;
                                /* end post */
                                post_msg = NULL;
                            }
                            
                            /* next msg */
                            tmp = srv_msg;
                            srv_msg = srv_msg->nxt;
                            tmp->nxt = NULL;
                            if (tmp->cmdt == NNTP_CMD_GROUP) {
                                if (priv->grp != NULL) {
                                    NntpMsgFree(priv->grp);
                                }
                                priv->grp = tmp;
                            }
                            else {
                                NntpMsgFree(tmp);
                            }
#ifdef XPL_CHECK_CODE
                            if (srv_msg == NULL) {
                                LogPrintf(LV_ERROR, "No command message");
                            }
#endif
                        }
                    }
                }
            }
            if (ret == -1)
                break;
        }
        serial = pkt->serial;
        cap_sec = pkt->cap_sec;
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    } while (pkt != NULL);

    if (pkt != NULL)
        PktFree(pkt);

    /* incomplete message */
    while (srv_msg != NULL) {
#if NNTP_EN_PEI
        if (ppei == NULL) {
            PeiNew(&ppei, nntp_id);
            PeiCapTime(ppei, srv_msg->capt_start);
            PeiMarker(ppei, serial);
            PeiStackFlow(ppei, priv->stack);
            NntpPeiUrl(ppei, priv);
            if (priv->grp != NULL) {
                NntpPei(ppei, priv->grp);
            }
        }
        NntpPei(ppei, srv_msg);
        if (srv_msg->cmdt == NNTP_CMD_POST  ||
            srv_msg->cmdt == NNTP_CMD_IHAVE ||
            srv_msg->cmdt == NNTP_CMD_ARTICLE || 
            srv_msg->cmdt == NNTP_CMD_BODY    ||
            srv_msg->cmdt == NNTP_CMD_HEAD) {
            /* insert PEI */
            PeiIns(ppei);
            ppei = NULL;
        }

#endif
        /* next msg */
        tmp = srv_msg;
        srv_msg = srv_msg->nxt;
        tmp->nxt = NULL;
        NntpMsgFree(tmp);
    }
    /* last pei */
    if (ppei != NULL) {
        /* insert PEI */
        PeiIns(ppei);
        ppei = NULL;
    }
    
    return ret;
}


static packet* NntpDissector(int flow_id)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    nntp_priv *priv;
    packet *pkt;

    LogPrintf(LV_DEBUG, "NNTP id: %d", flow_id);
    priv = DMemMalloc(sizeof(nntp_priv));
    memset(priv, 0, sizeof(nntp_priv));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv->port_s = port_src.uint16;
    priv->port_d = port_dst.uint16;
    priv->dir = NNTP_CLT_DIR_NONE;
    priv->stack = tcp;
    if (priv->port_s != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    if (ProtFrameProtocol(ip) == ip_id)
        priv->ipv6 = FALSE;
    
    if (priv->ipv6 == FALSE) {
        ProtGetAttr(ip, ip_src_id, &priv->ip_s);
        ProtGetAttr(ip, ip_dst_id, &priv->ip_d);
        ip_addr.s_addr = priv->ip_s.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = priv->ip_d.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &priv->ip_d);
        memcpy(ipv6_addr.s6_addr, priv->ip_s.ipv6, sizeof(priv->ip_s.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, priv->ip_d.ipv6, sizeof(priv->ip_d.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);

    if (NntpConnec(flow_id, priv) != 0) {
        /* raw nntp file */
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }

    /* free memory */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "NNTP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool NntpVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    bool ipv4, client;
    ftval lost, ips, ip_s;
    bool ret, fr_data;
    char *data, *new;
    short verify_step; /* 0: none; 1: server presentation ok; 2: command client ok */
    int cmp;
    unsigned long len;
    const char *eol, *lineend;
    nntp_cmd cmd;
    nntp_repl rep;

    ipv4 = FALSE;
    client = TRUE; /* first packet without lost packet is a client packet */
    ret = FALSE;
    fr_data = FALSE;
    verify_step = 0;
    pkt = FlowGetPktCp(flow_id);

    if (pkt != NULL) {
        ip = ProtGetNxtFrame(pkt->stk);
        if (ProtFrameProtocol(ip) == ip_id)
            ipv4 = TRUE;
        if (ipv4 == TRUE)
            ProtGetAttr(ip, ip_src_id, &ips);
        else
            ProtGetAttr(ip, ipv6_src_id, &ips);

        ProtGetAttr(pkt->stk, lost_id, &lost);
        while (lost.uint8 == FALSE && pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL)
                break;
            ProtGetAttr(pkt->stk, lost_id, &lost);
        }
    }
    
    if (pkt != NULL && lost.uint8 == FALSE) {
        ip = ProtGetNxtFrame(pkt->stk);
        if (ipv4 == TRUE) {
            ProtGetAttr(ip, ip_src_id, &ip_s);
            cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
        }
        else {
            ProtGetAttr(ip, ipv6_src_id, &ip_s);
            cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
        }
        if (cmp != 0) {
            /* first packet (with data) is server packet */
            client = FALSE;
        }

        data = (char *)pkt->data;
        len = pkt->len;
        do {
            lineend = find_line_end(data, data+len, &eol);
            if (*eol == '\r' || *eol == '\n') {
                if (verify_step == 0 && client == FALSE) {
                    /* first step is verify server presentation */
                    rep = NntpReply(data, lineend-data);
                    if (rep == NNTP_REP_200 || rep == NNTP_REP_201) {
                        if (check == FALSE) {
                            ret = TRUE;
                            break;
                        }
                        verify_step = 1;
                    }
                    else {
                        break;
                    }
                }
                else if (verify_step == 1) {
                    if (client == TRUE) {
                        /* second step is verify command from client */
                        cmd = NntpCommand(data, lineend-data);
                        if (cmd != NNTP_CMD_NONE) {
                            if (cmd == NNTP_CMD_CAPABILITIES || cmd == NNTP_CMD_GROUP || cmd == NNTP_CMD_LISTGROUP ||
                                cmd == NNTP_CMD_NEWGROUPS || cmd == NNTP_CMD_MODE || cmd == NNTP_CMD_IHAVE || cmd == NNTP_CMD_XGTITLE) {
                                ret = TRUE;
                                break;
                            }
                        }
                        else {
                            break;
                        }
                    }
                }
                else {
                    break;
                }
            }
            if (fr_data == FALSE) {
                data = xmalloc(len+1);
                if (data == NULL) {
                    LogPrintf(LV_WARNING, "Memmory unavailable");
                    break;
                }
                fr_data = TRUE;
                memcpy(data, pkt->data, len);
                data[len] = '\0';
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt != NULL) {
                ip = ProtGetNxtFrame(pkt->stk);
                if (ipv4 == TRUE) {
                    ProtGetAttr(ip, ip_src_id, &ip_s);
                    cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
                }
                else {
                    ProtGetAttr(ip, ipv6_src_id, &ip_s);
                    cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
                }
                if (cmp == 0) {
                    /* client to server */
                    if (client == FALSE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                    if (lost.uint8 == FALSE) {
                        new = xrealloc(data, len+pkt->len+1);
                        if (new == NULL) {
                            LogPrintf(LV_WARNING, "Memmory unavailable");
                            break;
                        }
                        data = new;
                        memcpy(data+len, pkt->data, pkt->len);
                        len += pkt->len;
                        data[len] = '\0';
                    }
                    else {
                        PktFree(pkt);
                        pkt = NULL;
                    }
                    client = TRUE;
                }
                else {
                    /* server to client */
                    if (client == TRUE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                    if (lost.uint8 == FALSE) {
                        new = xrealloc(data, len+pkt->len+1);
                        if (new == NULL) {
                            LogPrintf(LV_WARNING, "Memmory unavailable");
                            break;
                        }
                        data = new;
                        memcpy(data+len, pkt->data, pkt->len);
                        len += pkt->len;
                        data[len] = '\0';
                    }
                    else {
                        PktFree(pkt);
                        pkt = NULL;
                    }
                    client = FALSE;
                }
            }
        } while (pkt != NULL && len < 1024); /* 1k: max nntp server presentation/helo length */

        /* free memory */
        if (data != NULL && fr_data == TRUE) {
            xfree(data);
        }
    }
    
    if (pkt != NULL)
        PktFree(pkt);

    return ret;
}


static bool NntpVerify(int flow_id)
{
    return NntpVerifyCheck(flow_id, FALSE);
}


static bool NntpCheck(int flow_id)
{
    return NntpVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));

    /* protocol name */
    ProtName("Network News Transfer Protocol", "nntp");
    
    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_NNTP;
    dep.ProtCheck = NntpVerify;
    dep.pktlim = NNTP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = NntpCheck;
    hdep.pktlim = NNTP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);

    peic.abbrev = "grp";
    peic.desc = "Group";
    ProtPeiComponent(&peic);

    peic.abbrev = "article";
    peic.desc = "Article";
    ProtPeiComponent(&peic);

    peic.abbrev = "header";
    peic.desc = "Header";
    ProtPeiComponent(&peic);

    peic.abbrev = "body";
    peic.desc = "Body";
    ProtPeiComponent(&peic);

    peic.abbrev = "post";
    peic.desc = "Post Article";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, NntpDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char nntp_dir[256];

    /* part of file name */
    incr = 0;
    
    /* protocols and attributes */
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    tcp_id = ProtId("tcp");
    port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    lost_id = ProtAttrId(tcp_id, "tcp.lost");
    clnt_id = ProtAttrId(tcp_id, "tcp.clnt");
    nntp_id = ProtId("nntp");

    /* pei id */
    pei_url_id = ProtPeiComptId(nntp_id, "url");
    pei_grp_id = ProtPeiComptId(nntp_id, "grp");
    pei_article_id = ProtPeiComptId(nntp_id, "article");
    pei_header_id = ProtPeiComptId(nntp_id, "header");
    pei_body_id = ProtPeiComptId(nntp_id, "body");
    pei_post_id = ProtPeiComptId(nntp_id, "post");

    /* nntp tmp directory */
    sprintf(nntp_dir, "%s/%s", ProtTmpDir(), NNTP_TMP_DIR);
    mkdir(nntp_dir, 0x01FF);

    return 0;
}
