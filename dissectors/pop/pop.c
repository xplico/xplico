/* pop.c
 * Dissector of POP protocol
 *
 * $Id: pop.c,v 1.11 2007/11/15 19:54:13 costa Exp $
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

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "pop.h"
#include "pei.h"


#define POP_TMP_DIR    "pop"

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int clnt_id;
static int pop_id;

/* pei id */
static int pei_user_id;
static int pei_pswd_id;
static int pei_eml_id;

static volatile unsigned int incr;

static int PopRpl(pop_msg *msg, packet *pkt);
static int PopMuli(pop_msg *msg, packet *pkt);


static void PopMsgInit(pop_msg *msg)
{
    memset(msg, 0, sizeof(pop_msg));
    msg->file_eml = DMemMalloc(POP_FILENAME_PATH_SIZE);
    msg->file_eml[0] = '\0';
    msg->cmdt = POP_CMD_NONE;
    msg->st = POP_ST_NONE;
    msg->fd_eml = -1;
    msg->auth_cont = FALSE;
}


static void PopMsgFree(pop_msg *msg)
{
    pop_msg *next, *tmp;

    next = msg;
    while (next != NULL) {
        if (next->file_eml != NULL) {
            if (next->file_eml[0] != '\0' && next->fd_eml != -1 && next->dsize != 0) {
                LogPrintf(LV_WARNING, "File '%s' dosn't insert in a PEI", next->file_eml);
            }
        }
        if (next->cmd != NULL)
            xfree(next->cmd);
        if (next->repl != NULL)
            xfree(next->repl);
        if (next->multp_resp != NULL) {
            xfree(next->multp_resp);
        }
        if (next->fd_eml != -1) {
            close(next->fd_eml);
            LogPrintf(LV_WARNING, "File '%s' not closed", next->file_eml);
        }
        if (next->file_eml != NULL) {
            DMemFree(next->file_eml);
        }
        tmp = next;
        next = next->nxt;
        DMemFree(tmp);
    }
}


static int PopUser(char *param, char **user)
{
    char *estart, *eend, *end;
    int dim;

    *user = NULL;
    end = param + strlen(param);

    estart = memchr(param, ' ', end - param);
    if (estart == NULL)
        return -1;
    estart++;

    eend =  memchr(estart, '\r', end - estart);
    if (eend == NULL)
        return -1;

    dim = eend - estart;
    *user = DMemMalloc(dim + 1);
    memcpy(*user, estart, dim);
    (*user)[dim] = '\0';
    
    return 0;
}


static int PopPassword(char *param, char **passwd)
{
    char *estart, *eend, *end;
    int dim;

    *passwd = NULL;
    end = param + strlen(param);

    estart = memchr(param, ' ', end - param);
    if (estart == NULL)
        return -1;
    estart++;

    eend =  memchr(estart, '\r', end - estart);
    if (eend == NULL)
        return -1;

    dim = eend - estart;
    *passwd = DMemMalloc(dim + 1);
    memcpy(*passwd, estart, dim);
    (*passwd)[dim] = '\0';
    
    return 0;
}


static int PopApop(char *param, char **user)
{
    char *estart, *eend, *end;
    int dim;

    *user = NULL;
    end = param + strlen(param);

    estart = memchr(param, ' ', end - param);
    if (estart == NULL)
        return -1;
    estart++;

    eend =  memchr(estart, ' ', end - estart);
    if (eend == NULL)
        return -1;

    dim = eend - estart;
    *user = DMemMalloc(dim + 1);
    memcpy(*user, estart, dim);
    (*user)[dim] = '\0';
    
    return 0;
}


static int PopPei(pei *ppei, pop_msg *msg)
{
    pei_component *cmpn, *last;
    int ind;

    /* capture time */
    if (ppei->time_cap == 0)
        ppei->time_cap = msg->capt_start;

    /* last component */
    ind = 0;
    last = ppei->components;
    while (last != NULL && last->next != NULL) {
        last = last->next;
        ind++;
    }
    if (last != NULL)
        ind++;

    cmpn = NULL;
    switch (msg->cmdt) {
    case POP_CMD_APOP:
        cmpn = DMemMalloc(sizeof(pei_component));
        memset(cmpn, 0, sizeof(pei_component));
        cmpn->eid = pei_user_id;
        cmpn->id = ind;
        cmpn->time_cap = msg->capt_start;
        cmpn->time_cap_end = msg->capt_end;
        PopApop(msg->cmd, &cmpn->strbuf);
        cmpn->next = DMemMalloc(sizeof(pei_component));
        memset(cmpn->next, 0, sizeof(pei_component));
        cmpn->next->eid = pei_pswd_id;
        cmpn->next->id = ind;
        cmpn->next->time_cap = msg->capt_start;
        cmpn->next->time_cap_end = msg->capt_end;
        cmpn->next->strbuf = DMemMalloc(strlen(POP_CRYPTED)+1);
        strcpy(cmpn->next->strbuf, POP_CRYPTED);
        break;

    case POP_CMD_USER:
        cmpn = DMemMalloc(sizeof(pei_component));
        memset(cmpn, 0, sizeof(pei_component));
        cmpn->eid = pei_user_id;
        cmpn->id = ind;
        cmpn->time_cap = msg->capt_start;
        cmpn->time_cap_end = msg->capt_end;
        PopUser(msg->cmd, &cmpn->strbuf);
        break;

    case POP_CMD_PASS:
        cmpn = DMemMalloc(sizeof(pei_component));
        memset(cmpn, 0, sizeof(pei_component));
        cmpn->eid = pei_pswd_id;
        cmpn->id = ind;
        cmpn->time_cap = msg->capt_start;
        cmpn->time_cap_end = msg->capt_end;
        PopPassword(msg->cmd, &cmpn->strbuf);
        break;

    case POP_CMD_RETR:
        cmpn = DMemMalloc(sizeof(pei_component));
        memset(cmpn, 0, sizeof(pei_component));
        cmpn->eid = pei_eml_id;
        cmpn->id = ind;
        cmpn->time_cap = msg->capt_start;
        cmpn->time_cap_end = msg->capt_end;
        if (msg->capt_end == 0) {
            /* incomplete msg */
            cmpn->err = ELMT_ER_PARTIAL;
        }
#ifdef XPL_CHECK_CODE
        if (msg->file_eml[0] == '\0') {
            LogPrintf(LV_ERROR, "File name not found (fun:%s)", __FUNCTION__);
        }
#endif
        cmpn->file_path = msg->file_eml;
        msg->file_eml = NULL;
        if (msg->fd_eml != -1) {
            cmpn->err = ELMT_ER_PARTIAL;
            close(msg->fd_eml);
            msg->fd_eml = -1;
        }
        break;
        
    default:
        break;
    }

    /* insert */
    if (last == NULL)
        ppei->components = cmpn;
    else
        last->next = cmpn;

    return 0;
}


static pop_cmd PopCommand(const char *line, int linelen)
{
    const char *next_token;
    const char *lineend;
    int index;

    lineend = line + linelen;

    index = get_token_len(line, lineend, &next_token);
    if (index == 0) {
        return POP_CMD_NONE;
    }
    
    switch (index) {
    case 3:
        if (strncasecmp(line, "TOP", index) == 0) {
            return POP_CMD_TOP;
        }
        break;

    case 4:
        if (strncasecmp(line, "APOP", index) == 0) {
            return POP_CMD_APOP;
        }
        else  if (strncasecmp(line, "DELE", index) == 0) {
            return POP_CMD_DELE;
        }
        else  if (strncasecmp(line, "LIST", index) == 0) {
            return POP_CMD_LIST;
        }
        else  if (strncasecmp(line, "NOOP", index) == 0) {
            return POP_CMD_NOOP;
        }
        else  if (strncasecmp(line, "PASS", index) == 0) {
            return POP_CMD_PASS;
        }
        else  if (strncasecmp(line, "QUIT", index) == 0) {
            return POP_CMD_QUIT;
        }
        else  if (strncasecmp(line, "RETR", index) == 0) {
            return POP_CMD_RETR;
        }
        else  if (strncasecmp(line, "RSET", index) == 0) {
            return POP_CMD_RSET;
        }
        else  if (strncasecmp(line, "STAT", index) == 0) {
            return POP_CMD_STAT;
        }
        else  if (strncasecmp(line, "UIDL", index) == 0) {
            return POP_CMD_UIDL;
        }
        else  if (strncasecmp(line, "USER", index) == 0) {
            return POP_CMD_USER;
        }
        else  if (strncasecmp(line, "CAPA", index) == 0) {
            return POP_CMD_CAPA;
        }
        else  if (strncasecmp(line, "STLS", index) == 0) {
            LogPrintf(LV_WARNING, "POP command STLS not supported.");
            return POP_CMD_STLS;
        }
        else  if (strncasecmp(line, "AUTH", index) == 0) {
            return POP_CMD_AUTH;
        }
        else  if (strncasecmp(line, "XTND", index) == 0) {
            return POP_CMD_XTND;
        }
        break;

    default:
        break;
    }

    return POP_CMD_NONE;
}


static pop_status PopRespStatus(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int index;

    lineend = line + len;

    index = get_token_len(line, lineend, &next_token);
    if (index != 0) {
        if (strncasecmp(line, "+OK", 3) == 0) {
            return POP_ST_OK;
        }
        else if (strncasecmp(line, "-ERR", 4) == 0) {
            return POP_ST_ERR;
        }
    }
    
    return POP_ST_NONE;
}


static pop_status PopRespAuth(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int index;

    lineend = line + len;

    index = get_token_len(line, lineend, &next_token);
    if (index != 0) {
       if (strncasecmp(line, "+ ", 2) == 0) {
            return POP_ST_CONT;
       }
    }
    
    return POP_ST_NONE;
}


static bool PopClientPkt(pop_con *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
#if 0
    ftval clnt;
#endif

#if 1
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port);
        if (port.uint16 == priv->port)
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
        if (FTCmp(&priv->ip, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }
#else
    ProtGetAttr(pkt->stk, clnt_id, &clnt);
    if (clnt.uint8)
        ret = TRUE;
    else
        ret = FALSE;
#endif
    
    return ret;
}


static int PopCmd(pop_msg *msg, packet *pkt)
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
            msg->cmdt = PopCommand(msg->cmd, dim);
            if (msg->cmdt != POP_CMD_NONE) {
                msg->nxt = DMemMalloc(sizeof(pop_msg));
                PopMsgInit(msg->nxt);
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
                    msg->cmdt = POP_CMD_AUTH_CONT;
                    msg->nxt = DMemMalloc(sizeof(pop_msg));
                    PopMsgInit(msg->nxt);
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
                    LogPrintf(LV_WARNING, "Command unknow");
                    //ProtStackFrmDisp(pkt->stk, TRUE);
                    return -1;
                }
            }
        }
    } while (new);

    return 0;
}


static int PopEml(pop_msg *msg, packet *pkt)
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
        write(msg->fd_eml, msg->data, dim-5);
        close(msg->fd_eml);
        msg->fd_eml = -1;
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
            return PopRpl(msg->nxt, NULL);
        }
        msg->data[0] = '\0';
        msg->dsize = 0;
    }
    else if (msg->dsize > POP_DATA_BUFFER) {
        dim = msg->dsize - 5;
        write(msg->fd_eml, msg->data, dim);
        xmemcpy(msg->data, msg->data+dim, 5);
        msg->data[5] = '\0';
        msg->dsize = 5;
    }

    return 0;
}


static int PopMuli(pop_msg *msg, packet *pkt)
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
            return PopRpl(msg->nxt, NULL);
        }
    }

    return 0;
}


static bool PopCmdOption(const char *cmd, int len)
{
    if (memchr(cmd, ' ', len) != NULL)
        return TRUE;
    return FALSE;
}


static int PopRpl(pop_msg *msg, packet *pkt)
{
    const char *end, *eol;
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
    do {
        new = FALSE;
        end = msg->repl + msg->repl_size;
        lineend = (char *)find_line_end(msg->repl, end, &eol);
        if (*eol == '\r' || *eol == '\n') {
            dim = lineend - msg->repl;
            msg->st = PopRespStatus(msg->repl, dim);
            if (msg->st != POP_ST_NONE) {
                if (msg->st == POP_ST_ERR)
                    msg->complete = TRUE;
                else {
                    switch (msg->cmdt) {
                    case POP_CMD_APOP: /* one line cmd */
                    case POP_CMD_DELE:
                    case POP_CMD_NOOP:
                    case POP_CMD_PASS:
                    case POP_CMD_QUIT:
                    case POP_CMD_RSET:
                    case POP_CMD_STAT:
                    case POP_CMD_USER:
                    case POP_CMD_STLS:
                    case POP_CMD_AUTH_CONT:
                        msg->complete = TRUE;
                        if (msg->cmdt == POP_CMD_AUTH_CONT) {
                            LogPrintf(LV_DEBUG, "Fine AUTH");
                            if (pkt != NULL)
                                ProtStackFrmDisp(pkt->stk, TRUE);
                        }
                        break;

                    case POP_CMD_CAPA: /* multiline cmd */
                    case POP_CMD_TOP:
                    case POP_CMD_XTND:
                    case POP_CMD_AUTH:
                        dim = end - lineend;
                        msg->multp_resp = xmalloc(dim+1);
                        msg->multp_resp[dim] = '\0';
                        if (dim > 0) {
                            memcpy(msg->multp_resp, lineend, dim);
                            msg->mlp_res_size = dim;
                            lineend[0] = '\0';
                            return PopMuli(msg, NULL);
                        }
                        break;

                    case POP_CMD_LIST: /* one or multiline cmd */
                    case POP_CMD_UIDL:
                        if (PopCmdOption(msg->cmd, msg->cmd_size) == TRUE) {
                            /* one line */
                            msg->complete = TRUE;
                        }
                        else {
                            /* multi line */
                            dim = end - lineend;
                            msg->multp_resp = xmalloc(dim+1);
                            msg->multp_resp[dim] = '\0';
                            if (dim > 0) {
                                memcpy(msg->multp_resp, lineend, dim);
                                msg->mlp_res_size = dim;
                                lineend[0] = '\0';
                                return PopMuli(msg, NULL);
                            }
                        }
                        break;

                    case POP_CMD_RETR:
                        dim = end - lineend;
                        msg->data[dim] = '\0';
                        /* file path and name */
                        sprintf(msg->file_eml, "%s/%s/pop_%lld_%p_%i.eml", ProtTmpDir(), POP_TMP_DIR, (long long)time(NULL), msg, incr);
                        incr++;
                        /* open */
                        msg->fd_eml = open(msg->file_eml, O_WRONLY | O_CREAT, 0x01B6);
                        if (msg->fd_eml == -1) {
                            LogPrintf(LV_ERROR, "Unable to open file %s", msg->file_eml);
                            return -1;
                        }
                        if (dim > 0) {
                            memcpy(msg->data, lineend, dim);
                            msg->dsize = dim;
                            return PopEml(msg, NULL);
                        }
                        break;

                    case POP_CMD_NONE:
                        if (msg->first)
                            msg->complete = TRUE;
                        else
                            return -1;
                        break;
                    }
                }
                dim = end - lineend;
                if (dim > 0) {
                    if (msg->nxt == NULL) {
                        LogPrintf(LV_WARNING, "Reply without command");
                        if (pkt != NULL)
                            ProtStackFrmDisp(pkt->stk, TRUE);
                        return -1;
                    }
                    /* attach data */
                    msg->nxt->repl = xmalloc(dim + 1);
                    memcpy(msg->nxt->repl, lineend, dim);
                    lineend[0] = '\0';
                    msg->repl_size = lineend - msg->repl;
                    msg->nxt->repl_size = dim;
                    msg->nxt->repl[dim] = '\0';
                    msg = msg->nxt;
                    new = TRUE;
                }
            }
            else {
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
            }
        }
    } while (new);

    return 0;
}


static int PopEmail(int flow_id, pop_con *priv)
{
    packet *pkt;
    ftval lost;
    pop_msg *clt_msg, *srv_msg, *tmp;
    pei *ppei;
    int ret;
    unsigned long serial;

    /* setup */
    srv_msg = DMemMalloc(sizeof(pop_msg));
    PopMsgInit(srv_msg);
    clt_msg = DMemMalloc(sizeof(pop_msg));
    PopMsgInit(clt_msg);
    srv_msg->nxt = clt_msg;
    srv_msg->first = TRUE;
    ret = -1;

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
            if (PopClientPkt(priv, pkt)) {
                /* client */
                ret = PopCmd(clt_msg, pkt);
                if (ret == 0) {
                    /* check pipeline cmd */
                    while (clt_msg->cmdt != POP_CMD_NONE) {
                        clt_msg->capt_start = pkt->cap_sec;
                        clt_msg = clt_msg->nxt;
                    }
                }
            }
            else {
                /* server */
                if (srv_msg->fd_eml != -1) {
                    /* eml data */
                    ret = PopEml(srv_msg, pkt);
                    if (ret == 0) {
                        /* check pipeline cmd */
                        while (srv_msg->complete == TRUE) {
                            /* pei components insert */
                            srv_msg->capt_end = pkt->cap_sec;
                            if (ppei == NULL) {
                                ppei = DMemMalloc(sizeof(pei));
                                PeiInit(ppei);
                                ppei->prot_id = pop_id;
                                ppei->serial = pkt->serial;
                                ppei->stack = ProtCopyFrame(priv->stack, TRUE);
                                //ProtStackFrmDisp(ppei->stack, TRUE);
                                if (priv->user != NULL) {
                                    PopPei(ppei, priv->user);
                                }
                                if (priv->passwd != NULL) {
                                    PopPei(ppei, priv->passwd);
                                }
                            }
                            PopPei(ppei, srv_msg);
                            if (srv_msg->cmdt == POP_CMD_RETR) {
                                /* insert PEI */
                                PeiIns(ppei);
                                ppei = NULL;
                            }
                            /* next command */
                            tmp = srv_msg;
                            srv_msg = srv_msg->nxt;
                            tmp->nxt = NULL;
                            PopMsgFree(tmp);
                        }
                    }
                }
                else if (srv_msg->multp_resp != NULL) {
                    /* multi line */
                    ret = PopMuli(srv_msg, pkt);
                    if (ret == 0) {
                        /* check pipeline cmd */
                        while (srv_msg->complete == TRUE) {
                            /* pei components insert */
                            srv_msg->capt_end = pkt->cap_sec;
                            if (ppei == NULL) {
                                ppei = DMemMalloc(sizeof(pei));
                                PeiInit(ppei);
                                ppei->prot_id = pop_id;
                                ppei->serial = pkt->serial;
                                ppei->stack = ProtCopyFrame(priv->stack, TRUE);
                                //ProtStackFrmDisp(ppei->stack, TRUE);
                                if (priv->user != NULL) {
                                    PopPei(ppei, priv->user);
                                }
                                if (priv->passwd != NULL) {
                                    PopPei(ppei, priv->passwd);
                                }
                            }
                            PopPei(ppei, srv_msg);
                            /* next command */
                            tmp = srv_msg;
                            srv_msg = srv_msg->nxt;
                            tmp->nxt = NULL;
                            PopMsgFree(tmp);
                        }
                    }
                }
                else {
                    /* reply */
                    ret = PopRpl(srv_msg, pkt);
                    if (ret == 0) {
                        /* check pipeline cmd */
                        while (srv_msg != NULL && srv_msg->complete == TRUE) {
                            /* pei components insert */
                            srv_msg->capt_end = pkt->cap_sec;
                            if (ppei == NULL) {
                                ppei = DMemMalloc(sizeof(pei));
                                PeiInit(ppei);
                                ppei->prot_id = pop_id;
                                ppei->serial = pkt->serial;
                                ppei->stack = ProtCopyFrame(priv->stack, TRUE);
                                //ProtStackFrmDisp(ppei->stack, TRUE);
                                if (priv->user != NULL) {
                                    PopPei(ppei, priv->user);
                                }
                                if (priv->passwd != NULL) {
                                    PopPei(ppei, priv->passwd);
                                }
                            }
                            if (srv_msg->cmdt == POP_CMD_USER && srv_msg->st == POP_ST_OK) {
                                /* user name */
                                priv->user = srv_msg;
                                PopPei(ppei, srv_msg);
                                tmp = srv_msg;
                                srv_msg = srv_msg->nxt;
                                tmp->nxt = NULL;
                            }
                            else if (srv_msg->cmdt == POP_CMD_PASS && srv_msg->st == POP_ST_OK) {
                                /* password */
                                priv->passwd = srv_msg;
                                PopPei(ppei, srv_msg);
                                tmp = srv_msg;
                                srv_msg = srv_msg->nxt;
                                tmp->nxt = NULL;
                            }
                            else if (srv_msg->cmdt == POP_CMD_APOP && srv_msg->st == POP_ST_OK) {
                                /* username and password */
                                priv->user = srv_msg;
                                PopPei(ppei, srv_msg);
                                tmp = srv_msg;
                                srv_msg = srv_msg->nxt;
                                tmp->nxt = NULL;
                            }
                            else {
                                PopPei(ppei, srv_msg);
                                /* next msg */
                                tmp = srv_msg;
                                srv_msg = srv_msg->nxt;
                                tmp->nxt = NULL;
                                PopMsgFree(tmp);
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
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    } while (pkt != NULL);

    if (pkt != NULL)
        PktFree(pkt);

    /* incomplete message */
    while (srv_msg != NULL) {
        if (ppei == NULL) {
            ppei = DMemMalloc(sizeof(pei));
            PeiInit(ppei);
            ppei->prot_id = pop_id;
            ppei->serial = serial;
            ppei->stack = ProtCopyFrame(priv->stack, TRUE);
            //ProtStackFrmDisp(ppei->stack, TRUE);
            if (priv->user != NULL) {
                PopPei(ppei, priv->user);
            }
            if (priv->passwd != NULL) {
                PopPei(ppei, priv->passwd);
            }
        }
        if (srv_msg->cmdt == POP_CMD_RETR && srv_msg->file_eml[0] == '\0') {
            /* file name */
            sprintf(srv_msg->file_eml, "%s/%s/pop_%lld_%p_%i.eml", ProtTmpDir(), POP_TMP_DIR, (long long)time(NULL), srv_msg, incr);
            incr++;
        }
        PopPei(ppei, srv_msg);
        if (srv_msg->cmdt == POP_CMD_RETR) {
            /* insert PEI */
            PeiIns(ppei);
            ppei = NULL;
        }
        /* next msg */
        tmp = srv_msg;
        srv_msg = srv_msg->nxt;
        tmp->nxt = NULL;
        PopMsgFree(tmp);
    }
    /* last pei */
    if (ppei != NULL) {
        /* insert PEI */
        PeiIns(ppei);
        ppei = NULL;
    }

    /* free user & passw msg */
    if (priv->user != NULL) {
        PopMsgFree(priv->user);
        priv->user = NULL;
    }
    if (priv->passwd != NULL) {
        PopMsgFree(priv->passwd);
        priv->passwd = NULL;
    }

    return ret;
}


packet* PopDissector(int flow_id)
{
    packet* pkt;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, ip_dst;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    pop_con *priv;

    LogPrintf(LV_DEBUG, "POP id: %d", flow_id);

    priv = DMemMalloc(sizeof(pop_con));
    memset(priv, 0, sizeof(pop_con));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv->port = port_src.uint16;
    priv->ipv6 = FALSE;
    priv->stack = tcp;
    if (ProtFrameProtocol(ip) == ipv6_id)
        priv->ipv6 = TRUE;
    if (priv->ipv6 == FALSE) {
        ProtGetAttr(ip, ip_src_id, &priv->ip);
        ProtGetAttr(ip, ip_dst_id, &ip_dst);
        ip_addr.s_addr = priv->ip.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = ip_dst.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip);
        ProtGetAttr(ip, ipv6_dst_id, &ip_dst);
        memcpy(ipv6_addr.s6_addr, priv->ip.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, ip_dst.ipv6, sizeof(ip_dst.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    if (port_src.uint16 != port_dst.uint16) {
        priv->port_diff = TRUE;
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
    
    if (PopEmail(flow_id, priv) != 0) {
        /* raw pop file */
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }

    /* free memory */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "POP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool PopVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    char *data, *new;
    const char *eol, *lineend;
    unsigned long len;
    int cmp;
    bool ret, fr_data;
    ftval lost, ips, ip_s;
    bool ipv4, client;
    short verify_step; /* 0: none; 1: server presentation ok; 2: client ok */
    pop_cmd cmd;

    ipv4 = FALSE;
    client = TRUE; /* fist packet whitout lost packet is a client packet */
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
        if (cmp != 0) {
            /* first packet (with data) is server packet */
            client = FALSE;
        }

        if (lost.uint8 == FALSE) {
            data = (char *)pkt->data;
            len = pkt->len;
            do {
                lineend = find_line_end(data, data+len, &eol);
                if (*eol == '\r' || *eol == '\n') {
                    if (verify_step == 0 && client == FALSE) {
                        /* first step is verify server presentation */
                        if (PopRespStatus(data, lineend-data) != POP_ST_NONE) {
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
                    else if (verify_step == 1 && client == TRUE) {
                        /* second step is verify command from client */
                        cmd = PopCommand(data, lineend-data);
                        if (cmd != POP_CMD_NONE) {
                            ret = TRUE;
                        }
                        break;
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
            } while (pkt != NULL && len < 1024); /* 1k: max smtp server presentation/helo length */

            /* free memory */
            if (data != NULL && fr_data == TRUE) {
                xfree(data);
            }
        }
        
        if (pkt != NULL)
            PktFree(pkt);
    }
    
    return ret;
}


static bool PopVerify(int flow_id)
{
    return PopVerifyCheck(flow_id, FALSE);
}


static bool PopCheck(int flow_id)
{
    return PopVerifyCheck(flow_id, TRUE);
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
    ProtName("Post Office Protocol", "pop");

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_POP;
    dep.ProtCheck = PopVerify;
    dep.pktlim = POP_PKT_VER_LIMIT;
    ProtDep(&dep);
   
    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = PopCheck;
    hdep.pktlim = POP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "user";
    peic.desc = "User name";
    ProtPeiComponent(&peic);

    peic.abbrev = "password";
    peic.desc = "Password";
    ProtPeiComponent(&peic);

    peic.abbrev = "eml";
    peic.desc = "MIME type";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, PopDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    int tcp_id;
    char pop_dir[256];

    /* part of file name */
    incr = 0;

    /* info id */
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
    pop_id = ProtId("pop");

    /* pei id */
    pei_user_id = ProtPeiComptId(pop_id, "user");
    pei_pswd_id = ProtPeiComptId(pop_id, "password");
    pei_eml_id = ProtPeiComptId(pop_id, "eml");

    /* pop tmp directory */
    sprintf(pop_dir, "%s/%s", ProtTmpDir(), POP_TMP_DIR);
    mkdir(pop_dir, 0x01FF);

    return 0;
}
