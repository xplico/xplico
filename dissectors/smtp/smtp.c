/* smtp.c
 * Dissector of SMTP protocol
 *
 * $Id: smtp.c,v 1.8 2007/09/08 07:15:45 costa Exp $
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
#include <ctype.h>
#include <time.h>

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "smtp.h"
#include "pei.h"


#define SMTP_TMP_DIR    "smtp"

/* info id */
static int ip_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int clnt_id;
static int smtp_id;

/* pei id */
static int pei_to_id;
static int pei_from_id;
static int pei_eml_id;

static volatile unsigned int incr;


static void SmtpMsgInit(smtp_msg *msg)
{
    memset(msg, 0, sizeof(smtp_msg));
    msg->file_eml = DMemMalloc(SMTP_FILENAME_PATH_SIZE);
    msg->file_eml[0] = '\0';
    msg->cmdt = SMTP_CMD_NONE;
    msg->st = SMTP_ST_NONE;
    msg->fd_eml = -1;
    msg->err = FALSE;
    msg->auth_cont = FALSE;
}


static void SmtpMsgFree(smtp_msg *msg)
{
    smtp_msg *next, *tmp;

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


static int SmtpEmailAddr(char *param, char **email)
{
    char *estart, *eend, *end;
    int dim;

    *email = NULL;
    end = param + strlen(param);

    estart = memchr(param, '<', end - param);
    if (estart == NULL)
        return -1;
    estart++;

    eend =  memchr(estart, '>', end - estart);
    if (eend == NULL)
        return -1;

    dim = eend - estart;
    *email = DMemMalloc(dim + 1);
    memcpy(*email, estart, dim);
    (*email)[dim] = '\0';
    
    return 0;
}


static int SmtpPei(pei *ppei, smtp_msg *msg)
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
    case SMTP_CMD_MAIL:
        cmpn = DMemMalloc(sizeof(pei_component));
        memset(cmpn, 0, sizeof(pei_component));
        cmpn->eid = pei_from_id;
        cmpn->id = ind;
        cmpn->time_cap = msg->capt_start;
        cmpn->time_cap_end = msg->capt_end;
        if (msg->err) {
            cmpn->err = ELMT_ER_PARTIAL;
        }
        SmtpEmailAddr(msg->cmd, &cmpn->strbuf);
        break;

    case SMTP_CMD_RCPT:
        cmpn = DMemMalloc(sizeof(pei_component));
        memset(cmpn, 0, sizeof(pei_component));
        cmpn->eid = pei_to_id;
        cmpn->id = ind;
        cmpn->time_cap = msg->capt_start;
        cmpn->time_cap_end = msg->capt_end;
        if (msg->err) {
            cmpn->err = ELMT_ER_PARTIAL;
        }
        SmtpEmailAddr(msg->cmd, &cmpn->strbuf);
        break;

    case SMTP_CMD_NONE:
        if (msg->first == FALSE) {
#ifdef XPL_CHECK_CODE
            if (msg->file_eml[0] == '\0' && msg->err == FALSE && msg->st == SMTP_ST_2XX) {
                LogPrintf(LV_OOPS, "File name not found (fun:%s)", __FUNCTION__);
            }
#endif
            if (msg->file_eml[0] != '\0') {
                cmpn = DMemMalloc(sizeof(pei_component));
                memset(cmpn, 0, sizeof(pei_component));
                cmpn->eid = pei_eml_id;
                cmpn->id = ind;
                cmpn->time_cap = msg->capt_start;
                cmpn->time_cap_end = msg->capt_end;
                
                cmpn->file_path = msg->file_eml;
                msg->file_eml = NULL;
                if (msg->fd_eml != -1) {
                    cmpn->err = ELMT_ER_PARTIAL;
                    close(msg->fd_eml);
                    msg->fd_eml = -1;
                }
                if (msg->err) {
                    cmpn->err = ELMT_ER_PARTIAL;
                }
            }
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


static smtp_cmd SmtpCommand(const char *line, int linelen)
{
    const char *next_token;
    const char *lineend;
    int index;

    lineend = line + linelen;

    index = get_token_len(line, lineend, &next_token);
    if (index == 0) {
        return SMTP_CMD_NONE;
    }
    
    switch (index) {
    case 4:
        if (strncasecmp(line, "HELO", index) == 0) {
            return SMTP_CMD_HELO;
        }
        else  if (strncasecmp(line, "EHLO", index) == 0) {
            return SMTP_CMD_EHLO;
        }
        else  if (strncasecmp(line, "MAIL", index) == 0) {
            return SMTP_CMD_MAIL;
        }
        else  if (strncasecmp(line, "RCPT", index) == 0) {
            return SMTP_CMD_RCPT;
        }
        else  if (strncasecmp(line, "DATA", index) == 0) {
            return SMTP_CMD_DATA;
        }
        else  if (strncasecmp(line, "RSET", index) == 0) {
            return SMTP_CMD_RSET;
        }
        else  if (strncasecmp(line, "SEND", index) == 0) {
            return SMTP_CMD_SEND;
        }
        else  if (strncasecmp(line, "SOML", index) == 0) {
            return SMTP_CMD_SOML;
        }
        else  if (strncasecmp(line, "SAML", index) == 0) {
            return SMTP_CMD_SAML;
        }
        else  if (strncasecmp(line, "VRFY", index) == 0) {
            return SMTP_CMD_VRFY;
        }
        else  if (strncasecmp(line, "EXPN", index) == 0) {
            return SMTP_CMD_EXPN;
        }
        else  if (strncasecmp(line, "HELP", index) == 0) {
            return SMTP_CMD_HELP;
        }
        else  if (strncasecmp(line, "NOOP", index) == 0) {
            return SMTP_CMD_NOOP;
        }
        else  if (strncasecmp(line, "QUIT", index) == 0) {
            return SMTP_CMD_QUIT;
        }
        else  if (strncasecmp(line, "TURN", index) == 0) {
            return SMTP_CMD_TURN;
        }
        else  if (strncasecmp(line, "AUTH", index) == 0) {
            return SMTP_CMD_AUTH;
        }
        else  if (strncasecmp(line, "BDAT", index) == 0) {
#warning "to complete"
            LogPrintf(LV_WARNING, "Command BDAT not supported");
            //return SMTP_CMD_BDAT;
        }
        break;
        
    case 8:
        if (strncasecmp(line, "STARTTLS", index) == 0) {
#warning "to complete"
            LogPrintf(LV_WARNING, "Command STARTTLS not supported");
            //return SMTP_CMD_STARTTLS;
        }
        break;

    default:
        break;
    }

    return SMTP_CMD_NONE;
}


static smtp_status SmtpRespStatus(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int index, num;

    lineend = line + len;
    index = get_token_len(line, lineend, &next_token);
    if (index == 3 && line[index] == ' ') {
        num = atoi(line);
        if (num >= 200 && num < 280)
            return SMTP_ST_2XX;
        if (num >= 300 && num < 380)
            return SMTP_ST_3XX;
        else if (num >= 400 && num < 480)
            return SMTP_ST_4XX;
        else if (num >= 500 && num < 580)
            return SMTP_ST_5XX;
    }

    return SMTP_ST_NONE;
}


static bool SmtpClientPkt(smtp_con *priv, packet *pkt)
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


static int SmtpData(smtp_msg *msg, packet *pkt)
{
    char *check, *end;
    int dim, scheck, cmp;

    scheck = 0;

    /* put data in buffer */
    if (pkt != NULL) {
        memcpy(msg->data+msg->dsize, pkt->data, pkt->len);
        if (msg->dsize > 5)
            scheck = msg->dsize - 5;
        msg->dsize += (pkt->len);
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
        dim = check - msg->data + 4;
        write(msg->fd_eml, msg->data, dim-5);
        close(msg->fd_eml);
        msg->fd_eml = -1;
        if (msg->dsize > dim) {
            msg->nxt = DMemMalloc(sizeof(smtp_msg));
            SmtpMsgInit(msg->nxt);
            dim = msg->dsize - dim;
            msg->nxt->cmd = xmalloc(dim + 1);
            memcpy(msg->nxt->cmd, check+4, dim);
            msg->nxt->cmd[dim] = '\0';
            msg->nxt->cmd_size = dim;
        }
        msg->data[0] = '\0';
        msg->dsize = 0;

    }
    else if (msg->dsize > SMTP_DATA_BUFFER) {
        dim = msg->dsize - 5;
        write(msg->fd_eml, msg->data, dim);
        xmemcpy(msg->data, msg->data+dim, 5);
        msg->data[5] = '\0';
        msg->dsize = 5;
    }

    return 0;
}


static int SmtpCmd(smtp_msg *msg, packet *pkt)
{
    const char *end, *eol;
    char *lineend;
    int dim;
    bool new;
    int ret;

    /* attach data */
    if (pkt != NULL) {
        msg->cmd = xrealloc(msg->cmd, msg->cmd_size + pkt->len + 1);
        memcpy(msg->cmd+msg->cmd_size, pkt->data, pkt->len);
        msg->cmd_size += pkt->len;
        msg->cmd[msg->cmd_size] = '\0';
    }

    /* seach line and command */
    do {
        new = FALSE;
        end = msg->cmd + msg->cmd_size;
        lineend = (char *)find_line_end(msg->cmd, end, &eol);
        if (*eol == '\r' || *eol == '\n') {
            dim = lineend - msg->cmd;
            msg->cmdt = SmtpCommand(msg->cmd, dim);
            if (msg->cmdt != SMTP_CMD_NONE) {
                msg->nxt = DMemMalloc(sizeof(smtp_msg));
                SmtpMsgInit(msg->nxt);
                dim = msg->cmd_size - dim;
                if (msg->cmdt != SMTP_CMD_DATA) {
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
                    /* file path and name */
                    sprintf(msg->nxt->file_eml, "%s/%s/smtp_%lld_%p_%i.eml", ProtTmpDir(), SMTP_TMP_DIR,
                            (long long)time(NULL), msg->nxt, incr);
                    incr++;

                    /* open */
                    msg->nxt->fd_eml = open(msg->nxt->file_eml, O_WRONLY | O_CREAT, 0x01B6);
                    if (msg->nxt->fd_eml == -1) {
                        LogPrintf(LV_ERROR, "Unable to open file %s", msg->nxt->file_eml);
                        return -1;
                    }

                    /* put data */
                    if (dim > 0) {
                        /* put data in buffer */
                        memcpy(msg->nxt->data, lineend, dim);
                        msg->nxt->dsize = dim;
                        msg->nxt->data[msg->nxt->dsize] = '\0';
                        /* close old cmd */
                        lineend[0] = '\0';
                        msg->cmd_size = lineend - msg->cmd;
                        /* msg Data */
                        msg = msg->nxt;
                        /* parse data */
                        ret = SmtpData(msg, NULL);
                        if (ret == 0) {
                            if (msg->fd_eml == -1) {
                                /* data completed */
                                if (msg->nxt == NULL) {
                                    msg->nxt = DMemMalloc(sizeof(smtp_msg));
                                    SmtpMsgInit(msg->nxt);
                                }
                                else {
                                    /* after data there is a new command in pipeline */
                                    ret = SmtpCmd(msg->nxt, NULL);
                                    if (ret != 0) {
                                        return -1;
                                    }
                                }
                            }
                        }
                        else {
                            return -1;
                        }
                    }
                }
            }
            else {
                if (msg->auth_cont) {
                    /* AUTH continuation command */
                    msg->cmdt = SMTP_CMD_AUTH_CONT;
                    msg->nxt = DMemMalloc(sizeof(smtp_msg));
                    SmtpMsgInit(msg->nxt);
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
                    LogPrintf(LV_WARNING, "Command unknown");
                    return -1;
                }
            }
        }
    } while (new);

    return 0;
}


static int SmtpRpl(smtp_msg *msg, packet *pkt)
{
    const char *end, *eol, *line;
    char *lineend;
    int dim;
    bool new;

    /* attach data */
    msg->repl = xrealloc(msg->repl, msg->repl_size + pkt->len + 1);
    memcpy(msg->repl+msg->repl_size, pkt->data, pkt->len);
    msg->repl_size += pkt->len;
    msg->repl[msg->repl_size] = '\0';

    /* seach line and command */
    do {
        new = FALSE;
        end = msg->repl + msg->repl_size;
        lineend = (char *)find_line_end(msg->repl, end, &eol);
        if (*eol == '\r' || *eol == '\n') {
            dim = lineend - msg->repl;
            msg->st = SmtpRespStatus(msg->repl, dim);
            if (msg->st == SMTP_ST_NONE) {
                /* multiply response */
                line = msg->repl;
                while (msg->st == SMTP_ST_NONE) {
                    if (line[3] != '-') {
                        LogPrintf(LV_WARNING, "Reply unknow");
                        /*printf("%s\n", msg->repl);*/
                        return -1;
                    }
                    /* data to examine */
                    dim = end - lineend;
                    if (dim == 0) {
                        /* not new line */
                        break;
                    }
                    line = lineend;
                    lineend = (char *)find_line_end(line, end, &eol);
                    if (*eol == '\r' || *eol == '\n') {
                        dim = lineend - line;
                        msg->st = SmtpRespStatus(line, dim);
                    }
                    else {
                        /* line incomplete, wait next tcp pkt */
                        break;
                    }
                }
            }

            if (msg->st != SMTP_ST_NONE) {
                dim = end - lineend;
                if (dim > 0) {
                    if (msg->nxt == NULL) {
                        LogPrintf(LV_WARNING, "Reply without command");
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
        }
    } while (new);

    return 0;
}

static int SmtpEmail(int flow_id, smtp_con *priv)
{
    packet *pkt;
    ftval lost;
    smtp_msg *clt_msg, *srv_msg, *tmp;
    pei *ppei;
    int ret;

    /* setup */
    srv_msg = DMemMalloc(sizeof(smtp_msg));
    SmtpMsgInit(srv_msg);
    clt_msg = DMemMalloc(sizeof(smtp_msg));
    SmtpMsgInit(clt_msg);
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
            if (SmtpClientPkt(priv, pkt)) {
                /* client */
                if (clt_msg->fd_eml == -1) {
                    /* new command */
                    ret = SmtpCmd(clt_msg, pkt);
                    if (ret == 0) {
                        while (clt_msg->cmdt != SMTP_CMD_NONE) {
                            clt_msg->capt_start = pkt->cap_sec;
                            if (clt_msg->cmdt == SMTP_CMD_DATA) {
                                if (clt_msg->nxt->fd_eml == -1) {
                                    clt_msg = clt_msg->nxt;
                                }
                            }
                            clt_msg = clt_msg->nxt;
                        }
                    }
                }
                else {
                    /* data */
                    ret = SmtpData(clt_msg, pkt);
                    if (ret == 0) {
                        if (clt_msg->fd_eml == -1) {
                            /* data completed */
                            if (clt_msg->nxt == NULL) {
                                clt_msg->nxt = DMemMalloc(sizeof(smtp_msg));
                                SmtpMsgInit(clt_msg->nxt);
                                clt_msg = clt_msg->nxt;
                            }
                            else {
                                /* after data there is a new command in pipeline */
                                clt_msg = clt_msg->nxt;
                                ret = SmtpCmd(clt_msg, NULL);
                                if (ret == 0) {
                                    while (clt_msg->cmdt != SMTP_CMD_NONE) {
                                        clt_msg->capt_start = pkt->cap_sec;
                                        clt_msg = clt_msg->nxt;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else {
                /* server */
                ret = SmtpRpl(srv_msg, pkt);
                if (ret == 0) {
                    /* pipeline response */
                    do {
                        srv_msg->capt_end = pkt->cap_sec;
                        /* verify a response of DATA command */
                        if (srv_msg->cmdt == SMTP_CMD_DATA && srv_msg->st != SMTP_ST_3XX) {
                            /* no data transfer */
                            if (srv_msg->nxt != NULL) {
                                if (srv_msg->nxt->fd_eml != -1)
                                    close(srv_msg->nxt->fd_eml);
                                srv_msg->nxt->fd_eml = -1;
                                srv_msg->nxt->file_eml[0] = '\0';
                            }
                        }
                        if (srv_msg->st != SMTP_ST_NONE) {
                            /* inset PEI element */
                            if (ppei == NULL) {
                                ppei = DMemMalloc(sizeof(pei));
                                PeiInit(ppei);
                                ppei->prot_id = smtp_id;
                                ppei->serial = pkt->serial;
                                ppei->stack = ProtCopyFrame(priv->stack, TRUE);
                            }
                            SmtpPei(ppei, srv_msg);
                            if (srv_msg->cmdt == SMTP_CMD_NONE && srv_msg->first == FALSE) {
                                PeiIns(ppei);
                                ppei = NULL;
                            }
                            /* auth command */
                            if (srv_msg->cmdt == SMTP_CMD_AUTH || srv_msg->cmdt == SMTP_CMD_AUTH_CONT) {
                                if (srv_msg->st == SMTP_ST_3XX) {
                                    /* 334 */
                                    srv_msg->nxt->auth_cont = TRUE;
                                }
                            }
                            /* next command */
                            tmp = srv_msg;
                            srv_msg = srv_msg->nxt;
                            if (srv_msg == NULL) { /* this is true only if the server send message wothout client command */
                                srv_msg = DMemMalloc(sizeof(smtp_msg));
                                SmtpMsgInit(srv_msg);
                                clt_msg = srv_msg;
                            }
                            
                            tmp->nxt = NULL;
                            SmtpMsgFree(tmp);
                        }
                    } while (srv_msg->st != SMTP_ST_NONE);
                }
            }
            if (ret == -1)
                break;
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    } while (pkt != NULL);

    if (pkt != NULL)
        PktFree(pkt);

    while (srv_msg != NULL) {
        srv_msg->err = TRUE;
        /* incomplete message */
        if (srv_msg != NULL && (srv_msg->cmdt != SMTP_CMD_NONE || srv_msg->st != SMTP_ST_NONE ||
                                srv_msg->dsize != 0 || (srv_msg->file_eml[0] != '\0' && srv_msg->fd_eml == -1) )) {
            /* incomplete data stransfere */
            if (srv_msg->dsize != 0) {
                write(srv_msg->fd_eml, srv_msg->data, srv_msg->dsize);
                srv_msg->data[0] = '\0';
                srv_msg->dsize = 0;
                close(srv_msg->fd_eml);
                srv_msg->fd_eml = -1;
            }
            if (ppei != NULL) {
                SmtpPei(ppei, srv_msg);
                if (srv_msg->cmdt == SMTP_CMD_NONE) {
                    if (ppei->components != NULL) {
                        PeiIns(ppei);
                    }
                    else {
                        PeiFree(ppei);
                    }
                    ppei = NULL;
                }
            }
        }
        else {
            if (srv_msg->fd_eml != -1) {
                close(srv_msg->fd_eml);
                srv_msg->fd_eml = -1;
            }
        }
        /* next msg */
        tmp = srv_msg;
        srv_msg = srv_msg->nxt;
        tmp->nxt = NULL;
        SmtpMsgFree(tmp);
    }
    
    /* pei with error */
    if (ppei != NULL) {
        if (ppei->components != NULL) {
            PeiIns(ppei);
        }
        else {
            PeiFree(ppei);
        }
    }

    return ret;
}


packet* SmtpDissector(int flow_id)
{
    packet* pkt;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, ip_dst;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    smtp_con *priv;

    LogPrintf(LV_DEBUG, "SMTP id: %d", flow_id);

    priv = DMemMalloc(sizeof(smtp_con));
    memset(priv, 0, sizeof(smtp_con));
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

    if (SmtpEmail(flow_id, priv) != 0) {
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
            /* raw smtp file */
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }

    /* free memory */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "SMTP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool SmtpVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    char *data, *new;
    const char *eol, *lineend, *lstart;
    unsigned long len;
    int cmp;
    bool ret, multi, fr_data;
    ftval lost, ips, ip_s;
    bool ipv4, client;
    short verify_step; /* 0: none; 1: server presentation ok; 2: HELO/EHLO client ok */
    smtp_cmd cmd;

    ipv4 = FALSE;
    client = TRUE; /* fist packet without lost packet is a client packet */
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
                        if (SmtpRespStatus(data, lineend-data) != SMTP_ST_NONE) {
                            if (check == FALSE) {
                                ret = TRUE;
                                break;
                            }
                            verify_step = 1;
                        }
                        else {
                            /* it is possible e multiple response server */
                            if ((lineend - data) < 4 || data[3] != '-')
                                break;
                            multi = FALSE;
                            do {
                                lstart = lineend;
                                lineend = find_line_end(lstart, data+len, &eol);
                                if (*eol == '\r' || *eol == '\n') {
                                    if (SmtpRespStatus(lstart, lineend-lstart) != SMTP_ST_NONE) {
                                        if (check == FALSE) {
                                            ret = TRUE;
                                            multi = TRUE;
                                            break;
                                        }
                                        verify_step = 1;
                                    }
                                    else {
                                        if ((lineend - lstart) < 4 || lstart[3] != '-') {
                                            multi = TRUE;
                                            break;
                                        }
                                    }
                                }
                            } while (!multi && lineend-data < len);
                            if (multi == TRUE)
                                break;
                        }
                    }
                    else if (verify_step == 1 && client == TRUE) {
                        /* second step is verify HELO/EHLO command from client */
                        cmd = SmtpCommand(data, lineend-data);
                        if (cmd == SMTP_CMD_HELO || cmd == SMTP_CMD_EHLO) {
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


static bool SmtpVerify(int flow_id)
{
    return SmtpVerifyCheck(flow_id, FALSE);
}


static bool SmtpCheck(int flow_id)
{
    return SmtpVerifyCheck(flow_id, TRUE);
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
    ProtName("Simple Mail Transfer Protocol", "smtp");

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_SMTP;
    dep.ProtCheck = SmtpVerify;
    dep.pktlim = SMTP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = SmtpCheck;
    hdep.pktlim = SMTP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "to";
    peic.desc = "Addresses";
    ProtPeiComponent(&peic);

    peic.abbrev = "from";
    peic.desc = "Sender";
    ProtPeiComponent(&peic);

    peic.abbrev = "eml";
    peic.desc = "MIME type";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, SmtpDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    int tcp_id;
    char smtp_dir[256];

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
    smtp_id = ProtId("smtp");

    /* pei id */
    pei_to_id = ProtPeiComptId(smtp_id, "to");
    pei_from_id = ProtPeiComptId(smtp_id, "from");
    pei_eml_id = ProtPeiComptId(smtp_id, "eml");

    /* smtp tmp directory */
    sprintf(smtp_dir, "%s/%s", ProtTmpDir(), SMTP_TMP_DIR);
    mkdir(smtp_dir, 0x01FF);

    return 0;
}
