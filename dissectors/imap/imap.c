/* imap.c
 * Dissector of IMAP4 protocol
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2014 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include "imap.h"
#include "pei.h"


#define IMAP_TMP_DIR    "imap"

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
static int imap_id;

/* pei id */
static int pei_user_id;
static int pei_pswd_id;
static int pei_params_id;
static int pei_eml_id;

static volatile unsigned int incr;

static int ImapRpl(imap_msg *msg, packet *pkt);


static void ImapMsgInit(imap_msg *msg)
{
    memset(msg, 0, sizeof(imap_msg));
    msg->cmdt = IMAP_CMD_NONE;
    msg->st = IMAP_ST_NONE;
}


static void ImapMsgFree(imap_msg *msg)
{
    imap_msg *next, *tmp;
    imap_conv *nxt_conv, *fr_conv;

    next = msg;
    while (next != NULL) {
        if (next->cmd != NULL)
            xfree(next->cmd);
        if (next->repl != NULL)
            xfree(next->repl);
        if (next->multp_conv != NULL) {
            nxt_conv = next->multp_conv;
            while (nxt_conv != NULL) {
                fr_conv = nxt_conv;
                nxt_conv = nxt_conv->nxt;
                if (fr_conv->clnt != NULL)
                    xfree(fr_conv->clnt);
                if (fr_conv->srv != NULL)
                    xfree(fr_conv->srv);
                DMemFree(fr_conv);
            }
        }
        if (next->psrv_data != NULL) {
            nxt_conv = next->psrv_data;
            while (nxt_conv != NULL) {
                fr_conv = nxt_conv;
                nxt_conv = nxt_conv->nxt;
                if (fr_conv->clnt != NULL)
                    xfree(fr_conv->clnt);
                if (fr_conv->srv != NULL)
                    xfree(fr_conv->srv);
                DMemFree(fr_conv);
            }
        }
        tmp = next;
        next = next->nxt;
        DMemFree(tmp);
    }
}


static void ImapPrintMsg(const imap_msg *msg)
{
    LogPrintf(LV_DEBUG, "\ttag: %s", msg->tag);
    LogPrintf(LV_DEBUG, "\tcmd: %s", msg->cmd);
    LogPrintf(LV_DEBUG, "\trepl %s", msg->repl);
}


static int ImapUser(char *param, char **user)
{
    char *estart, *eend, *end;
    int dim;

    *user = NULL;
    end = param + strlen(param);

    /* tag */
    estart = memchr(param, ' ', end - param);
    if (estart == NULL)
        return -1;
    estart++;

    /* user */
    estart = memchr(estart, ' ', end - estart);
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


static int ImapPassword(char *param, char **passwd)
{
    char *estart, *eend, *end;
    int dim;

    *passwd = NULL;
    end = param + strlen(param);

    /* tag */
    estart = memchr(param, ' ', end - param);
    if (estart == NULL)
        return -1;
    estart++;

    /* user */
    estart = memchr(estart, ' ', end - estart);
    if (estart == NULL)
        return -1;
    estart++;

    /* password */
    estart = memchr(estart, ' ', end - estart);
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


static int ImapPei(pei *ppei, imap_msg *msg)
{
    pei_component *cmpn;
    imap_conv *nxt_conv;
    FILE *fp_eml;
    char *file_path;

    /* capture time */
    if (ppei->time_cap == 0)
        ppei->time_cap = msg->capt_start;

    cmpn = NULL;
    switch (msg->cmdt) {
    case IMAP_CMD_LOGIN:
        /* user */
        PeiNewComponent(&cmpn, pei_user_id);
        PeiCompCapTime(cmpn, msg->capt_start);
        PeiCompCapEndTime(cmpn, msg->capt_end);
        ImapUser(msg->cmd, &cmpn->strbuf);
        PeiAddComponent(ppei, cmpn);
        /* password */
        PeiNewComponent(&cmpn, pei_pswd_id);
        PeiCompCapTime(cmpn, msg->capt_start);
        PeiCompCapEndTime(cmpn, msg->capt_end);
        ImapPassword(msg->cmd, &cmpn->strbuf);
        PeiAddComponent(ppei, cmpn);
        break;
        
    default:
        if (msg->psrv_data != NULL) {
            nxt_conv = msg->psrv_data;
            file_path = DMemMalloc(IMAP_FILENAME_PATH_SIZE);
            while (nxt_conv != NULL) {
                if (nxt_conv->srv_cnt != NULL) {
                    PeiNewComponent(&cmpn, pei_params_id);
                    PeiCompCapTime(cmpn, msg->capt_start);
                    PeiCompCapEndTime(cmpn, msg->capt_end);
                    PeiCompAddStingBuff(cmpn, nxt_conv->srv_cnt);
                    PeiAddComponent(ppei, cmpn);
                }
                /* file path and name */
                sprintf(file_path, "%s/%s/imap_%lld_%p_%i.eml", ProtTmpDir(), IMAP_TMP_DIR, (long long)time(NULL), msg, incr);
                incr++;
                /* open */
                fp_eml = fopen(file_path, "w");
                if (fp_eml == NULL) {
                    LogPrintf(LV_ERROR, "Unable to open file %s", file_path);
                }
                else {
                    PeiNewComponent(&cmpn, pei_eml_id);
                    PeiCompCapTime(cmpn, msg->capt_start);
                    PeiCompCapEndTime(cmpn, msg->capt_end);

                    fwrite(nxt_conv->srv, 1, nxt_conv->srv_size, fp_eml);
                    fclose(fp_eml);
                    if (nxt_conv->srv_size < nxt_conv->srv_dim || nxt_conv->lost == TRUE)
                        PeiCompError(cmpn, ELMT_ER_PARTIAL);
                    PeiCompAddFile(cmpn, "eml", file_path, nxt_conv->srv_size);
                    PeiAddComponent(ppei, cmpn);
                }

                nxt_conv = nxt_conv->nxt;
            }
            DMemFree(file_path);
        }
        break;
    }

    return 0;
}


static imap_cmd ImapCommand(const char *line, int linelen)
{
    const char *next_token;
    const char *lineend;
    int index;

    lineend = line + linelen;

    /* The first token is the tag */
    index = get_token_len(line, lineend, &next_token);
    if (index == 0 || line[index] != ' ') {
        return IMAP_CMD_NONE;
    }
    line = next_token;

    /* The next token is the command */
    index = get_token_len(line, lineend, &next_token);
    if (index == 0) {
        return IMAP_CMD_NONE;
    }

    switch (index) {
    case 2:
        if (strncasecmp(line, "ID", index) == 0) {
            return IMAP_CMD_ID;
        }
        break;
        
    case 3:
        if (strncasecmp(line, "UID", index) == 0) {
            return IMAP_CMD_UID;
        }
        break;

    case 4:
        if (strncasecmp(line, "COPY", index) == 0) {
            return IMAP_CMD_COPY;
        }
        else if (strncasecmp(line, "LIST", index) == 0) {
            return IMAP_CMD_LIST;
        }
        else if (strncasecmp(line, "LSUB", index) == 0) {
            return IMAP_CMD_LSUB;
        }
        else if (strncasecmp(line, "NOOP", index) == 0) {
            return IMAP_CMD_NOOP;
        }
        else if (strncasecmp(line, "IDLE", index) == 0) {
            return IMAP_CMD_IDLE;
        }
        break;

    case 5:
        if (strncasecmp(line, "CHECK", index) == 0) {
            return IMAP_CMD_CHECK;
        }
        else if (strncasecmp(line, "CLOSE", index) == 0) {
            return IMAP_CMD_CLOSE;
        }
        else if (strncasecmp(line, "FETCH", index) == 0) {
            return IMAP_CMD_FETCH;
        }
        else if (strncasecmp(line, "LOGIN", index) == 0) {
            return IMAP_CMD_LOGIN;
        }
        else if (strncasecmp(line, "STORE", index) == 0) {
            return IMAP_CMD_STORE;
        }
        break;

    case 6:
        if (strncasecmp(line, "APPEND", index) == 0) {
            return IMAP_CMD_APPEND;
        }
        else if (strncasecmp(line, "CREATE", index) == 0) {
            return IMAP_CMD_CREATE;
        }
        else if (strncasecmp(line, "DELETE", index) == 0) {
            return IMAP_CMD_DELETE;
        }
        else if (strncasecmp(line, "LOGOUT", index) == 0) {
            return IMAP_CMD_LOGOUT;
        }
        else if (strncasecmp(line, "RENAME", index) == 0) {
            return IMAP_CMD_RENAME;
        }
        else if (strncasecmp(line, "SEARCH", index) == 0) {
            return IMAP_CMD_SEARCH;
        }
        else if (strncasecmp(line, "SELECT", index) == 0) {
            return IMAP_CMD_SELECT;
        }
        else if (strncasecmp(line, "STATUS", index) == 0) {
            return IMAP_CMD_STATUS;
        }
        else if (strncasecmp(line, "GETACL", index) == 0) {
            return IMAP_CMD_GETACL;
        }
        else if (strncasecmp(line, "SETACL", index) == 0) {
            return IMAP_CMD_SETACL;
        }
        break;
        
    case 7:
        if (strncasecmp(line, "X<atom>", index) == 0) {
            return IMAP_CMD_XATOM;
        }
        else if (strncasecmp(line, "EXAMINE", index) == 0) {
            return IMAP_CMD_EXAMINE;
        }
        else if (strncasecmp(line, "EXPUNGE", index) == 0) {
            return IMAP_CMD_EXPUNGE;
        }
        break;

    case 8:
        if (strncasecmp(line, "STARTTLS", index) == 0) {
            return IMAP_CMD_STARTTLS;
        }
        else if (strncasecmp(line, "MYRIGHTS", index) == 0) {
            return IMAP_CMD_MYRIGHTS;
        }
        else if (strncasecmp(line, "GETQUOTA", index) == 0) {
            return IMAP_CMD_GETQUOTA;
        }
        else if (strncasecmp(line, "SETQUOTA", index) == 0) {
            return IMAP_CMD_SETQUOTA;
        }
        else if (strncasecmp(line, "UNSELECT", index) == 0) {
            return IMAP_CMD_UNSELECT;
        }
        else if (strncasecmp(line, "COMPRESS", index) == 0) {
            return IMAP_CMD_COMPRESS;
        }
        break;

    case 9:
        if (strncasecmp(line, "SUBSCRIBE", index) == 0) {
            return IMAP_CMD_SUBSCRIBE;
        }
        else if (strncasecmp(line, "DELETEACL", index) == 0) {
            return IMAP_CMD_DELETEACL;
        }
        else if (strncasecmp(line, "NAMESPACE", index) == 0) {
            return IMAP_CMD_NAMESPACE;
        }
        break;

    case 10:
        if (strncasecmp(line, "CAPABILITY", index) == 0) {
            return IMAP_CMD_CAPABILITY;
        }
        else if (strncasecmp(line, "LISTRIGHTS", index) == 0) {
            return IMAP_CMD_LISTRIGHTS;
        }
        break;

    case 11:
        if (strncasecmp(line, "UNSUBSCRIBE", index) == 0) {
            return IMAP_CMD_UNSUBSCRIBE;
        }
        break;

    case 12:
        if (strncasecmp(line, "AUTHENTICATE", index) == 0) {
            return IMAP_CMD_AUTHENTICATE;
        }
        else if (strncasecmp(line, "GETQUOTAROOT", index) == 0) {
            return IMAP_CMD_GETQUOTAROOT;
        }
        break;

    default:
        break;
    }

    return IMAP_CMD_NONE;
}


static imap_status ImapRespStatus(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int index;

    lineend = line + len;

    /* The first token is the tag id */
    index = get_token_len(line, lineend, &next_token);
    if (index == 0 || line[index] != ' ') {
        return IMAP_CMD_NONE;
    }
    line = next_token;
    
    /* The next token is the status response */
    index = get_token_len(line, lineend, &next_token);
    if (index != 0) {
        if (strncasecmp(line, "BAD", 3) == 0) {
            return IMAP_ST_BAD;
        }
        else if (strncasecmp(line, "BYE", 3) == 0) {
            return IMAP_ST_BYE;
        }
        else if (strncasecmp(line, "NO", 2) == 0) {
            return IMAP_ST_NO;
        }
        else if (strncasecmp(line, "OK", 2) == 0) {
            return IMAP_ST_OK;
        }
        else if (strncasecmp(line, "PREAUTH", 7) == 0) {
            return IMAP_ST_PREAUTH;
        }
    }
    
    return IMAP_ST_NONE;
}


static bool ImapClientPkt(imap_con *priv, packet *pkt)
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


static int ImapTag(char *tag, const char *line)
{
    const char *token;
    int index;

    /* The first token is the tag */
    token = strchr(line, ' ');
    if (token == NULL) {
        return -1;
    }
    index = token - line;
    memcpy(tag, line, index);
    tag[index] = '\0';

    return 0;
}


static imap_tag ImapTagType(char *tag)
{
    imap_tag type;

    if (tag[0] == '+')
        type = IMAP_TAG_CON;
    else if (tag[0] == '*')
        type = IMAP_TAG_INCO;
    else
        return IMAP_TAG_ID;
    
    /* check only IMAP_TAG_CON and IMAP_TAG_INCO */
    if (tag[1] != ' ' && tag[1] != '\0')
        return IMAP_TAG_ID;

    return type;
}


static int ImapOctet(const char *line, int len)
{
    char *open, *close;
    int num;

    /* find '{' and '}' */
    open = memchr(line, '{', len);
    close = memchr(line, '}', len);

    /* check if near {xxx} there is \lf\cr */
    if (close < open || len - (close - line) != 3) {
        return -1;
    }
    
    /* convert number */
    num = atoi(open+1);
    
    return num;
}


static int ImapCmd(imap_msg *msg, packet *pkt)
{
    const char *end, *eol;
    char *lineend;
    int dim;
    bool new;

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
            msg->cmdt = ImapCommand(msg->cmd, dim);
            if (msg->cmdt != IMAP_CMD_NONE) {
                ImapTag(msg->tag, msg->cmd);
                msg->nxt = DMemMalloc(sizeof(imap_msg));
                ImapMsgInit(msg->nxt);
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
                if (dim > 1 && msg->cmd[0] == '\r' && msg->cmd[1] == '\n') {
                    /* skeep empty command */
                    dim = msg->cmd_size - dim;
                    LogPrintf(LV_INFO, "Command empty");
                    memcpy(msg->cmd, lineend, dim);
                    msg->cmd[dim] = '\0';
                    msg->cmd_size = dim;
                }
                else {
                    LogPrintf(LV_WARNING, "Command (%s) unknow", msg->cmd);
                    if (pkt != NULL) {
                        ProtStackFrmDisp(pkt->stk, TRUE);
                    }
                    return -1;
                }
            }
        }
    } while (new);

    return 0;
}


static int ImapMulti(imap_msg *msg, packet *pkt)
{
    imap_conv *conv;
    const char *end, *eol;
    char *lineend, *line;
    int dim, line_size, ret;
    bool new;

    /* search last conversation */
    conv = msg->multp_conv;
    while (conv->nxt != NULL)
        conv = conv->nxt;

    /* append data */
    conv->clnt = xrealloc(conv->clnt, conv->clnt_size + pkt->len + 1);
    memcpy(conv->clnt+conv->clnt_size, pkt->data, pkt->len);
    conv->clnt_size += pkt->len;
    conv->clnt[conv->clnt_size] = '\0';

    /* search end of conversation */
    if (msg->cmdt == IMAP_CMD_IDLE) {
        line = conv->clnt;
        line_size = conv->clnt_size;
        do {
            new = FALSE;
            end = line + line_size;
            lineend = (char *)find_line_end(line, end, &eol);
            if (*eol == '\r' || *eol == '\n') {
                dim = lineend - line;
                if (strncmp(line, "DONE", 4) == 0) {
                    msg->nxt = DMemMalloc(sizeof(imap_msg));
                    ImapMsgInit(msg->nxt);
                    dim = end - lineend;
                    ret = 0;
                    if (dim > 0) {
                        msg->nxt->cmd = xmalloc(dim + 1);
                        memcpy(msg->nxt->cmd, lineend, dim);
                        msg->nxt->cmd_size = dim;
                        msg->nxt->cmd[dim] = '\0';
                        lineend = '\0';
                        conv->clnt_size -= dim;
                        ret = ImapCmd(msg->nxt, NULL);
                    }
                    return ret;
                }
                dim = end - lineend;
                if (dim > 0) {
                    line = lineend;
                    line_size = dim;
                    new = TRUE;
                }
            }
        } while (new);
    }

    return 0;
}


static int ImapRplData(imap_msg *msg, packet *pkt)
{
    imap_conv *conv;
    int dim;

    /* search last conversation */
    conv = msg->psrv_data;
    while (conv->nxt != NULL)
        conv = conv->nxt;

    /* append data */
    if (pkt != NULL) {
        conv->srv = xrealloc(conv->srv, conv->srv_size + pkt->len + 1);
        if (pkt->data != NULL) 
            memcpy(conv->srv+conv->srv_size, pkt->data, pkt->len);
        else {
            memset(conv->srv+conv->srv_size, 0, pkt->len);
            conv->lost = TRUE;
        }
        conv->srv_size += pkt->len;
        conv->srv[conv->srv_size] = '\0';
    }

    /* virify completition */
    if (conv->srv_size >= conv->srv_dim) {
        msg->srv_data = FALSE;
        dim = conv->srv_size - conv->srv_dim;
        if (dim > 0) {
            if (pkt == NULL || pkt->data != NULL) {
                /* copy in repl and analize it */
                msg->repl = xrealloc(msg->repl, msg->repl_size + dim + 1);
                memcpy(msg->repl+msg->repl_size, conv->srv+conv->srv_dim, dim);
                msg->repl_size += dim;
                msg->repl[msg->repl_size] = '\0';
                conv->srv[conv->srv_dim] = '\0';
                conv->srv_size = conv->srv_dim;
                return ImapRpl(msg, NULL);
            }
            else {
                /* lost packet */
                return -1;
            }
        }
    }

    return 0;
}


static int ImapBracOpen(imap_msg *msg)
{
    char *tok_op, *tok_cl, *end;
    int num;

    if (msg->psrv_data != NULL) {
        /* count bracket */
        tok_op = msg->repl;
        tok_cl = tok_op;
        end = msg->repl + msg->repl_line;
        num = 0;
        do {
            if (tok_op != NULL)
                tok_op = memchr(tok_op, '(', end-tok_op);
            if (tok_cl != NULL)
                tok_cl = memchr(tok_cl, ')', end-tok_cl);
            if (tok_op != NULL) {
                num++;
                tok_op++;
            }
            if (tok_cl != NULL) {
                num--;
                tok_cl++;
            }
        } while (tok_op != NULL || tok_cl != NULL);
#ifdef XPL_CHECK_CODE
        if (num < 0) {
            LogPrintf(LV_OOPS, "Parcket error (fun:%s)", __FUNCTION__);
            exit(-1);
        }
#endif
        if (num > 0)
            return 0;
    }
    
    return -1;
}


static int ImapRpl(imap_msg *msg, packet *pkt)
{
    const char *end, *eol;
    char *lineend, *repl;
    int dim, repl_size, tag_size;
    char tag[IMAP_TAG_SIZE];
    imap_msg *res_tag;
    bool new;
    int data_dim;
    imap_conv *data;

    /* attach data */
    if (pkt !=  NULL) {
        msg->repl = xrealloc(msg->repl, msg->repl_size + pkt->len + 1);
        memcpy(msg->repl+msg->repl_size, pkt->data, pkt->len);
        msg->repl_size += pkt->len;
        msg->repl[msg->repl_size] = '\0';
    }

    /* seach line and command */
    repl = msg->repl + msg->repl_line;
    repl_size = msg->repl_size - msg->repl_line;
    do {
        new = FALSE;
        end = repl + repl_size;
        lineend = (char *)find_line_end(repl, end, &eol);
        if (*eol == '\r' || *eol == '\n') {
            dim = lineend - repl;

            /* tag type */
            switch (ImapTagType(repl)) {
            case IMAP_TAG_ID:
                /* check end data octect */
                if (ImapBracOpen(msg) == 0) {
                    msg->repl_line += dim;
                    dim = end - lineend;
                    if (dim > 0) {
                        repl = lineend;
                        repl_size = dim;
                        new = TRUE;
                    }
                }
                else {
                    /* end tag */
                    msg->repl_line += dim;
                    if (ImapTag(tag, repl) == -1) {
                        LogPrintf(LV_WARNING, "Response error");
                        if (pkt != NULL) {
                            ProtStackFrmDisp(pkt->stk, TRUE);
                        }
                        return -1;
                    }
                    
                    /* search command tag */
                    res_tag = msg;
                    tag_size = strlen(tag);
                    while (res_tag != NULL) {
                        if (tag_size == strlen(res_tag->tag)) {
                            if (memcmp(res_tag->tag, tag, tag_size) == 0)
                                break;
                        }
                        res_tag = res_tag->nxt;
                    }
                    if (res_tag == NULL) {
                        LogPrintf(LV_WARNING, "Tag command and response don't match");
                        return -1;
                    }
                    
                    /* complete command/response */
                    if (res_tag != msg) {
                        res_tag->multp_conv = msg->multp_conv;
                        msg->multp_conv = NULL;
                        res_tag->repl = msg->repl;
                        msg->repl = NULL;
                        res_tag->repl_size = msg->repl_size;
                        msg->repl_size = 0;
                    }
                    res_tag->st = ImapRespStatus(repl, dim);
                    if (res_tag->st != IMAP_ST_NONE) {
                        res_tag->complete = TRUE;
                    }
                    else {
                        LogPrintf(LV_WARNING, "Response status unknow");
                        return -1;
                    }
                    dim = end - lineend;
                    if (dim > 0) {
                        /* seach line and command for new srv response */
                        msg = msg->nxt;
                        msg->repl = xrealloc(msg->repl, msg->repl_size + dim + 1);
                        memcpy(msg->repl+msg->repl_size, lineend, dim);
                        msg->repl_size += dim;
                        msg->repl[msg->repl_size] = '\0';
                        repl = msg->repl + msg->repl_line;
                        repl_size = msg->repl_size - msg->repl_line;
                        new = TRUE;
                    }
                }
                break;

            case IMAP_TAG_INCO:
                /* incomplete tag */
                msg->repl_line += dim;

                /* check data */
                data_dim = ImapOctet(repl, dim);
                if (data_dim != -1) {
                    msg->srv_data = TRUE;
                    if (msg->psrv_data == NULL) {
                        msg->psrv_data = DMemMalloc(sizeof(imap_conv));
                        memset(msg->psrv_data, 0, sizeof(imap_conv));
                        data = msg->psrv_data;
                    }
                    else {
                        data = msg->psrv_data;
                        while (data->nxt != NULL)
                            data = data->nxt;
                        data->nxt = DMemMalloc(sizeof(imap_conv));
                        memset(data->nxt, 0, sizeof(imap_conv));
                        data = data->nxt;
                    }
                    data->srv_dim = data_dim;
                    data->srv_cnt = xmalloc(dim + 1);
                    memcpy(data->srv_cnt, repl, dim);
                    data->srv_cnt[dim] = '\0';
                    dim = end - lineend;

                    if (dim > 0) {
                        data->srv = xmalloc(dim + 1);
                        memcpy(data->srv, lineend, dim);
                        data->srv[dim] = '\0';
                        data->srv_size += dim;
                        lineend = '\0';
                        msg->repl_size -= dim;
                        msg->repl[msg->repl_size] = '\0';
                        return ImapRplData(msg, NULL);
                    }
                }
                else {
                    dim = end - lineend;
                    if (dim > 0) {
                        repl = lineend;
                        repl_size = dim;
                        new = TRUE;
                    }
                    else if (msg->first == TRUE) {
                        msg->complete = TRUE;
                    }
                }
                break;
                
            case IMAP_TAG_CON:
                /* continuation tag */
                if (msg->multp_conv == NULL) {
                    msg->multp_conv = DMemMalloc(sizeof(imap_conv));
                    memset(msg->multp_conv, 0, sizeof(imap_conv));
                }
#ifdef XPL_CHECK_CODE
                else if (msg->multp_conv->clnt_dim == 0) {
                    LogPrintf(LV_OOPS, "Client dimension unknow (fun:%s)", __FUNCTION__);
                    exit(-1);
                }
#endif
                msg->multp_conv->srv = msg->repl; /* it must be */
                msg->repl = NULL;
                msg->multp_conv->srv_size = msg->repl_size;
                msg->repl_size = 0;
                if (lineend != end) {
                    LogPrintf(LV_WARNING, "Response continuation tag");
                    if (pkt != NULL) {
                        ProtStackFrmDisp(pkt->stk, TRUE);
                    }
                    ImapPrintMsg(msg);
                    return -1;
                }
                break;
            }
        }
    } while (new);

    return 0;
}


static int ImapRplMulti(imap_msg *msg, packet *pkt)
{
    const char *end, *eol;
    char *lineend, *repl;
    int dim, repl_size;
    bool new;
    imap_conv *conv;
    int ret;

     /* search last conversation */
    conv = msg->multp_conv;
    while (conv->nxt != NULL)
        conv = conv->nxt;
    
    /* check if new or not */
    if (conv->clnt != NULL) {
        /* new */
        conv->nxt = DMemMalloc(sizeof(imap_conv));
        memset(conv->nxt, 0, sizeof(imap_conv));
        conv = conv->nxt;
    }

    /* append data */
    conv->srv = xrealloc(conv->srv, conv->srv_size + pkt->len + 1);
    memcpy(conv->srv+conv->srv_size, pkt->data, pkt->len);
    conv->srv_size += pkt->len;
    conv->srv[conv->srv_size] = '\0';
    
    /* seach line and command */
    repl = conv->srv;
    repl_size = conv->srv_size;
    ret = 0;
    do {
        new = FALSE;
        end = repl + repl_size;
        lineend = (char *)find_line_end(repl, end, &eol);
        if (*eol == '\r' || *eol == '\n') {
            dim = lineend - repl;
            /* tag type */
            switch (ImapTagType(repl)) {
            case IMAP_TAG_ID:
            case IMAP_TAG_INCO:
                /* copy lines in repl and parse it */
                msg->repl = xrealloc(msg->repl, msg->repl_size + repl_size + 1);
                memcpy(msg->repl+msg->repl_size, repl, repl_size);
                msg->repl_size += repl_size;
                msg->repl[msg->repl_size] = '\0';
                repl[0] = '\0';
                ret = ImapRpl(msg, NULL);
                break;

            case IMAP_TAG_CON:
                /* continuation tag */
                dim = end - lineend;
                if (dim > 0) {
                    repl = lineend;
                    repl_size = dim;
                    new = TRUE;
                }
                break;

            }
        }
    } while (new);

    return ret;
}


static int ImapEmail(int flow_id, imap_con *priv)
{
    packet *pkt;
    ftval lost;
    imap_msg *clt_msg, *srv_msg, *tmp;
    pei *ppei;
    int ret;
    unsigned long serial;

    /* setup */
    srv_msg = DMemMalloc(sizeof(imap_msg));
    ImapMsgInit(srv_msg);
    clt_msg = DMemMalloc(sizeof(imap_msg));
    ImapMsgInit(clt_msg);
    srv_msg->nxt = clt_msg;
    srv_msg->first = TRUE;
    ret = -1;

    ppei = NULL;

    /* first tcp packet */
    pkt = FlowGetPkt(flow_id);
    do {
        //ProtStackFrmDisp(pkt->stk, TRUE);
        if (pkt != NULL && pkt->len != 0) {
            /* check if there are packet lost */
            ProtGetAttr(pkt->stk, lost_id, &lost);
            if (lost.uint8 == TRUE) {
                LogPrintf(LV_WARNING, "Packet lost");
                //ProtStackFrmDisp(pkt->stk, TRUE);
                /* packet lost */
                if (ImapClientPkt(priv, pkt) || srv_msg->srv_data == FALSE) {
                    ret = -1;
                    break;
                }
            }
            if (ImapClientPkt(priv, pkt)) {
                /* client */
                if (clt_msg->cmdt == IMAP_CMD_NONE) {
                    ret = ImapCmd(clt_msg, pkt);
                }
                else if (clt_msg->multp_conv != NULL && clt_msg->complete == FALSE) {
                    ret = ImapMulti(clt_msg, pkt);
                }
                else {
                    if (clt_msg->nxt == NULL) {
                        clt_msg->nxt = DMemMalloc(sizeof(imap_msg));
                        ImapMsgInit(clt_msg->nxt);
                    }
                    clt_msg = clt_msg->nxt;
                    ret = ImapCmd(clt_msg, pkt);
                }
                if (ret == 0) {
                    /* check pipeline cmd */
                    tmp = NULL;
                    while (clt_msg->nxt != NULL && clt_msg->cmdt != IMAP_CMD_NONE) {
                        clt_msg->capt_start = pkt->cap_sec;
                        tmp = clt_msg;
                        clt_msg = clt_msg->nxt;
                    }
                    if (clt_msg->cmdt == IMAP_CMD_NONE && tmp != NULL)
                        clt_msg = tmp;
                }
            }
            else {
                /* server */
                if (srv_msg->srv_data == TRUE) {
                    ret = ImapRplData(srv_msg, pkt);
                }
                else if (srv_msg->multp_conv != NULL) {
                    ret = ImapRplMulti(srv_msg, pkt);
                }
                else {
                    ret = ImapRpl(srv_msg, pkt);
                }
                if (ret == 0) {
                    /* check pipeline cmd */
                    while (srv_msg->complete == TRUE) {
                        srv_msg->capt_end = pkt->cap_sec;
                        /* pei components insert */
                        if (ppei == NULL) {
                            ppei = DMemMalloc(sizeof(pei));
                            PeiInit(ppei);
                            ppei->prot_id = imap_id;
                            ppei->serial = pkt->serial;
                            ppei->stack = ProtCopyFrame(priv->stack, TRUE);
                            if (priv->login != NULL) {
                                ImapPei(ppei, priv->login);
                            }
                        }
                        ImapPei(ppei, srv_msg);
                        if (srv_msg->psrv_data != NULL) {
                            /* insert PEI */
                            PeiIns(ppei);
                            ppei = NULL;
                        }
                        /* next command */
                        tmp = srv_msg;
                        if (clt_msg == srv_msg) {
                            clt_msg->nxt = DMemMalloc(sizeof(imap_msg));
                            ImapMsgInit(clt_msg->nxt);
                            clt_msg = clt_msg->nxt;
                        }
                        srv_msg = srv_msg->nxt;
                        tmp->nxt = NULL;
                        if (tmp->cmdt == IMAP_CMD_LOGIN)
                            priv->login = tmp;
                        else
                            ImapMsgFree(tmp);
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
        /* pei components insert */
        if (ppei == NULL) {
            ppei = DMemMalloc(sizeof(pei));
            PeiInit(ppei);
            ppei->prot_id = imap_id;
            ppei->serial = serial;
            ppei->stack = ProtCopyFrame(priv->stack, TRUE);
            if (priv->login != NULL) {
                ImapPei(ppei, priv->login);
            }
        }
        ImapPei(ppei, srv_msg);
        if (srv_msg->psrv_data != NULL) {
            /* insert PEI */
            PeiIns(ppei);
            ppei = NULL;
        }
        tmp = srv_msg;
        srv_msg = srv_msg->nxt;
        tmp->nxt = NULL;
        ImapMsgFree(tmp);
    }

    /* last pei */
    if (ppei != NULL) {
        /* insert PEI */
        PeiIns(ppei);
        ppei = NULL;
    }

    /* free login msg */
    if (priv->login != NULL) {
        ImapMsgFree(priv->login);
        priv->login = NULL;
    }

    return ret;
}


packet* ImapDissector(int flow_id)
{
    packet* pkt;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, ip_dst;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    imap_con *priv;

    LogPrintf(LV_DEBUG, "IMAP4 id: %d", flow_id);

    priv = DMemMalloc(sizeof(imap_con));
    memset(priv, 0, sizeof(imap_con));
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


    if (ImapEmail(flow_id, priv) != 0) {
        /* raw imap file */
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }

    /* free memory */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "IMAP4... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool ImapVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    char *data, *new;
    const char *eol, *lineend;
    unsigned long len;
    int cmp;
    bool ret, fr_data;
    ftval lost, ips, ip_s;
    bool ipv4, client, plost;
    short verify_step; /* 0: none; 1: server presentation ok; 2: client ok */
    imap_cmd cmd;

    ipv4 = plost = FALSE;
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
        while (lost.uint8 == TRUE || pkt->len == 0) {
            if (lost.uint8 == TRUE)
                plost = TRUE;
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
                        if (ImapRespStatus(data, lineend-data) != IMAP_ST_NONE && data[0] == '*') {
                            if (check == FALSE) {
                                ret = TRUE;
                                break;
                            }
                            verify_step = 1;
                        }
                        else {
                            if (plost) {
                                cmd = ImapCommand(data, lineend-data);
                                if (cmd != IMAP_CMD_NONE && check == FALSE) {
                                    ret = TRUE;
                                }
                            }
                            break;
                        }
                    }
                    else if (verify_step == 1 && client == TRUE) {
                        /* second step is verify command from client */
                        cmd = ImapCommand(data, lineend-data);
                        if (cmd != IMAP_CMD_NONE) {
                            ret = TRUE;
                            break;
                        }
                        else {
                            break;
                        }
                    }
                    else {
                        if (check == FALSE && plost == TRUE) {
                            if (ImapRespStatus(data, lineend-data) != IMAP_ST_NONE) {
                                ret = TRUE;
                            }
                            else {
                                cmd = ImapCommand(data, lineend-data);
                                if (cmd != IMAP_CMD_NONE) {
                                    ret = TRUE;
                                }
                            }
                        }
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
                if (pkt != NULL && pkt->len != 0) {
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


static bool ImapVerify(int flow_id)
{
    return ImapVerifyCheck(flow_id, FALSE);
}


static bool ImapCheck(int flow_id)
{
    return ImapVerifyCheck(flow_id, TRUE);
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
    ProtName("Internet Message Access Protocol", "imap");

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = 143;
    dep.ProtCheck = ImapVerify;
    dep.pktlim = IMAP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = ImapCheck;
    hdep.pktlim = IMAP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "user";
    peic.desc = "User name";
    ProtPeiComponent(&peic);

    peic.abbrev = "password";
    peic.desc = "Password";
    ProtPeiComponent(&peic);

    peic.abbrev = "params";
    peic.desc = "Fetch params";
    ProtPeiComponent(&peic);

    peic.abbrev = "eml";
    peic.desc = "MIME type";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, ImapDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    int tcp_id;
    char imap_dir[256];

    /* part of file name */
    incr = 0;

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
    imap_id = ProtId("imap");

    /* pei id */
    pei_user_id = ProtPeiComptId(imap_id, "user");
    pei_pswd_id = ProtPeiComptId(imap_id, "password");
    pei_params_id = ProtPeiComptId(imap_id, "params");
    pei_eml_id = ProtPeiComptId(imap_id, "eml");

    /* imap tmp directory */
    sprintf(imap_dir, "%s/%s", ProtTmpDir(), IMAP_TMP_DIR);
    mkdir(imap_dir, 0x01FF);

    return 0;
}
