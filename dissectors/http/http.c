/* http.c
 * HTTP protocol dissector
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <limits.h>
#include <stdio.h>

#include "proto.h"
#include "dmemory.h"
#include "strutil.h"
#include "flow.h"
#include "log.h"
#include "http.h"
#include "http_com.h"
#include "pei.h"
#include "fileformat.h"

#define HTTP_TMP_DIR    "http"

static int prot_id;
static int ip_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int uagent_id;
static int host_id;
static int ctype_id;
static int range_id;
static int encoding_id;
static int httpfd_id;
static int pei_url_id;
static int pei_client_id;
static int pei_host_id;
static int pei_content_type;
static int pei_method_id;
static int pei_status_id;
static int pei_req_header_id;
static int pei_req_body_id;
static int pei_res_header_id;
static int pei_res_body_id;
static int pei_file_id;
 
static const unsigned short std_ports[] = TCP_PORTS_HTTP;
static unsigned short std_ports_dim;
static volatile unsigned int incr;

static http_st_code st_code[] = {
    {100, HTTP_ST_100},
    {101, HTTP_ST_101},
    {102, HTTP_ST_102},
    {199, HTTP_ST_199},

    {200, HTTP_ST_200},
    {201, HTTP_ST_201},
    {202, HTTP_ST_202},
    {203, HTTP_ST_203},
    {204, HTTP_ST_204},
    {205, HTTP_ST_205},
    {206, HTTP_ST_206},
    {207, HTTP_ST_207},
    {299, HTTP_ST_299},

    {300, HTTP_ST_300},
    {301, HTTP_ST_301},
    {302, HTTP_ST_302},
    {303, HTTP_ST_303},
    {304, HTTP_ST_304},
    {305, HTTP_ST_305},
    {307, HTTP_ST_307},
    {399, HTTP_ST_399},

    {400, HTTP_ST_400},
    {401, HTTP_ST_401},
    {402, HTTP_ST_402},
    {403, HTTP_ST_403},
    {404, HTTP_ST_404},
    {405, HTTP_ST_405},
    {406, HTTP_ST_406},
    {407, HTTP_ST_407},
    {408, HTTP_ST_408},
    {409, HTTP_ST_409},
    {410, HTTP_ST_410},
    {411, HTTP_ST_411},
    {412, HTTP_ST_412},
    {413, HTTP_ST_413},
    {414, HTTP_ST_414},
    {415, HTTP_ST_415},
    {416, HTTP_ST_416},
    {417, HTTP_ST_417},
    {422, HTTP_ST_422},
    {423, HTTP_ST_423},
    {424, HTTP_ST_424},
    {499, HTTP_ST_499},

    {500, HTTP_ST_500},
    {501, HTTP_ST_501},
    {502, HTTP_ST_502},
    {503, HTTP_ST_503},
    {504, HTTP_ST_504},
    {505, HTTP_ST_505},
    {507, HTTP_ST_507},
    {599, HTTP_ST_599}
};

static char *meth[] = {
    "OPTIONS",
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "DELETE",
    "TRACE",
    "CONNECT",
    "PATCH",
    "LINK",
    "UNLINK",
    "PROPFIND",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "POLL",
    "BCOPY",
    "BMOVE",
    "SEARCH",
    "BDELETE",
    "PROPPATCH",
    "BPROPFIND",
    "BPROPPATCH",
    "LABEL",
    "MERGE",
    "REPORT",
    "UPDATE",
    "CHECKIN",
    "CHECKOUT",
    "UNCHECKOUT",
    "MKACTIVITY",
    "MKWORKSPACE",
    "VERSION-CONTROL",
    "BASELINE-CONTROL",
    "NOTIFY",
    "SUBSCRIBE",
    "UNSUBSCRIBE",
    "ICY",
    "NONE"
};

static http_com* HttpExtractChunckedBody(http_com *rex, bool req);


static void HttpMsgInit(http_msg *msg)
{
    memset(msg, 0, sizeof(http_msg));
    msg->req_hdr_file = DMemMalloc(HTTP_FILENAME_PATH_SIZE);
    msg->req_hdr_file[0] = '\0';
    msg->res_hdr_file = DMemMalloc(HTTP_FILENAME_PATH_SIZE);
    msg->res_hdr_file[0] = '\0';
    msg->req_body_file = DMemMalloc(HTTP_FILENAME_PATH_SIZE);
    msg->req_body_file[0] = '\0';
    msg->res_body_file = DMemMalloc(HTTP_FILENAME_PATH_SIZE);
    msg->res_body_file[0] = '\0';
    msg->rsize = 0;
}


static int HttpComInit(http_com *data)
{
    memset(data, 0, sizeof(http_com));
    data->body_fp = NULL;
    
    return 0;
}


static char* HttpURI(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;
    char *uri;
    
    /* \r\n necesary for bug in client POST */
    if (len > 1 && strncmp(line, "\r\n", 2) == 0) {
        len -= 2;
        line += 2;
    }
    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return NULL;
    }
    line = next_token;

    /* The next token is the URI. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return NULL;

    uri = DMemMalloc(tokenlen+1);
    if (uri != NULL) {
        memcpy(uri, line, tokenlen);
        uri[tokenlen] = '\0';
    }

    return uri;
}


static inline char *HttpUriExt(const char *uri)
{
    int i;
    char *ext;

    /* extension file name */
    if (uri == NULL)
        return NULL;
    
    ext = strrchr(uri, '.');
    if (ext != NULL) {
        ext++;
        if (strlen(ext) > 4)
            ext = NULL;
        else {
            i = 0;
            while (ext[i] != '\0') {
                if (!((ext[i] >= 'a' && ext[i] <= 'z') || (ext[i] >= 'A' && ext[i] <= 'Z'))) {
                    ext = NULL;
                    break;
                }
                i++;
            }
        }
    }
    
    return ext;
}


static int HttpRange(http_msg *msg, const char *param)
{
    unsigned long rbase, rend, rsize;

    /* parse */
    if (sscanf(param, "bytes %lu-%lu/%lu", &rbase, &rend, &rsize) == 3) {
        msg->rbase = rbase;
        msg->rend = rend; 
        msg->rsize = rsize;
    }

    return 0;
}


static http_ver HttpReqVersion(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    int tokenlen;

    lineend = line + len;

    /* The first token is the method. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return HTTP_VER_NONE;
    }
    line = next_token;

    /* The next token is the URI. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ')
        return HTTP_VER_NONE;
    line = next_token;

    /* Everything to the end of the line is the version. */
    tokenlen = lineend - line;
    if (tokenlen == 0)
        return HTTP_VER_NONE;
    
    if (strncmp(line, "HTTP/1.0", 8) == 0)
        return HTTP_VER_1_0;
    
    if (strncmp(line, "HTTP/1.1", 8) == 0)
        return HTTP_VER_1_1;

    return HTTP_VER_NONE;
}


static http_ver HttpResVersion(const char *line, int len)
{
    if (strncmp(line, "HTTP/1.0", 8) == 0)
        return HTTP_VER_1_0;
    
    if (strncmp(line, "HTTP/1.1", 8) == 0)
        return HTTP_VER_1_1;

    return HTTP_VER_NONE;
}


static http_mthd HttpReqMethod(const char *data, int linelen, bool test)
{
    const char *ptr;
    int	index = 0;
    char *unkn;

    /*
     * From RFC 2774 - An HTTP Extension Framework
     *
     * Support the command prefix that identifies the presence of
     * a "mandatory" header.
     */
    if (linelen >= 2) {
        if (strncmp(data, "M-", 2) == 0 || strncmp(data, "\r\n", 2) == 0) { /* \r\n necesary for bug in client POST */
            data += 2;
            linelen -= 2;
        }
    }
    
    /*
     * From draft-cohen-gena-client-01.txt, available from the uPnP forum:
     *	NOTIFY, SUBSCRIBE, UNSUBSCRIBE
     *
     * From draft-ietf-dasl-protocol-00.txt, a now vanished Microsoft draft:
     *	SEARCH
     */
    ptr = (const char *)data;
    /* Look for the space following the Method */
    while (index != linelen) {
        if (*ptr == ' ')
            break;
        else {
            ptr++;
            index++;
        }
    }

    /* Check the methods that have same length */
    switch (data[0]) {
    case 'G':
        if (strncmp(data, "GET", index) == 0) {
            return HTTP_MT_GET;
        }
        break;
        
    case 'P':
        if (strncmp(data, "POST", index) == 0) {
            return HTTP_MT_POST;
        }
        else if (strncmp(data, "PUT", index) == 0) {
            return HTTP_MT_PUT;
        }
        else if (strncmp(data, "POLL", index) == 0) {
            return HTTP_MT_POLL;
        }
        else if (strncmp(data, "PROPFIND", index) == 0) {
            return HTTP_MT_PROPFIND;
        }
        else if (strncmp(data, "PROPPATCH", index) == 0) {
            return HTTP_MT_PROPPATCH;
        }
        else if (strncmp(data, "PATCH", index) == 0) {
            return HTTP_MT_PATCH;
        }
        break;
        
    case 'B':
        if (strncmp(data, "BCOPY", index) == 0) {
            return HTTP_MT_BCOPY;
        }
        else if (strncmp(data, "BMOVE", index) == 0) {
            return HTTP_MT_BMOVE;
        }
        else if (strncmp(data, "BDELETE", index) == 0) {
            return HTTP_MT_BDELETE;
        }
        else  if (strncmp(data, "BPROPFIND", index) == 0) {
            return HTTP_MT_BPROPFIND;
        }
        else if (strncmp(data, "BPROPPATCH", index) == 0) {
            return HTTP_MT_BPROPPATCH;
        }
        else if (strncmp(data, "BASELINE-CONTROL", index) == 0) {  /* RFC 3253 12.6 */
            return HTTP_MT_BASELINE_CONTROL;
        }
        break;
        
    case 'C':
        if (strncmp(data, "COPY", index) == 0) {
            return HTTP_MT_COPY;
        }
        else if (strncmp(data, "CONNECT", index) == 0) {
            return HTTP_MT_CONNECT;
        }
        else if (strncmp(data, "CHECKIN", index) == 0) {  /* RFC 3253 4.4, 9.4 */
            return HTTP_MT_CHECKIN;
        }
        else if (strncmp(data, "CHECKOUT", index) == 0) { /* RFC 3253 4.3, 9.3 */
            return HTTP_MT_CHECKOUT;
        }
        /*
        else if (strncmp(data, "CCM_POST", index) == 0) {
            return HTTP_MT_CCM_POST;
        }
        */
        break;
        
    case 'D':
        if (strncmp(data, "DELETE", index) == 0) {
            return HTTP_MT_DELETE;
        }
        break;
        
    case 'H':
        if (strncmp(data, "HEAD", index) == 0) {
            return HTTP_MT_HEAD;
        }
        break;
        
#if 0
    case 'I':
        if (strncmp(data, "ICY", index) == 0) {
            return HTTP_MT_ICY;
        }
        break;
#endif
        
    case 'L':
        if (strncmp(data, "LOCK", index) == 0) {
            return HTTP_MT_LOCK;
        }
        else if (strncmp(data, "LINK", index) == 0) {
            return HTTP_MT_LINK;
        }
        else if (strncmp(data, "LABEL", index) == 0) {  /* RFC 3253 8.2 */
            return HTTP_MT_LABEL;
        }
        break;
        
    case 'M':
        if (strncmp(data, "MOVE", index) == 0) {
            return HTTP_MT_MOVE;
        }
        else if (strncmp(data, "MKCOL", index) == 0) {
            return HTTP_MT_MKCOL;
        }
        else if (strncmp(data, "MERGE", index) == 0) {  /* RFC 3253 11.2 */
            return HTTP_MT_MERGE;
        }
        else if (strncmp(data, "MKACTIVITY", index) == 0) {  /* RFC 3253 13.5 */
            return HTTP_MT_MKACTIVITY;
        }
        else if (strncmp(data, "MKWORKSPACE", index) == 0) {  /* RFC 3253 6.3 */
            return HTTP_MT_MKWORKSPACE;
        }
        break;
        
    case 'N':
        if (strncmp(data, "NOTIFY", index) == 0) {
            return HTTP_MT_NOTIFY;
        }
        break;
        
    case 'O':
        if (strncmp(data, "OPTIONS", index) == 0) {
            return HTTP_MT_OPTIONS;
        }
        break;
        
    case 'S':
        if (strncmp(data, "SEARCH", index) == 0) {
            return HTTP_MT_SEARCH;
        }
        else if (strncmp(data, "SUBSCRIBE", index) == 0) {
            return HTTP_MT_SUBSCRIBE;
        }
        break;
        
    case 'T':
        if (strncmp(data, "TRACE", index) == 0) {
            return HTTP_MT_TRACE;
        }
        break;
        
    case 'U':
        if (strncmp(data, "UNLOCK", index) == 0) {
            return HTTP_MT_UNLOCK;
        }
        else if (strncmp(data, "UNLINK", index) == 0) {
            return HTTP_MT_UNLINK;
        }
        else if (strncmp(data, "UPDATE", index) == 0) {  /* RFC 3253 7.1 */
            return HTTP_MT_UPDATE;
        }
        else if (strncmp(data, "UNCHECKOUT", index) == 0) {  /* RFC 3253 4.5 */
            return HTTP_MT_UNCHECKOUT;
        }
        else if (strncmp(data, "UNSUBSCRIBE", index) == 0) {
            return HTTP_MT_UNSUBSCRIBE;
        }
        break;
        
    case 'V':
        if (strncmp(data, "VERSION-CONTROL", index) == 0) {  /* RFC 3253 3.5 */
            return HTTP_MT_VERSION_CONTROL;
        }
        break;
        
    case 'R':
        if (strncmp(data, "REPORT", index) == 0) {  /* RFC 3253 3.6 */
            return HTTP_MT_REPORT;
        }
        /*
        else if (strncmp(data, "RPC_CONNECT", index) == 0) {
            return HTTP_MT_RPC_CONNECT;
        }
        */
        break;
    }
    
    if (index > 0 && !test) {
        unkn = DMemMalloc(index+1);
        memcpy(unkn, data, index);
        unkn[index] = '\0';
        LogPrintf(LV_WARNING, "Http method (%s) don't managed.", unkn);
        DMemFree(unkn);
    }

    return HTTP_MT_NONE;
}


static http_status HttpRespStatus(const char *line, int len)
{
    const char *next_token;
    const char *lineend;
    http_status status;
    int tokenlen, val;
    int i, dim = sizeof(st_code);

    lineend = line + len;
    status = HTTP_ST_NONE;

    /* The first token is the protocol and version */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || line[tokenlen] != ' ') {
        return status;
    }

    line = next_token;
    /* The next token is status value. */
    tokenlen = get_token_len(line, lineend, &next_token);
    if (tokenlen == 0 || (line[tokenlen] != ' ' && line[tokenlen] != '\r' && line[tokenlen] != '\n')) {
        return status;
    }
    if (sscanf(line, "%i", &val) != 1) {
        LogPrintf(LV_ERROR, "HTTP return status\n");

        return status;
    }
    
    /* search enum */
    for (i=0; i<dim; i++) {
        if (st_code[i].num == val) {
            status = st_code[i].st;
            break;
        }
    }

    return status;
}


static bool HttpWithoutBody(http_status status)
{
    if (status == HTTP_ST_304)
        return TRUE;

    return FALSE;
}


static char *HttpHeaderParam(const char *header, int hlen, const char *param)
{
    const char *line, *eol, *lineend, *hend, *c;
    char *ret;
    int len, host_len, param_len;

    line = header;
    len = hlen;
    hend = header + len;
    lineend = NULL;
    ret = NULL;
    param_len = strlen(param);
    while (lineend < hend) {
        lineend = find_line_end(line, hend, &eol);
        if (lineend != line+len && (*eol == '\r' || *eol == '\n')) {
            if (strncasecmp(line, param, param_len) == 0) {
                c = line + param_len;
                while (*c == ' ' && c != lineend)
                    c++;
                host_len = eol - c;
                ret = DMemMalloc(host_len + 1);
                memcpy(ret, c, host_len);
                ret[host_len] = '\0';
                break;
            }
        }
        line = lineend;
        len = hend - lineend;
    }

    return ret;
}


static bool HttpClientPkt(http_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
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

    /* first time, the verify function verify that first pkt is a client pkt */
    if (priv->dir == HTTP_CLT_DIR_NONE) {
        if (ret == TRUE)
            priv->dir = HTTP_CLT_DIR_OK;
        else {
            priv->dir = HTTP_CLT_DIR_REVERS;
            ret = TRUE;
            LogPrintf(LV_WARNING, "Acquisition file/probe has an error!");
            if (pkt != NULL)
                ProtStackFrmDisp(pkt->stk, TRUE);
        }
    }
    else {
        if (priv->dir == HTTP_CLT_DIR_REVERS)
            ret = !ret;
    }
    
    return ret;
}


static char* HttpHeaderEnd(const char *header, unsigned long len)
{
    const char *lf, *nxtlf, *end;
    const char *buf_end;
   
    end = NULL;
    buf_end = header + len;
    lf =  memchr(header, '\n', len);
    if (lf == NULL)
        return NULL;
    lf++; /* next charater */
    nxtlf = memchr(lf, '\n', buf_end - lf);
    while (nxtlf != NULL) {
        if (nxtlf-lf < 2) {
            end = nxtlf;
            break;
        }
        nxtlf++;
        lf = nxtlf;
        nxtlf = memchr(nxtlf, '\n', buf_end - nxtlf);
    }

    return (char *)end;
}


static http_com* HttpExtractHeader(http_com *rex, bool req)
{
    char *param, *end, *body_data;
    bool body, newh, clength;
    FILE *fp;
    unsigned long size;
    long sig_size;
    http_msg *msg;
    int hdr_size;
    unsigned long serial = 0;
    unsigned long start_cap = 0;
    char *range, *ext;

    do {
        newh = FALSE;
        msg = NULL;
        
        /* check header end:  "\r\n\r\n"*/
        end = HttpHeaderEnd(rex->hdr_buf, rex->hdr_sz);
        if (end != NULL) {
            end++;
            /* check if a serial number are set */
            if (rex->serial == 0) {
                rex->serial = serial;
                rex->start_cap = start_cap;
            }

            if (req == TRUE) {
                /* create new HTTP message */
                rex->msg = DMemMalloc(sizeof(http_msg));
                HttpMsgInit(rex->msg);
                msg = rex->msg;
                msg->mtd = HttpReqMethod(rex->hdr_buf, rex->hdr_sz, FALSE);
                if (msg->mtd == HTTP_MT_NONE) {
                    return NULL;
                }
                msg->uri = HttpURI(rex->hdr_buf, rex->hdr_sz);
                msg->host = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Host:");
                msg->client = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "User-Agent:");

                /* Content-Type, Content-Encoding */
                if (msg->mtd == HTTP_MT_POST) {
                    rex->cnt_type = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Content-Type:");
                    msg->content_type[0] = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Content-Type:");
                    msg->content_encoding[0] = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Content-Encoding:");
                }

                /* Range */
                range = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Range:");
                if (range != NULL) {
                    msg->rset = range;
                }
                sprintf(msg->req_hdr_file, "%s/%s/http_rq_hdr_%lld_%p_%i.txt", ProtTmpDir(), HTTP_TMP_DIR,
                        (long long)time(NULL), msg, incr);
                incr++;
                fp = fopen(msg->req_hdr_file, "w");
                if (fp != NULL) {
                    fwrite(rex->hdr_buf, 1, end - rex->hdr_buf, fp);
                    msg->req_hdr_size = end - rex->hdr_buf;
                    hdr_size = msg->req_hdr_size;
                    fclose(fp);
                }
                else {
                    LogPrintf(LV_ERROR, "Unable to open file %s", msg->req_hdr_file);
                }
                rex->req_h = TRUE;
                rex->body_sz = 0;
            }
            else {
                msg = rex->msg;
                if (msg == NULL) {
                    LogPrintf(LV_ERROR, "Bug in HTTP dissector (%s:%i)", __FILE__, __LINE__);
                    return NULL;
                }
                msg->status = HttpRespStatus(rex->hdr_buf, rex->hdr_sz);
                if (msg->status == HTTP_ST_NONE) {
                    LogPrintf(LV_WARNING, "Http status response unknown");
                    //printf("%s\n", rex->hdr_buf);
                    return NULL;
                }
                if (msg->status == HTTP_ST_100) {
                    msg->status = HTTP_ST_NONE;
                    /* next header */
                    if (end - rex->hdr_buf == rex->hdr_sz) {
                        rex->hdr_sz = 0;
                        rex->hdr_buf[0] = '\0';
                        return rex;
                    }
                    rex->hdr_sz -= (end - rex->hdr_buf);
                    memcpy(rex->hdr_buf, end, rex->hdr_sz);
                    /* check header end:  "\r\n\r\n"*/
                    end = HttpHeaderEnd(rex->hdr_buf, rex->hdr_sz);
                    if (end == NULL) {
                        return rex;
                    }
                    end++;
                }

                /* Content-Range */
                range = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Content-Range:");
                if (range != NULL) {
                    HttpRange(rex->msg, range);
                    DMemFree(range);
                }
                
                /* Content-Type */
                if (msg->content_type[1] == NULL) {
                    if (rex->cnt_type == NULL)  /* != NULL only with POST */
                        rex->cnt_type = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Content-Type:");
                    msg->content_type[1] = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Content-Type:");
                }
                if (msg->content_encoding[1] == NULL) {
                    msg->content_encoding[1] = HttpHeaderParam(rex->hdr_buf, rex->hdr_sz, "Content-Encoding:");
                }
                sprintf(msg->res_hdr_file, "%s/%s/http_rs_hdr_%lld_%p_%i.txt", ProtTmpDir(), HTTP_TMP_DIR,
                        (long long)time(NULL), msg, incr);
                fp = fopen(msg->res_hdr_file, "w");
                if (fp != NULL) {
                    fwrite( rex->hdr_buf, 1, end - rex->hdr_buf, fp);
                    msg->res_hdr_size = end - rex->hdr_buf;
                    hdr_size = msg->res_hdr_size;
                    fclose(fp);
                }
                else {
                    LogPrintf(LV_ERROR, "Unable to open file %s", msg->res_hdr_file);
                    perror("");
                }
                rex->res_h = TRUE;
                rex->body_sz = 0;
            }
            
            /* check if body or a new header */
            body = FALSE;
            clength = FALSE;
            if (msg->mtd != HTTP_MT_HEAD) {
                /* body is present if there is or content-type or content-lengh
                   or transfer-encoding */
                param = memchr(rex->hdr_buf, '\n', hdr_size);
                
                while (param != NULL && param < end) {
                    param++;
                    if (strncasecmp(param, "Content-Length:", 15) == 0) {
                        body = TRUE;
                        clength = TRUE;
                        if (sscanf(param + 15, "%li", &sig_size) == 1) {
                            /* if  size is negative */
                            if (sig_size < 0) {
                                rex->size = 0;
                                if (param[15] == '-' || param[16] == '-' || param[17] == '-') {
                                    LogPrintf(LV_WARNING, "Content-Length (=%i) error: check pcap", sig_size);
                                }
                                else if (sscanf(param + 15, "%lu", &size) == 1) {
                                    rex->size = size;
                                    rex->clength = size;
                                }
                            }
                            else {
                                rex->size = sig_size;
                                rex->clength = sig_size;
                            }
                        }
                    }
                    else if (strncasecmp(param, "Content-Type:", 13) == 0) {
                        /* it's applicable only at response */
                        if (req == FALSE) {
                            if (!HttpWithoutBody(msg->status)) {
                                body = TRUE;
                                if (clength == FALSE)
                                    rex->size = ULONG_MAX;
                            }
                        }
                    }
                    else if (strncasecmp(param, "Transfer-Encoding:", 18) == 0) {
                        body = TRUE;
                        /* search encoding type */
                        param += 18;
                        while (param < end && (*param == ' ' || *param == '\t'))
                            param++;
                        if (param < end) {
                            if (strncasecmp(param, "chunked", 7) == 0) {
                                rex->chunked = TRUE;
                            }
                            else {
                                LogPrintf(LV_WARNING, "Transfer encoding \"%s\" unknown!", param);
                            }
                        }
                        else {
                            LogPrintf(LV_WARNING, "Transfer encoding empty!");
                        }
                    }
                    else  if (strncasecmp(param, "Connection:", 11) == 0) {
                        /* search type */
                        param += 11;
                        while (param < end && (*param == ' ' || *param == '\t'))
                            param++;
                        if (param < end) {
                            if (strncasecmp(param, "close", 5) == 0) {
                                rex->close = TRUE;
                                if (req == FALSE) {
                                    /* suppose a body because connection if body don't arrive
                                       turn off */
                                    body = TRUE;
                                }
                            }
                        }
                    }
                    param = memchr(param, '\n', end - param);
                }
            }

            /* verify server responce version */
            if (body == FALSE && req == FALSE) {
                if (HttpResVersion(rex->hdr_buf, hdr_size) == HTTP_VER_1_0) {
                    if (!HttpWithoutBody(msg->status)) {
                        body = TRUE;
                        rex->size = ULONG_MAX;
                    }
                    rex->close = TRUE;
                }
            }
            if (body) {
                if (rex->close == TRUE && req == FALSE) {
                    /* this avoid error length supplied from server */
                    /* NB: search close in code if you change this line!! */
                    rex->size = ULONG_MAX;
                }
                if (req == TRUE) {
                    sprintf(msg->req_body_file, "%s/%s/http_rq_body_%lld_%p_%i", ProtTmpDir(), HTTP_TMP_DIR,
                            (long long)time(NULL), msg, incr);
                    fp = fopen(msg->req_body_file, "w");
                    if (fp == NULL) {
                        LogPrintf(LV_ERROR, "Unable to open file %s", msg->req_body_file);
                        perror("");
                    }
                    else {
#ifdef XPL_CHECK_CODE
                        if (rex->body_fp != NULL) {
                            LogPrintf(LV_OOPS, "FP body dont closed 1");
                            exit(-1);
                        }
#endif
                        rex->body_fp = fp;
                    }
                }
                else {
                    ext = HttpUriExt(msg->uri);
                    if (ext != NULL) {
                        sprintf(msg->res_body_file, "%s/%s/http_rs_body_%lld_%p_%i.%s", ProtTmpDir(), HTTP_TMP_DIR,
                                (long long)time(NULL), msg, incr, ext);
                    }
                    else {
                        sprintf(msg->res_body_file, "%s/%s/http_rs_body_%lld_%p_%i", ProtTmpDir(), HTTP_TMP_DIR,
                                (long long)time(NULL), msg, incr);
                    }
                    fp = fopen(msg->res_body_file, "w");
                    if (fp == NULL) {
                        LogPrintf(LV_ERROR, "Unable to open file %s", msg->res_body_file);
                        perror("");
                    }
                    else {
#ifdef XPL_CHECK_CODE
                        if (rex->body_fp != NULL) {
                            LogPrintf(LV_OOPS, "FP body dont closed 2");
                            printf("%s\n", rex->hdr_buf);
                            *(char *)0 = 1;
                            exit(-1);
                        }
#endif
                        rex->body_fp = fp;
                    }
                }
                if (hdr_size < rex->hdr_sz) {
                    body_data = rex->hdr_buf + hdr_size;
                    if (rex->chunked == TRUE) {
                        rex->chk_size = rex->hdr_sz - hdr_size;
                        if (rex->chk_size < HTTP_CHUNKED_BUFF_SIZE) {
                            memcpy(rex->chk_buf,  end, rex->chk_size);
                            rex->chk_buf[rex->chk_size] = '\0';
                        }
                        else {
                            LogPrintf(LV_FATAL, "Temporary buffer too small");
                            exit(-1);
                        }
                        xfree(rex->hdr_buf);
                        rex->hdr_buf = NULL;
                        rex->hdr_sz = 0;
                        rex = HttpExtractChunckedBody(rex, req);
                        if (rex == NULL) {
                            return NULL;
                        }
                    }
                    else {
                        if (rex->hdr_sz - hdr_size <= rex->size) {
                            fwrite(body_data, 1, rex->hdr_sz - hdr_size, rex->body_fp);
                            rex->body_sz = rex->hdr_sz - hdr_size;
                            xfree(rex->hdr_buf);
                            rex->hdr_buf = NULL;
                            rex->hdr_sz = 0;
                            if (rex->size == rex->body_sz) {
                                if (req == TRUE) {
                                    rex->req_b = TRUE;
                                    rex->size = 0;
                                }
                                else {
                                    rex->res_b = TRUE;
                                    rex->compl = TRUE;
                                }
                                fclose(rex->body_fp);
                                rex->body_fp = NULL;
                            }
                        }
                        else {
                            fwrite(body_data, 1, rex->size, rex->body_fp);
                            rex->body_sz = rex->size;
                            if (req == TRUE) {
                                rex->req_b = TRUE;
                                rex->size = 0;
                            }
                            else {
                                rex->res_b = TRUE;
                                rex->compl = TRUE;
                            }
                            fclose(rex->body_fp);
                            rex->body_fp = NULL;
                            end = body_data + rex->size;
                            if (req == TRUE) {
                                rex->next = DMemMalloc(sizeof(http_com));
                                HttpComInit(rex->next);
                            }
                            else {
                                if (rex->next == NULL) {
                                    LogPrintf(LV_WARNING, "HTTP response without request2");
                                    return NULL;
                                }
                            }
                            rex->next->hdr_sz = rex->hdr_sz - (hdr_size + rex->body_sz);
                            rex->next->hdr_buf = xmalloc(rex->next->hdr_sz + 1);
                            memcpy(rex->next->hdr_buf, body_data+rex->body_sz, rex->next->hdr_sz);
                            rex->next->hdr_buf[rex->next->hdr_sz] = '\0';
                            xfree(rex->hdr_buf);
                            rex->hdr_buf = NULL;
                            rex->hdr_sz = 0;
                            serial = rex->serial;
                            start_cap = rex->start_cap;
                            rex = rex->next;
                            newh = TRUE;
                        }
                    }
                }
                else {
                    xfree(rex->hdr_buf);
                    rex->hdr_buf = NULL;
                    rex->hdr_sz = 0;
                    if (rex->chunked == TRUE) {
                        /* packet chunket alrady alligned */
                        rex->chk_cmpl = TRUE;
                    }
                    /* if body have zero byte size */
                    if (rex->size == 0 && rex->chunked == FALSE) {
                        if (req == TRUE) {
                            rex->req_b = TRUE;
                            rex->size = 0;
                        }
                        else {
                            rex->res_b = TRUE;
                            rex->compl = TRUE;
                        }
                        fclose(rex->body_fp);
                        rex->body_fp = NULL;
                    }
                }
            }
            else {
                if (req == TRUE) {
                    rex->req_b = TRUE;
                    rex->size = 0;
                }
                else {
                    rex->res_b = TRUE;
                    rex->compl = TRUE;
                }
                if (end - rex->hdr_buf < rex->hdr_sz) {
                    if (req == TRUE) {
                        rex->next = DMemMalloc(sizeof(http_com));
                        HttpComInit(rex->next);
                    }
                    else {
                        if (rex->next == NULL) {
                            LogPrintf(LV_WARNING, "HTTP response without request1");
                            return NULL;
                        }
                    }
                    rex->next->hdr_sz = rex->hdr_sz - (end - rex->hdr_buf);
                    rex->next->hdr_buf = xmalloc(rex->next->hdr_sz + 1);
                    memcpy(rex->next->hdr_buf, end, rex->next->hdr_sz);
                    rex->next->hdr_buf[rex->next->hdr_sz] = '\0';
                    xfree(rex->hdr_buf);
                    rex->hdr_buf = NULL;
                    rex->hdr_sz = 0;
                    serial = rex->serial;
                    start_cap = rex->start_cap;
                    rex = rex->next;
                    newh = TRUE;
                }
                else {
                    xfree(rex->hdr_buf);
                    rex->hdr_buf = NULL;
                    rex->hdr_sz = 0;
                }
            }
        }
    } while (newh);

    return rex;
}


static http_com* HttpExtractChunckedBody(http_com *rex, bool req)
{
    bool new;
    char *start, *data, *end, *c;
    int chunk_size;

    /* chunked trailer */
    if (rex->trailer == TRUE) {
        start = rex->chk_buf;
        end = rex->chk_buf + rex->chk_size;
        /* we consider a possibility that chuncked 0 size don't have in the same packet \r\n\r\n but only \r\n */
        if (rex->chk_size > 1 && rex->chk_buf[0] == '\r' && rex->chk_buf[1] == '\n') {
            start =  rex->chk_buf + 1;
        }
        else {
            start = HttpHeaderEnd(start, rex->chk_size);
        }
        if (start != NULL) {
            start++;
            rex->body_sz = 0;
            rex->chk_sz = 0;
            rex->chk_size = 0;
            if (rex->body_fp != NULL)
                fclose(rex->body_fp);
            rex->body_fp = NULL;
            if (req) {
                rex->req_b = TRUE;
                rex->size = 0;
            }
            else {
                rex->res_b = TRUE;
                rex->compl = TRUE;
            }
            if (start != end) {
                /* new header */
                if (req == TRUE) {
                    rex->next = DMemMalloc(sizeof(http_com));
                    HttpComInit(rex->next);
                    if (rex->hdr_buf != NULL && rex->res_h == TRUE) {
                        LogPrintf(LV_WARNING, "Verify this condiction (b)");
                        xfree(rex->hdr_buf);
                        rex->hdr_buf = NULL;
                        rex->hdr_sz = 0;
                    }
                }
                if (rex->next != NULL) {
                    rex->next->hdr_sz = rex->hdr_sz - (end - start);
                    rex->next->hdr_buf = xmalloc(rex->hdr_sz + 1);
                    memcpy(rex->next->hdr_buf, start, rex->next->hdr_sz);
                    rex->next->hdr_buf[rex->next->hdr_sz] = '\0';
                    rex = HttpExtractHeader(rex->next, req);
                    if (rex == NULL)
                        return NULL;
                }
                else {
                     LogPrintf(LV_ERROR, "Chunked trailer error");
                }
            }
        }
        else {
            start = strrchr(rex->chk_buf, '\n');
            if (start != NULL) {
                memcpy(rex->chk_buf, start, end - start);
                rex->chk_size = end - start;
                rex->chk_buf[rex->chk_size] = '\0';
            }
            else
                rex->chk_size = 0;
        }

        return rex;
    }

    /* new chunked block */
    do {
        new = FALSE;
        start = rex->chk_buf;
        end = rex->chk_buf + rex->chk_size;
        data = memchr(rex->chk_buf, '\n', rex->chk_size);
        if (data != NULL) {
            *data = '\0';
            /* We don't care about the extensions */
            c = start;
            if ((c = strchr(c, ';'))) {
                *c = '\0';
            }
            *data = '\n';
            data++;
            chunk_size = 0;
            if (sscanf(start, "%x", &chunk_size) != 1 || chunk_size < 0) {
                LogPrintf(LV_ERROR, "Chunked block error");
                return NULL;
            }
            rex->chk_sz = chunk_size;
            rex->body_sz = 0;
            rex->chk_cmpl = FALSE;
            if (chunk_size == 0) {
                rex->trailer = TRUE;
                start = HttpHeaderEnd(data-2, end-data+2);
                if (start != NULL) {
                    start++;
                    rex->body_sz = 0;
                    rex->chk_sz = 0;
                    rex->chk_size = 0;
                    fclose(rex->body_fp);
                    rex->body_fp = NULL;
                    if (req) {
                        rex->req_b = TRUE;
                        rex->size = 0;
                    }
                    else {
                        rex->res_b = TRUE;
                        rex->compl = TRUE;
                    }
                    if (start != end) {
                        /* new header */
                        if (req == TRUE) {
                            rex->next = DMemMalloc(sizeof(http_com));
                            HttpComInit(rex->next);
                            if (rex->hdr_buf != NULL && rex->res_h == TRUE) {
                                LogPrintf(LV_WARNING, "Verify this condiction (a)");
                                xfree(rex->hdr_buf);
                                rex->hdr_buf = NULL;
                                rex->hdr_sz = 0;
                            }
                        }
                        if (rex->next != NULL) {
                            rex->next->hdr_sz = end - start;
                            rex->next->hdr_buf = xmalloc(rex->next->hdr_sz + 1);
                            memcpy(rex->next->hdr_buf, start, rex->next->hdr_sz);
                            rex->next->hdr_buf[rex->next->hdr_sz] = '\0';
                            rex = HttpExtractHeader(rex->next, req);
                            if (rex == NULL)
                                return NULL;
                        }
                        else {
                            LogPrintf(LV_ERROR, "Chunked trailer error");
                        }
                    }
                }
                else {
                    rex->chk_cmpl = TRUE;
                    memcpy(rex->chk_buf, data, end - data);
                    rex->chk_size = end - data;
                    rex->chk_buf[rex->chk_size] = '\0';
                }
            }
            else if (end > data) {
                if (chunk_size < (end - data)) {
                    rex->body_sz = chunk_size;
                    fwrite(data, 1, chunk_size, rex->body_fp);
                    start = data + chunk_size;
                    start = memchr(start, '\n', end - start);
                    if (start != NULL) {
                        rex->body_sz = 0;
                        rex->chk_sz = 0;
                        rex->chk_cmpl = TRUE;
                        start++;
                        if (start < end) {
                            xmemcpy(rex->chk_buf, start, end - start);
                            rex->chk_size = end - start;
                            rex->chk_buf[rex->chk_size] = '\0';
                            new = TRUE;
                        }
                        else {
                            rex->chk_size = 0;
                        }
                    }
                }
                else {
                    rex->body_sz = end - data;
                    fwrite(data, 1, rex->body_sz, rex->body_fp);
                }
            }
            else {
                rex->chk_size = 0;
            }
        }
    } while (new);

    return rex;
}


static packet *HttpResyncHead(http_priv *priv, int flow_id)
{
    const char *eol, *lineend;
    char *data;
    unsigned long len;
    packet *pkt;
    ftval lost;
    http_ver ver;
    
    pkt = FlowGetPkt(flow_id);
    while (pkt != NULL) {
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE) {
            data = (char *)pkt->data;
            len = pkt->len;
            lineend = find_line_end(data, data+len, &eol);
            if (lineend != data+len && (*eol == '\r' || *eol == '\n')) {
                ver = HttpReqVersion(data, lineend-data);
                if (ver != HTTP_VER_NONE) {
                    if (HttpReqMethod(data, lineend-data, TRUE) != HTTP_MT_NONE) {
                        if (HttpClientPkt(priv, pkt) == FALSE)
                            priv->dir = HTTP_CLT_DIR_REVERS;
                        break;
                    }
                }
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    return pkt;
}


static int HttpGather(http_priv *priv, int flow_id)
{
    static unsigned long last_cap_time = 0;
    packet *pkt;
    http_com *req;
    http_com *res;
    ftval lost;
    char *tmp, *end;
    int dim;

    /* server packet queue */
    res = priv->msgl;
    if (res != NULL && res->compl == TRUE) {
        res->end_cap = last_cap_time;
        return 0;
    }

    /* client packet queue */
    req = priv->msgl;
    while (req != NULL && req->next != NULL)
        req = req->next;
    if (req == NULL) {
#ifdef XPL_CHECK_CODE
        if (res != NULL) {
            LogPrintf(LV_OOPS, "HTTP response without request");
            ProtStackFrmDisp(FlowStack(flow_id), TRUE);
            exit(-1);
        }
#endif
        req = DMemMalloc(sizeof(http_com));
        HttpComInit(req);
        priv->msgl = req;
        res = req;
    }
    
    do {
        /* new tcp packet */
        pkt = FlowGetPkt(flow_id);
        if (priv->dir == HTTP_CLT_DIR_NONE && pkt != NULL) {
            ProtGetAttr(pkt->stk, lost_id, &lost);
            if (lost.uint8 == TRUE) {
                PktFree(pkt);
                pkt = HttpResyncHead(priv, flow_id);
            }
        }
        if (pkt != NULL && pkt->len != 0) {
            /* last capture time */
            last_cap_time = pkt->cap_sec;
            /* check if there are packet lost */
            ProtGetAttr(pkt->stk, lost_id, &lost);
            //ProtStackFrmDisp(pkt->stk, TRUE);
            if (HttpClientPkt(priv, pkt)) {
                /* serial number */
                if (req->serial == 0) {
                    req->serial = pkt->serial;
                    req->start_cap = pkt->cap_sec;
                    LogPrintf(LV_DEBUG, "Req: %lu", req->start_cap);
                }
                /* client */
                if (req->req_b == TRUE) {
                    /* next request */
                    /* check lost packet */
                    if (lost.uint8 == TRUE) {
                        LogPrintf(LV_WARNING, "Packets lost in request new");
                        ProtStackFrmDisp(pkt->stk, TRUE);
                        PktFree(pkt);
                        return -1;
                    }
                    req->next = DMemMalloc(sizeof(http_com));
                    HttpComInit(req->next);
                    if (req->hdr_buf != NULL && req->res_h == TRUE) {
                        LogPrintf(LV_WARNING, "Verify this condiction (c)");
                        xfree(req->hdr_buf);
                        req->hdr_buf = NULL;
                        req->hdr_sz = 0;
                    }
                    req = req->next;
                    /* serial number */
                    req->serial = pkt->serial;
                    req->start_cap = pkt->cap_sec;
                    LogPrintf(LV_DEBUG, "Req: %lu", req->start_cap);
                }
                if (req->req_h == FALSE) {
                    /* request header */
                    /* check lost packet */
                    if (lost.uint8 == TRUE) {
                        LogPrintf(LV_WARNING, "Packets lost in request");
                        ProtStackFrmDisp(pkt->stk, TRUE);
                        PktFree(pkt);
                        return -1;
                    }
                    req->hdr_buf = xrealloc(req->hdr_buf, req->hdr_sz + pkt->len + 1);
                    memcpy(req->hdr_buf+req->hdr_sz, pkt->data, pkt->len);
                    req->hdr_sz += pkt->len;
                    req->hdr_buf[req->hdr_sz] = '\0';
                    req = HttpExtractHeader(req, TRUE);
                    if (req == NULL) {
                        PktFree(pkt);
                        return -1;
                    }
                }
                else {
                    /* request body */
                    if (req->chunked) {
                        if (lost.uint8 == TRUE) {
                            LogPrintf(LV_WARNING, "Packets lost in request body chunked");
                            ProtStackFrmDisp(pkt->stk, TRUE);
                            PktFree(pkt);
                            return -1;
                        }
                        if (req->chk_cmpl) {
                            if (req->chk_size + pkt->len > HTTP_CHUNKED_BUFF_SIZE) {
                                LogPrintf(LV_FATAL, "Temporary buffer too small");
                                exit(-1);
                            }
                            memcpy(req->chk_buf + req->chk_size, pkt->data, pkt->len);
                            req->chk_size += pkt->len;
                            req->chk_buf[req->chk_size] = '\0';
                            req = HttpExtractChunckedBody(req, TRUE);
                            if (req == NULL) {
                                PktFree(pkt);
                                return -1;
                            }
                        }
                        else {
                            if (req->chk_sz == req->body_sz) {
                                /* search CRLF */
                                end = pkt->data + pkt->len;
                                tmp = memchr(pkt->data, '\n', pkt->len);
                                if (tmp != NULL) {
                                    req->chk_cmpl = TRUE;
                                    if (end - tmp >= HTTP_CHUNKED_BUFF_SIZE) {
                                        LogPrintf(LV_FATAL, "Temporary buffer too small");
                                        ProtStackFrmDisp(priv->frame, TRUE);
                                        exit(-1);
                                    }
                                    memcpy(req->chk_buf, tmp, end - tmp);
                                    req->chk_size = end - tmp;
                                    req->chk_buf[req->chk_size] = '\0';
                                    req = HttpExtractChunckedBody(req, TRUE);
                                    if (req == NULL) {
                                        PktFree(pkt);
                                        return -1;
                                    }
                                }
                            }
                            else {
                                dim = req->chk_sz - req->body_sz;
                                if (pkt->len > dim) {
                                    fwrite(pkt->data, 1, dim, req->body_fp);
                                    req->body_sz = req->chk_sz;
                                    end = pkt->data + pkt->len;
                                    tmp = memchr(pkt->data+dim, '\n', pkt->len-dim);
                                    if (tmp != NULL) {
                                        tmp++;
                                        req->chk_cmpl = TRUE;
                                        if (end - tmp >= HTTP_CHUNKED_BUFF_SIZE) {
                                            LogPrintf(LV_FATAL, "Temporary buffer too small");
                                            ProtStackFrmDisp(priv->frame, TRUE);
                                            exit(-1);
                                        }
                                        memcpy(req->chk_buf, tmp, end - tmp);
                                        req->chk_size = end - tmp;
                                        req->chk_buf[req->chk_size] = '\0';
                                        req = HttpExtractChunckedBody(req, TRUE);
                                        if (req == NULL) {
                                            PktFree(pkt);
                                            return -1;
                                        }
                                    }
                                }
                                else {
                                    fwrite(pkt->data, 1, pkt->len, req->body_fp);
                                    req->body_sz += pkt->len;
                                }
                            }
                        }
                    }
                    else {
#ifdef XPL_CHECK_CODE
                        if (req->size < req->body_sz) {
                            LogPrintf(LV_OOPS, "HTTP reasemple request body");
                            ProtStackFrmDisp(pkt->stk, TRUE);
                            PktFree(pkt);
                            return -1;
                        }
#endif
                        dim = req->size - req->body_sz;
                        if (pkt->len > dim) {
                            if (lost.uint8 == TRUE) {
                                LogPrintf(LV_WARNING, "Packets lost in request body");
                                ProtStackFrmDisp(pkt->stk, TRUE);
                                PktFree(pkt);
                                return -1;
                            }
                            fwrite(pkt->data, 1, dim, req->body_fp);
                            req->body_sz = req->size;
                            req->req_b = TRUE;
                            req->size = 0;
                            fclose(req->body_fp);
                            req->body_fp = NULL;
                            req->next = DMemMalloc(sizeof(http_com));
                            HttpComInit(req->next);
                            req->next->hdr_sz = pkt->len - dim;
                            req->next->hdr_buf = xrealloc(req->next->hdr_buf, req->next->hdr_sz + 1);
                            memcpy(req->next->hdr_buf, pkt->data+dim, req->next->hdr_sz);
                            req = req->next;
                            /* serial number */
                            req->serial = pkt->serial;
                            req->start_cap = pkt->cap_sec;
                            req->hdr_buf[req->hdr_sz] = '\0';
                            req = HttpExtractHeader(req, TRUE);
                            if (req == NULL) {
                                PktFree(pkt);
                                return -1;
                            }
                        }
                        else {
                            if (lost.uint8 == TRUE) {
                                LogPrintf(LV_WARNING, "Packets lost in request body");
                                ProtStackFrmDisp(pkt->stk, TRUE);
                                tmp = xmalloc(pkt->len);
                                if (tmp != NULL) {
                                    memset(tmp, 0, pkt->len);
                                    fwrite(tmp, 1, pkt->len, req->body_fp);
                                    xfree(tmp);
                                    tmp = NULL;
                                    req->msg->error = ELMT_ER_HOLE; // hole in body
                                }
                            }
                            else {
                                fwrite(pkt->data, 1, pkt->len, req->body_fp);
                            }
                            req->body_sz += pkt->len;
                            if (req->size == req->body_sz) {
                                req->req_b = TRUE;
                                req->size = 0;
                                fclose(req->body_fp);
                                req->body_fp = NULL;
                            }
                        }
                    }
                }
            }
            else {
                /* serial number */
                if (res->serial == 0) {
                    res->serial = pkt->serial;
                    res->start_cap = pkt->cap_sec;
                }
                /* server */
                if (res->res_b == TRUE) {
                    if (res->next == NULL) {
                        LogPrintf(LV_WARNING, "HTTP response without request3");
                        PktFree(pkt);
                        return -1;
                    }
                    res = res->next;
                }
                /* check request */
                if (res->req_b != TRUE || res->req_h != TRUE) {
                    /* check lost packet */
                    if (lost.uint8 == TRUE) {
                        LogPrintf(LV_WARNING, "Packets lost in response header");
                        ProtStackFrmDisp(pkt->stk, TRUE);
                        PktFree(pkt);
                        return -1;
                    }
                    if (res->req_h != TRUE || HttpRespStatus(pkt->data, pkt->len) != HTTP_ST_100) {
                        LogPrintf(LV_WARNING, "HTTP response without request5");
                        ProtStackFrmDisp(pkt->stk, TRUE);
                        PktFree(pkt);

                        return -1;
                    }
                }

                if (res->res_h == FALSE) {
                    /* response header */
                    /* check lost packet */
                    if (lost.uint8 == TRUE) {
                        LogPrintf(LV_WARNING, "Packets lost in response header");
                        ProtStackFrmDisp(pkt->stk, TRUE);
                        PktFree(pkt);
                        return -1;
                    }
                    res->hdr_buf = xrealloc(res->hdr_buf, res->hdr_sz + pkt->len + 1);
                    memcpy(res->hdr_buf+res->hdr_sz, pkt->data, pkt->len);
                    res->hdr_sz += pkt->len;
                    res->hdr_buf[res->hdr_sz] = '\0';
                    res = HttpExtractHeader(res, FALSE);
                    if (res == NULL) {
                        LogPrintf(LV_WARNING, "HTTP response header");
                        ProtStackFrmDisp(pkt->stk, TRUE);
                        PktFree(pkt);
                        
                        return -1;
                    }
                }
                else {
                    /* response body */
                    if (res->chunked) {
                        /* chunked */
                        /* check lost packet */
                        if (lost.uint8 == TRUE) {
                            LogPrintf(LV_WARNING, "Packets lost in response chunked");
                            ProtStackFrmDisp(pkt->stk, TRUE);
                            PktFree(pkt);
                            return -1;
                        }
                        if (res->chk_cmpl) {
                            if (res->chk_size + pkt->len > HTTP_CHUNKED_BUFF_SIZE) {
                                LogPrintf(LV_FATAL, "Temporary buffer too small");
                                exit(-1);
                            }
                            memcpy(res->chk_buf + res->chk_size, pkt->data, pkt->len);
                            res->chk_size += pkt->len;
                            res->chk_buf[res->chk_size] = '\0';
                            res = HttpExtractChunckedBody(res, FALSE);
                            if (res == NULL) {
                                PktFree(pkt);
                                return -1;
                            }
                        }
                        else {
                            if (res->chk_sz == res->body_sz) {
                                /* search CRLF */
                                end = pkt->data + pkt->len;
                                tmp = memchr(pkt->data, '\n', pkt->len);
                                if (tmp != NULL) {
                                    tmp++;
                                    res->chk_cmpl = TRUE;
                                    memcpy(res->chk_buf, tmp, end - tmp);
                                    res->chk_size = end - tmp;
                                    res->chk_buf[res->chk_size] = '\0';
                                    res = HttpExtractChunckedBody(res, FALSE);
                                    if (res == NULL) {
                                        PktFree(pkt);
                                        return -1;
                                    }
                                }
                            }
                            else {
                                dim = res->chk_sz - res->body_sz;
                                if (pkt->len > dim) {
                                    fwrite(pkt->data, 1, dim, res->body_fp);
                                    res->body_sz += dim;
                                    end = pkt->data + pkt->len;
                                    tmp = memchr(pkt->data+dim, '\n', pkt->len-dim);
                                    if (tmp != NULL) {
                                        tmp++;
                                        res->chk_cmpl = TRUE;
                                        if (end - tmp >= HTTP_CHUNKED_BUFF_SIZE) {
                                            LogPrintf(LV_FATAL, "Temporary buffer too small");
                                            ProtStackFrmDisp(priv->frame, TRUE);
                                            exit(-1);
                                        }
                                        memcpy(res->chk_buf, tmp, end - tmp);
                                        res->chk_size = end - tmp;
                                        res->chk_buf[res->chk_size] = '\0';
                                        res = HttpExtractChunckedBody(res, FALSE);
                                        if (res == NULL) {
                                            PktFree(pkt);
                                            return -1;
                                        }
                                    }
                                }
                                else {
                                    fwrite(pkt->data, 1, pkt->len, res->body_fp);
                                    res->body_sz += pkt->len;
                                }
                            }
                        }
                    }
                    else {
                        /* not chunked */
                        dim = res->size - res->body_sz;
                        if (pkt->len > dim) {
                            /* check lost packet */
                            if (lost.uint8 == TRUE) {
                                LogPrintf(LV_WARNING, "Packets lost between response request");
                                ProtStackFrmDisp(pkt->stk, TRUE);
                                PktFree(pkt);
                                return -1;
                            }
                            fwrite(pkt->data, 1, dim, res->body_fp);
                            res->body_sz = res->size;
                            fclose(res->body_fp);
                            res->body_fp = NULL;
                            res->res_b = TRUE;
                            res->compl = TRUE;
                            if (res->next == NULL) {
                                /* it is possible that some server return 1 byte '\n' over the
                                   size specified (ex: PingServer) */
                                if (pkt->len - dim != 1 || pkt->data[dim] != '\n') {
                                    LogPrintf(LV_WARNING, "HTTP response without request4");
                                    PktFree(pkt);
                                    return -1;
                                }
                            }
                            else {
                                res->next->hdr_sz = pkt->len - dim;
                                res->next->hdr_buf = xrealloc(res->next->hdr_buf, res->next->hdr_sz + 1);
                                memcpy(res->next->hdr_buf, pkt->data+dim, res->next->hdr_sz);
                                res = res->next;
                                res->hdr_buf[res->hdr_sz] = '\0';
                                res = HttpExtractHeader(res, FALSE);
                                if (res == NULL) {
                                    PktFree(pkt);
                                    return -1;
                                }
                            }
                        }
                        else {
                            /* check lost packet */
                            if (lost.uint8 == TRUE) {
                                LogPrintf(LV_WARNING, "Packets lost in body response");
                                ProtStackFrmDisp(pkt->stk, TRUE);
                                tmp = xmalloc(pkt->len);
                                memset(tmp, 0, pkt->len);
                                fwrite(tmp, 1, pkt->len, res->body_fp);
                                xfree(tmp);
                                res->msg->error = ELMT_ER_HOLE; // hole in body
                            }
                            else {
                                fwrite(pkt->data, 1, pkt->len, res->body_fp);
                            }
                            res->body_sz += pkt->len;
                            if (res->size == res->body_sz) {
                                fclose(res->body_fp);
                                res->body_fp = NULL;
                                res->res_b = TRUE;
                                res->compl = TRUE;
                            }
                        }
                    }
                }
            }
            PktFree(pkt);
        }
        else {
            if (pkt == NULL) {
                if (res != NULL && res->close && res->res_h) { /* this is true only if response header close */
                    if (res->clength == 0 || res->clength <= res->body_sz) {
                        /* close body file */
                        if (res->body_fp != NULL) {
                            fclose(res->body_fp);
                            res->body_fp = NULL;
                        }
#ifdef XPL_CHECK_CODE
                        else {
                            LogPrintf(LV_WARNING, "Body, without body file");
                        }
#endif
                        res->compl = TRUE;
                    }
                    else {
                        return -1;
                    }
                }
                else {
                    return -1;
                }
            }
            else {
                /* check if lost... only syn in this case (len == 0) */
                ProtGetAttr(pkt->stk, lost_id, &lost);
                if (lost.uint8 == TRUE) {
                    LogPrintf(LV_WARNING, "Packets lost with len 0");
                }
                PktFree(pkt);
            }
        }
    } while (priv->msgl->compl == FALSE);

    /* time of last packet */
    if (res != NULL)
        res->end_cap = last_cap_time;

    return 0;
}


static packet* HttpDissector(int flow_id)
{
    packet *http_pkt, *pkt;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, ip_dst, info;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    char buffer[256];
    http_priv *priv;
    http_com *inser;
    struct stat info_file;

    priv = FlowPrivGet(flow_id);
    if (priv == NULL) {
        /* statup */
        LogPrintf(LV_DEBUG, "HTTP id: %d", flow_id);
        priv = DMemMalloc(sizeof(http_priv));
        memset(priv, 0, sizeof(http_priv));
        tcp = FlowStack(flow_id);
        ip = ProtGetNxtFrame(tcp);
        ProtGetAttr(tcp, port_src_id, &port_src);
        ProtGetAttr(tcp, port_dst_id, &port_dst);
        priv->port = port_src.uint16;
        priv->dir = HTTP_CLT_DIR_NONE;
        if (priv->port != port_dst.uint16)
            priv->port_diff = TRUE;
        priv->ipv6 = TRUE;
        if (ProtFrameProtocol(ip) == ip_id)
            priv->ipv6 = FALSE;

        if (priv->ipv6 == FALSE) {
            ProtGetAttr(ip, ip_src_id, &priv->ip);
            ProtGetAttr(ip, ip_dst_id, &ip_dst);
            ip_addr.s_addr = priv->ip.uint32;
            inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
            ip_addr.s_addr = ip_dst.uint32;
            inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
            LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
            LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);
        }
        else {
            ProtGetAttr(ip, ipv6_src_id, &priv->ip);
            ProtGetAttr(ip, ipv6_dst_id, &ip_dst);
            memcpy(ipv6_addr.s6_addr, priv->ip.ipv6, sizeof(priv->ip.ipv6));
            inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
            memcpy(ipv6_addr.s6_addr, ip_dst.ipv6, sizeof(priv->ip.ipv6));
            inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
            LogPrintf(LV_DEBUG, "\tSRC: [%s]:%d", ips_str, port_src.uint16);
            LogPrintf(LV_DEBUG, "\tDST: [%s]:%d", ipd_str, port_dst.uint16);
        }

        /* http base frame stack packet */
        priv->frame = ProtCreateFrame(prot_id);
        ProtSetNxtFrame(priv->frame, ProtCopyFrame(tcp, TRUE));

        FlowPrivPut(flow_id, priv);
    }

    http_pkt = NULL;

    if (HttpGather(priv, flow_id) == 0) {
        /* new message */
        if (priv->msgl != NULL) {
            inser =  priv->msgl;
            priv->msgl = inser->next;
            if (inser->msg != NULL) {
                /* new http packet */
                http_pkt = PktNew();
                http_pkt->stk = ProtCopyFrame(priv->frame, TRUE);

                /* set frame attribute */
                info.str = inser->msg->host;
                ProtInsAttr(http_pkt->stk, host_id, &info);
                if (inser->cnt_type != NULL) {
                    info.str = inser->cnt_type;
                }
                else {
                    info.str = "\0";
                }
                ProtInsAttr(http_pkt->stk, ctype_id, &info);
                info.str = inser->msg->client;
                ProtInsAttr(http_pkt->stk, uagent_id, &info);
                if (inser->msg->rsize != 0) {
                    sprintf(buffer, "%lu-%lu/%lu", inser->msg->rbase, inser->msg->rend, inser->msg->rsize);
                    info.str = buffer;
                }
                else if (inser->msg->rset != NULL) {
                    info.str = inser->msg->rset;
                }
                else
                    info.str = "\0";
                ProtInsAttr(http_pkt->stk, range_id, &info);
                if (inser->msg->content_encoding[1] != NULL) {
                    info.str = inser->msg->content_encoding[1];
                }
                else {
                    info.str = "\0";
                }
                ProtInsAttr(http_pkt->stk, encoding_id, &info);
                
                /* serial number */
                inser->msg->serial = inser->serial;
                http_pkt->serial = inser->serial;

                /* body size */
                inser->msg->req_body_size = 0;
                inser->msg->res_body_size = 0;
                if (inser->msg->req_body_file[0] != '\0') {
                    stat(inser->msg->req_body_file, &info_file);
                    inser->msg->req_body_size = info_file.st_size;
                }
                if (inser->msg->res_body_file[0] != '\0') {
                    stat(inser->msg->res_body_file, &info_file);
                    inser->msg->res_body_size = info_file.st_size;
                }

                /* capture times */
                inser->msg->start_cap = inser->start_cap;
                inser->msg->end_cap = inser->end_cap;
                http_pkt->cap_sec = inser->start_cap;

                /* pkt data */
                http_pkt->data = (char *)inser->msg;
                inser->msg = NULL;
                
                /* free memory */
                if (inser->cnt_type != NULL) {
                    DMemFree(inser->cnt_type);
                    inser->cnt_type = NULL;
                }
            }
#ifdef XPL_CHECK_CODE
            if (inser->body_fp != NULL) {
                LogPrintf(LV_OOPS, "FD body dont closed");
                ProtStackFrmDisp(http_pkt->stk, TRUE);
                exit(-1);
            }
#endif
            /* free data memory */
            DMemFree(inser);
        }
    }
    else {
        /* create partial http packet */
        if (priv->msgl != NULL) {
            inser =  priv->msgl;
            priv->msgl = inser->next;
            
            /* close file descriptr opened */
            if (inser->body_fp != NULL) {
                fclose(inser->body_fp);
            }
            if (inser->msg != NULL && inser->msg->mtd != HTTP_MT_NONE) {
                /* new http packet */
                http_pkt = PktNew();
                http_pkt->stk = ProtCopyFrame(priv->frame, TRUE);

                /* set frame attribute */
                info.str = inser->msg->host;
                ProtInsAttr(http_pkt->stk, host_id, &info);
                if (inser->cnt_type != NULL) {
                    info.str = inser->cnt_type;
                }
                else {
                    info.str = "\0";
                }
                ProtInsAttr(http_pkt->stk, ctype_id, &info);
                info.str = inser->msg->client;
                ProtInsAttr(http_pkt->stk, uagent_id, &info);
                if (inser->msg->rsize != 0) {
                    sprintf(buffer, "%lu-%lu/%lu", inser->msg->rbase, inser->msg->rend, inser->msg->rsize);
                    info.str = buffer;
                }
                else if (inser->msg->rset != NULL) {
                    info.str = inser->msg->rset;
                }
                else
                    info.str = "\0";
                ProtInsAttr(http_pkt->stk, range_id, &info);
                if (inser->msg->content_encoding[1] != NULL) {
                    info.str = inser->msg->content_encoding[1];
                }
                else {
                    info.str = "\0";
                }
                ProtInsAttr(http_pkt->stk, encoding_id, &info);
                
                /* serial number */
                inser->msg->serial = inser->serial;

                /* body size */
                inser->msg->req_body_size = 0;
                inser->msg->res_body_size = 0;
                if (inser->msg->req_body_file[0] != '\0') {
                    stat(inser->msg->req_body_file, &info_file);
                    inser->msg->req_body_size = info_file.st_size;
                }
                if (inser->msg->res_body_file[0] != '\0') {
                    stat(inser->msg->res_body_file, &info_file);
                    inser->msg->res_body_size = info_file.st_size;
                }

                /* error: data lost */
                inser->msg->error = ELMT_ER_PARTIAL;

                /* capture times */
                inser->msg->start_cap = inser->start_cap;
                inser->msg->end_cap = inser->end_cap;
                http_pkt->cap_sec = inser->start_cap;

                /* pkt data */
                http_pkt->data = (char *)inser->msg;
                inser->msg = NULL;
                
                /* free memory */
                if (inser->cnt_type != NULL) {
                    DMemFree(inser->cnt_type);
                    inser->cnt_type = NULL;
                }
                if (inser->hdr_buf != NULL) {
                    xfree(inser->hdr_buf);
                    inser->hdr_buf = NULL;
                }
            }

            /* free data memory */
            DMemFree(inser);
        }
        /* raw http file */
#if 1
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
#else
        /* all packets go to tcp garbage dissector */
#endif
    }

    /* end flow and data */
    if (priv->msgl == NULL) {
        if (FlowIsClose(flow_id) == TRUE && FlowGrpIsEmpty(flow_id) == TRUE) {
            FlowPrivPut(flow_id, NULL);
            ProtDelFrame(priv->frame);
            DMemFree(priv);
                        
            LogPrintf(LV_DEBUG, "HTTP... bye bye  fid:%d", flow_id);
        }
    }
    
    return http_pkt;
}


static packet* HttpMsgDissector(packet *pkt)
{
    http_msg *msg;
    pei *ppei;
    pei_component *cmpn;
    char tmp[32];
    packet *pkt_cp;
    const char *bnd;
    multipart_f *mpfile;
    multipart_f *nxt;

    ppei = NULL;

    /* display info */
    msg = (http_msg *)pkt->data;

#ifdef XPL_CHECK_CODE
    if (msg->serial == 0) {
        LogPrintf(LV_FATAL, "HTTP HttpMsgDissector serial error");
        exit(-1);
    }
#endif

    /* file extraction */
    bnd = HttpMsgBodyBoundary(msg, TRUE);
    if (msg->mtd == HTTP_MT_POST && bnd != NULL) {
        mpfile = FFormatMultipart(msg->req_body_file, bnd);
        //FFormatMultipartPrint(mpfile);
        nxt = mpfile;
        while (nxt) {
            if (nxt->file_path != NULL) {
                /* pei */
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
                /*  file */
                PeiNewComponent(&cmpn, pei_file_id);
                PeiCompCapTime(cmpn, msg->start_cap);
                PeiCompCapEndTime(cmpn, msg->end_cap);
                PeiCompAddFile(cmpn, nxt->file_name, nxt->file_path, 0);
                PeiAddComponent(ppei, cmpn);

                /* insert pei */
                PeiIns(ppei);
            }
            nxt = nxt->nxt;
        }
        FFormatMultipartFree(mpfile);
    }
    /* pei */
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
    /*   clent */
    PeiNewComponent(&cmpn, pei_client_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    PeiCompAddStingBuff(cmpn, msg->client);
    PeiAddComponent(ppei, cmpn);
    /*   host */
    PeiNewComponent(&cmpn, pei_host_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    PeiCompAddStingBuff(cmpn, msg->host);
    PeiAddComponent(ppei, cmpn);
    /*   content_type */
    if (msg->content_type[0] != NULL) {
        PeiNewComponent(&cmpn, pei_content_type);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddStingBuff(cmpn, msg->content_type[0]);
        PeiAddComponent(ppei, cmpn);
    }
    if (msg->content_type[1] != NULL) {
        PeiNewComponent(&cmpn, pei_content_type);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddStingBuff(cmpn, msg->content_type[1]);
        PeiAddComponent(ppei, cmpn);
    }
    /*   method */
    PeiNewComponent(&cmpn, pei_method_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    PeiCompAddStingBuff(cmpn,  meth[msg->mtd]);
    PeiAddComponent(ppei, cmpn);
    /*   status */
    PeiNewComponent(&cmpn, pei_status_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    sprintf(tmp, "%i", msg->status);
    PeiCompAddStingBuff(cmpn, tmp);
    PeiAddComponent(ppei, cmpn);
    /*   req hdr */
    if (msg->req_hdr_file) {
        PeiNewComponent(&cmpn, pei_req_header_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddFile(cmpn, NULL, msg->req_hdr_file, msg->req_hdr_size);
        if (msg->error && msg->req_body_size == 0 && msg->res_hdr_size == 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
        PeiAddComponent(ppei, cmpn);
    }
    /*   req body */
    if (msg->req_body_size) {
        PeiNewComponent(&cmpn, pei_req_body_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddFile(cmpn, NULL, msg->req_body_file, msg->req_body_size);
        if (msg->error && msg->res_hdr_size == 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
        PeiAddComponent(ppei, cmpn);
    }
    /*   res hdr */
    if (msg->res_hdr_size) {
        PeiNewComponent(&cmpn, pei_res_header_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddFile(cmpn, NULL, msg->res_hdr_file, msg->res_hdr_size);
        if (msg->error && msg->res_body_size == 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
        PeiAddComponent(ppei, cmpn);
    }
    /*   res body */
    if (msg->res_body_size) {
        PeiNewComponent(&cmpn, pei_res_body_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiCompAddFile(cmpn, NULL, msg->res_body_file, msg->res_body_size);
        if (msg->error == ELMT_ER_HOLE) {
            PeiCompError(cmpn, ELMT_ER_HOLE);
        }
        else if (msg->error != 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
        PeiAddComponent(ppei, cmpn);
    }

    /* forward pkt to http file download dissector */
    if (msg->error == ELMT_ER_PARTIAL && msg->status == HTTP_ST_200 && msg->res_body_size && httpfd_id != -1) {
        pkt_cp = HttpMsgPktCpy(pkt);
        if (ProtDissecPkt(httpfd_id, pkt_cp) != NULL) {
            LogPrintf(LV_ERROR, "Pkt removed!");
        }
    }
    
    /* free memory */
    if (pkt != NULL) {
        HttpMsgFree(msg);
        PktFree(pkt);
    }

    /* insert pei */
    PeiIns(ppei);

    return NULL;
}


static bool HttpVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    char *data, *new, *rdata;
    const char *eol, *lineend;
    unsigned long len, rlen;
    int cmp, i;
    http_ver ver;
    bool ret, fr_data, method;
    ftval lost, ips, ip_s, port;
    bool ipv4;
    bool resync;

    ipv4 = FALSE;
    ret = FALSE;
    fr_data = FALSE;
    method = FALSE;
    resync = FALSE;
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
        if (lost.uint8 == TRUE) {
            resync = TRUE;
            if (check == TRUE) {
                /* check if src port is a standards port */
                ProtGetAttr(pkt->stk, port_src_id, &port);
                for (i=0; i!=std_ports_dim; i++) {
                    if (port.uint16 == std_ports[i]) {
                        check = FALSE;
                        break;
                    }
                }
            }
            if (check == FALSE) {
                /* only if there is a packet lost in head ho stream and port
                   of server is standard, then we try to identify http */
                PktFree(pkt);
                pkt = FlowGetPktCp(flow_id);
                if (pkt != NULL) {
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                }
                resync = TRUE;
            }
        }
        while (pkt != NULL && lost.uint8 == FALSE && pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL) {
                break;
            }
            ProtGetAttr(pkt->stk, lost_id, &lost);
        }
        if (resync == TRUE && pkt != NULL) { /* find the first http method */
            do {
                ProtGetAttr(pkt->stk, lost_id, &lost);
                if (lost.uint8 == FALSE) {
                    data = (char *)pkt->data;
                    len = pkt->len;
                    lineend = find_line_end(data, data+len, &eol);
                    if (lineend != data+len && (*eol == '\r' || *eol == '\n')) {
                        ver = HttpReqVersion(data, lineend-data);
                        if (ver != HTTP_VER_NONE) {
                            if (HttpReqMethod(data, lineend-data, TRUE) != HTTP_MT_NONE) {
                                break;
                            }
                        }
                    }
                }
                PktFree(pkt);
                pkt = FlowGetPktCp(flow_id);
            } while (pkt != NULL);
        }
    }
    if (pkt != NULL) {
        if (lost.uint8 == FALSE) {
            data = (char *)pkt->data;
            len = pkt->len;
            do {
                lineend = find_line_end(data, data+len, &eol);
                if (lineend != data+len && (*eol == '\r' || *eol == '\n')) {
                    ver = HttpReqVersion(data, lineend-data);
                    if (ver != HTTP_VER_NONE) {
                        if (HttpReqMethod(data, lineend-data, TRUE) != HTTP_MT_NONE) {
                            /* to garanty a complete header to other ProtCheck protocol */
                            if (HttpHeaderEnd(data, len) != NULL) {
                                method = TRUE;
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
                do {
                    PktFree(pkt);
                    pkt = FlowGetPktCp(flow_id);
                    if (pkt != NULL) {
                        if (method && check == FALSE) {
                            ret = TRUE;
                            break;
                        }
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
                            ProtGetAttr(pkt->stk, lost_id, &lost);
                            if (lost.uint8 == FALSE) {
                                if (method == FALSE) {
                                    new = xrealloc(data, len+pkt->len+1);
                                    if (new == NULL) {
                                        LogPrintf(LV_WARNING, "Memmory unavailable");
                                        break;
                                    }
                                    data = new;
                                    memcpy(data+len, pkt->data, pkt->len);
                                    len += pkt->len;
                                    data[len] = '\0';
                                    break; /* to new test; see up*/
                                }
                                else {
                                    continue;
                                }
                            }
                            else {
                                /* end */
                                PktFree(pkt);
                                pkt = NULL;
                            }
                        }
                        else if (method == TRUE) {
                            ProtGetAttr(pkt->stk, lost_id, &lost);
                            if (lost.uint8 == FALSE) {
                                rdata = (char *)pkt->data;
                                rlen = pkt->len;
                                /* check if the first responce has HTTP */
                                lineend = find_line_end(rdata, rdata+rlen, &eol);
                                if (lineend != rdata+rlen && (*eol == '\r' || *eol == '\n')) {
                                    if (HttpRespStatus(rdata, lineend-rdata) != HTTP_ST_NONE) {
                                        ret = TRUE;
                                    }
                                }
                            }
                            PktFree(pkt);
                            pkt = NULL;
                        }
                    }
                } while (pkt != NULL);
            } while (ret == FALSE && pkt != NULL && len < 4096); /* 4k: max http request length */
            if (method == TRUE && FlowIsClose(flow_id) == TRUE) {
                ret = TRUE;
            }
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


static bool HttpVerify(int flow_id)
{
    return HttpVerifyCheck(flow_id, FALSE);
}


static bool HttpCheck(int flow_id)
{
    return HttpVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;
    unsigned short i;

    /* init */
    std_ports_dim = sizeof(std_ports)/sizeof(unsigned short);
    
    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Hypertext Transfer Protocol", "http");
           
    /* user agent */
    info.name = "User-Agent";
    info.abbrev = "http.user_agent";
    info.type = FT_STRING;
    uagent_id = ProtInfo(&info);

    /* host */
    info.name = "Host";
    info.abbrev = "http.host";
    info.type = FT_STRING;
    host_id = ProtInfo(&info);

    /* content type */
    info.name = "Content-Type";
    info.abbrev = "http.content_type";
    info.type = FT_STRING;
    ctype_id = ProtInfo(&info);

    /* content range */
    info.name = "Content-Range";
    info.abbrev = "http.content_range";
    info.type = FT_STRING;
    range_id = ProtInfo(&info);

    /* content encoding */
    info.name = "Content-Encoding";
    info.abbrev = "http.content_encoding";
    info.type = FT_STRING;
    encoding_id = ProtInfo(&info);

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.ProtCheck = HttpVerify;
    dep.pktlim = HTTP_PKT_VER_LIMIT;
    for (i=0; i!=std_ports_dim; i++) {
        dep.val.uint16 = std_ports[i];
        ProtDep(&dep);
    }

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = HttpCheck;
    hdep.pktlim = HTTP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);

    peic.abbrev = "client";
    peic.desc = "Client";
    ProtPeiComponent(&peic);

    peic.abbrev = "host";
    peic.desc = "Host";
    ProtPeiComponent(&peic);

    peic.abbrev = "content_type";
    peic.desc = "Content Type";
    ProtPeiComponent(&peic);

    peic.abbrev = "method";
    peic.desc = "Method";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "status";
    peic.desc = "Status response";
    ProtPeiComponent(&peic);

    peic.abbrev = "req.header";
    peic.desc = "Request header";
    ProtPeiComponent(&peic);

    peic.abbrev = "req.body";
    peic.desc = "Request body";
    ProtPeiComponent(&peic);

    peic.abbrev = "res.header";
    peic.desc = "Response header";
    ProtPeiComponent(&peic);

    peic.abbrev = "res.body";
    peic.desc = "Response body";
    ProtPeiComponent(&peic);

    peic.abbrev = "boundary";
    peic.desc = "Boundary contents";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, HttpDissector, NULL, HttpMsgDissector);

    return 0;
}


int DissectInit(void)
{
    int tcp_id;
    char http_dir[256];

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
    prot_id = ProtId("http");
    httpfd_id = ProtId("httpfd");
    
    /* pei id */
    pei_url_id = ProtPeiComptId(prot_id, "url");
    pei_client_id = ProtPeiComptId(prot_id, "client");
    pei_host_id = ProtPeiComptId(prot_id, "host");
    pei_content_type = ProtPeiComptId(prot_id, "content_type");
    pei_method_id = ProtPeiComptId(prot_id, "method");
    pei_status_id = ProtPeiComptId(prot_id, "status");
    pei_req_header_id = ProtPeiComptId(prot_id, "req.header");
    pei_req_body_id = ProtPeiComptId(prot_id, "req.body");
    pei_res_header_id = ProtPeiComptId(prot_id, "res.header");
    pei_res_body_id = ProtPeiComptId(prot_id, "res.body");
    pei_file_id = ProtPeiComptId(prot_id, "boundary");

    /* http tmp directory */
    sprintf(http_dir, "%s/%s", ProtTmpDir(), HTTP_TMP_DIR);
    mkdir(http_dir, 0x01FF);

    return 0;
}
