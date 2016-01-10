/* http.c
 * common functions to manage http packet
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <string.h>
#include <stdio.h>

#include "dmemory.h"
#include "http.h"
#include "log.h"
#include "fileformat.h"
#include "proto.h"

static unsigned int rndn = 0;

void HttpMsgPrint(const http_msg *msg)
{
    if (msg->uri) {
        LogPrintf(LV_DEBUG, "URI: %s", msg->uri);
    }
    if (msg->host) {
        LogPrintf(LV_DEBUG, "  Host: %s", msg->host);
    }
    if (msg->content_type[0]) {
        LogPrintf(LV_DEBUG, "  Content-Type (request): %s", msg->content_type[0]);
    }
    if (msg->content_type[1]) {
        LogPrintf(LV_DEBUG, "  Content-Type: %s", msg->content_type[1]);
    }
    if (msg->content_encoding[0]) {
        LogPrintf(LV_DEBUG, "  Content-Encoding (request): %s", msg->content_encoding[0]);
    }
    if (msg->content_encoding[1]) {
        LogPrintf(LV_DEBUG, "  Content-Encoding: %s", msg->content_encoding[1]);
    }
    if (msg->rset) {
        LogPrintf(LV_DEBUG, "  Range: %s", msg->rset);
    }
    if (msg->client) {
        LogPrintf(LV_DEBUG, "  Client: %s", msg->client);
    }
    if (msg->req_hdr_file) {
        LogPrintf(LV_DEBUG, "  Req Header: %s", msg->req_hdr_file);
    }
    if (msg->req_body_file) {
        LogPrintf(LV_DEBUG, "  Req Body: %s", msg->req_body_file);
    }
    if (msg->res_hdr_file) {
        LogPrintf(LV_DEBUG, "  Resp Header: %s", msg->res_hdr_file);
    }
    if (msg->res_body_file) {
        LogPrintf(LV_DEBUG, "  Resp Body: %s", msg->res_body_file);
    }
}


void HttpMsgFree(http_msg *msg)
{
    DMemFree(msg->uri);
    DMemFree(msg->host);
    if (msg->content_type[0])
        DMemFree(msg->content_type[0]);
    if (msg->content_type[1])
        DMemFree(msg->content_type[1]);
    if (msg->content_encoding[0])
        DMemFree(msg->content_encoding[0]);
    if (msg->content_encoding[1])
        DMemFree(msg->content_encoding[1]);
    if (msg->rset)
        DMemFree(msg->rset);
    DMemFree(msg->client);
    DMemFree(msg->req_hdr_file);
    DMemFree(msg->req_body_file);
    DMemFree(msg->res_hdr_file);
    DMemFree(msg->res_body_file);
}


packet *HttpMsgPktCpy(const packet *pkt)
{
    const http_msg *orig;
    http_msg *msg;
    packet *new;

    msg = DMemMalloc(sizeof(http_msg));
    memset(msg, 0, sizeof(http_msg));
    orig = (http_msg *)pkt->data;

    msg->mtd = orig->mtd;
    msg->status = orig->status;
    msg->rbase = orig->rbase;
    msg->rend = orig->rend;
    msg->rsize = orig->rsize;
    msg->req_hdr_size = orig->req_hdr_size;
    msg->req_body_size = orig->req_body_size;
    msg->res_hdr_size = orig->res_hdr_size;
    msg->res_body_size = orig->res_body_size;
    msg->error = orig->error;
    msg->serial = orig->serial;
    msg->start_cap = orig->start_cap;
    msg->end_cap = orig->end_cap;
    if (orig->uri) {
        msg->uri = DMemMalloc(strlen(orig->uri)+1);
        strcpy(msg->uri, orig->uri);
    }
    if (orig->host) {
        msg->host = DMemMalloc(strlen(orig->host)+1);
        strcpy(msg->host, orig->host);
    }
    if (orig->content_type[0]) {
        msg->content_type[0] = DMemMalloc(strlen(orig->content_type[0])+1);
        strcpy(msg->content_type[0], orig->content_type[0]);
    }
    if (orig->content_type[1]) {
        msg->content_type[1] = DMemMalloc(strlen(orig->content_type[1])+1);
        strcpy(msg->content_type[1], orig->content_type[1]);
    }
    if (orig->content_encoding[0]) {
        msg->content_encoding[0] = DMemMalloc(strlen(orig->content_encoding[0])+1);
        strcpy(msg->content_encoding[0], orig->content_encoding[0]);
    }
    if (orig->content_encoding[1]) {
        msg->content_encoding[1] = DMemMalloc(strlen(orig->content_encoding[1])+1);
        strcpy(msg->content_encoding[1], orig->content_encoding[1]);
    }
    if (orig->rset) {
        msg->rset = DMemMalloc(strlen(orig->rset)+1);
        strcpy(msg->rset, orig->rset);
    }
    if (orig->client) {
        msg->client = DMemMalloc(strlen(orig->client)+1);
        strcpy(msg->client, orig->client);
    }
    if (orig->req_hdr_size) {
        msg->req_hdr_file = DMemMalloc(strlen(orig->req_hdr_file)+5);
        sprintf(msg->req_hdr_file, "%s_%i", orig->req_hdr_file, rndn);
        FFormatCopy(orig->req_hdr_file, msg->req_hdr_file);
    }
    if (orig->req_body_size) {
        msg->req_body_file = DMemMalloc(strlen(orig->req_body_file)+5);
        sprintf(msg->req_body_file, "%s_%i", orig->req_body_file, rndn);
        FFormatCopy(orig->req_body_file, msg->req_body_file);
    }
    if (orig->res_hdr_size) {
        msg->res_hdr_file = DMemMalloc(strlen(orig->res_hdr_file)+5);
        sprintf(msg->res_hdr_file, "%s_%i", orig->res_hdr_file, rndn);
        FFormatCopy(orig->res_hdr_file, msg->res_hdr_file);
    }
    if (orig->res_body_size) {
        msg->res_body_file = DMemMalloc(strlen(orig->res_body_file)+5);
        sprintf(msg->res_body_file, "%s_%i", orig->res_body_file, rndn);
        FFormatCopy(orig->res_body_file, msg->res_body_file);
    }

    /* new packet */
    new = PktNew();
    new->stk = ProtCopyFrame(pkt->stk, TRUE);
    new->serial = pkt->serial;
    new->cap_sec = pkt->cap_sec;
    new->data = (char *)msg;

    /* to change the name without replace */
    rndn++;

    return new;
}


void HttpMsgRemove(http_msg *msg)
{
    if (msg->req_hdr_file)
        remove(msg->req_hdr_file);
    if (msg->req_body_file)
        remove(msg->req_body_file);
    if (msg->res_hdr_file)
        remove(msg->res_hdr_file);
    if (msg->res_body_file)
        remove(msg->res_body_file);
}


const char *HttpMsgBodyBoundary(const http_msg *msg, bool req)
{
    char *bnd;
    unsigned short i;

    if (req)
        i = 0;
    else
        i = 1;

    if (msg->content_type[i] == NULL)
        return NULL;
    
    bnd = strstr(msg->content_type[i], "boundary=");
    if (bnd == NULL) {
        return NULL;
    }
    bnd += 9; /* "boundary=" size */

    return bnd;
}


void http_link(void)
{

}
