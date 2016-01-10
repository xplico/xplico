/* http_com.h
 *
 * $Id: http_com.h,v 1.5 2007/06/05 17:57:11 costa Exp $
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
 */


#ifndef __HTTP_COM_H__
#define __HTTP_COM_H__

#include <stdio.h>

#include "http.h"

/* path buffer size */
#define HTTP_FILENAME_PATH_SIZE        256
#define HTTP_CHUNKED_BUFF_SIZE         16318

/* standard port */
#define TCP_PORTS_HTTP {80, 8080, 3128, 3132, 8088, 11371, 3689}

/* packets limit for HttpVerify, HttpCheck */
#define HTTP_PKT_VER_LIMIT             15

typedef enum _http_client_dir  http_client_dir;
enum _http_client_dir {
    HTTP_CLT_DIR_NONE,
    HTTP_CLT_DIR_OK,
    HTTP_CLT_DIR_REVERS
};


typedef struct _http_st_code http_st_code;
struct _http_st_code {
    int num;          /* status code number */
    http_status st;   /* status */
};


typedef struct _http_com http_com;
struct _http_com {
    http_msg *msg;          /* new http message */
    char *cnt_type;         /* Content-Type */
    time_t start_cap;       /* start capture time */
    time_t end_cap;         /* end capture time */
    bool req_h;             /* state of message request header */
    bool req_b;             /* state of message request body */
    bool res_h;             /* state of message response header */
    bool res_b;             /* state of message response body */
    bool compl;             /* message terminataed (whit or without error) */
    unsigned long serial;   /* serial number (used in pei) */
    char *hdr_buf;          /* buffer of incomplete request header */
    FILE *body_fp;          /* file descriptor of body */
    bool close;             /* connection: close */
    bool chunked;           /* body from server is chanked */
    bool trailer;           /* search trailer */
    bool chk_cmpl;          /* chunked block completed */
    char chk_buf[HTTP_CHUNKED_BUFF_SIZE]; /* temporany buffer for chunked data */
    int chk_size;           /* chk_buf size */
    unsigned long hdr_sz;   /* temporany size of header */
    unsigned long chk_sz;   /* chanked block size */
    unsigned long body_sz;  /* body/chunked byte received */
    unsigned long size;     /* body dimension */
    unsigned long clength;  /* Content-Length */
    http_com *next;         /* next message pipeline */
};


typedef struct _http_priv http_priv;
struct _http_priv {
    bool port_diff;         /* connection with different port */
    http_client_dir dir;    /* real direction of client */
    unsigned short port;    /* source port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip;               /* ip source */
    http_com *msgl;         /* message list */
    pstack_f *frame;        /* frame base of flow */
};

#endif /* __HTTP_COM_H__ */
