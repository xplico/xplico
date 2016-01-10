/* mgcp.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __MGCP_H__
#define __MGCP_H__

#include <stdio.h>

#include "packet.h"
#include "sdp.h"
#include "pei.h"


/* path buffer size */
#define MGCP_FILENAME_PATH_SIZE        256
#define MGCP_HEADER_LINE               1024

/* standard port */
#define UDP_PORT_MGCP 2427
#define TCP_PORT_MGCP 2427
#define UDP_PORT_MGCP_CA 2727
#define TCP_PORT_MGCP_CA 2727

/* packets limit for MgcpVerify, MgcpCheck */
#define MGCP_PKT_VER_LIMIT        15
#define MGCP_PKT_NULL_LIMIT       10

#define MGCP_PKT_TIMEOUT         200

typedef enum _mgcp_mthd mgcp_mthd;
enum _mgcp_mthd {
    MGCP_MT_AUEP = 0,
    MGCP_MT_AUCX,
    MGCP_MT_CRCX,
    MGCP_MT_DLCX,
    MGCP_MT_EPCF,
    MGCP_MT_MDCX,
    MGCP_MT_NTFY,
    MGCP_MT_RQNT,
    MGCP_MT_RSIP,
    MGCP_MT_NONE
};


typedef enum _mgcp_ver mgcp_ver;
enum _mgcp_ver {
    MGCP_VER_1_0,
    MGCP_VER_NONE
};


#define MGCP_ST_RESP_FIRST    0
#define MGCP_ST_RESP_LAST     541

typedef enum _mgcp_status mgcp_status;
enum _mgcp_status {
    MGCP_ST_200,
    MGCP_ST_VALID,
    MGCP_ST_NONE /* uncknow staus */
};

/* media type */
typedef enum {
    MT_NONE = 0,
    MT_AUDIO,
    MT_VIDEO
} media_tp;



/* mgcp message */
typedef struct _mgcp_msg mgcp_msg;
struct _mgcp_msg {
    mgcp_mthd mtd;                  /* req method */
    mgcp_status status;             /* resp status */
    char tran_id[MGCP_HEADER_LINE]; /* transaction ID */
    char conn_id[MGCP_HEADER_LINE]; /* connection ID */
    char call_id[MGCP_HEADER_LINE]; /* call ID */
    bool hdr;                      /* header complete or not */
    bool compl;                    /* message completed or not */
    char *start_line;              /* start-line */
    char *header;                  /* message-header */
    char *body;                    /* message-body */
    unsigned long hdr_size;        /* header size */
    unsigned long bd_size;         /* body size */
    mgcp_msg *nxt;                 /* next msg with same call-id */
};


typedef struct _media_storage media_storage;
struct _media_storage {
    char file_name[MGCP_FILENAME_PATH_SIZE];  /* file name ;) */
    unsigned short media_num;   /* number of media that use this file as storage */
    FILE *fp;    /* if not NULL the file is open */
};


typedef struct _rtx_media rtx_media;
struct _rtx_media {
    /* media type */
    media_tp mtp;            /**< media type */
    media_storage *strg;     /**< media storage */
    /* ip type */
    bool ipv6;
    ftval ip_dst;            /**< IP destination */
    /* rtp */
    ftval dst_port;          /**< destination port */
    unsigned long ssrc;      /**< ssrc of rtp */
    unsigned char pt;        /**< payload type */
    time_t start_time_sec;   /**< fist packet time */
    time_t start_time_usec;  /**< fist packet time */
    time_t end_time_sec;     /**< last packet time */
    unsigned long pkt_num;   /**< total packets number */
    /* rtcp */
    ftval c_dst_port;        /**< destination port */
    rtx_media *nxt;          /**< media with different ssrc or pt */
};


/* mgcp call */
typedef struct _mgcp_call mgcp_call;
struct _mgcp_call {
    char id[MGCP_HEADER_LINE];      /* connection ID */
    char tran_id[MGCP_HEADER_LINE]; /* frist transaction ID */
    char from[MGCP_HEADER_LINE];
    char to[MGCP_HEADER_LINE];
    char cmd_file[MGCP_FILENAME_PATH_SIZE];
    FILE *cmd_fp;    /* commands file pointer */
    time_t start_time_sec;  /* fist packet time */
    time_t end_time_sec;    /* last packet time */
    sdp_msg *sdp_cr; /* sdp caller */
    sdp_msg *sdp_cd; /* sdp called */
    bool closed;  /* call end */
    /* audio */
    int rule_cr_id;    /* rule (provisional code) */
    int rule_cd_id;    /* rule (provisional code) */
    int audio_rtp_cr;     /* flow id of audio caller */
    int audio_rtp_cd;     /* flow id of audio called */
    int audio_rtcp_cr;    /* flow id of audio caller */
    int audio_rtcp_cd;    /* flow id of audio called */
    rtx_media audio_cr;// *audio_cr;  /* rtp and rtcp audio caller */
    rtx_media audio_cd;// *audio_cd;  /* rtp and rtcp audio called */
    /* to complete */
    media_storage cr;// to remove and improve
    media_storage cd;// to remove and improve
    /* video */
    /* pei */
    pei *ppei;
    mgcp_call *nxt;
};


#endif /* __MGCP_H__ */
