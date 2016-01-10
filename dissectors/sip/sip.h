/* sip.h
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


#ifndef __SIP_H__
#define __SIP_H__

#include <stdio.h>

#include "packet.h"
#include "sdp.h"
#include "pei.h"


/* path buffer size */
#define SIP_FILENAME_PATH_SIZE        256
#define SIP_HEADER_LINE               1024

/* standard port */
#define TCP_PORT_SIP 5060
#define UDP_PORT_SIP 5060
#define TLS_PORT_SIP 5061

/* packets limit for SipVerify, SipCheck */
#define SIP_PKT_VER_LIMIT        15
#define SIP_PKT_NULL_LIMIT       10
#define SIP_PKT_RESP_ONLY         3

#define SIP_PKT_TIMEOUT         200
#define SIP_SDP_TO               10

typedef enum _sip_mthd sip_mthd;
enum _sip_mthd {
    SIP_MT_ACK = 0,
    SIP_MT_BYE,
    SIP_MT_CANCEL,
    SIP_MT_DO,
    SIP_MT_INFO,
    SIP_MT_INVITE,
    SIP_MT_MESSAGE,
    SIP_MT_NOTIFY,
    SIP_MT_OPTIONS,
    SIP_MT_PRACK,
    SIP_MT_QAUTH,
    SIP_MT_REFER,
    SIP_MT_REGISTER,
    SIP_MT_SPRACK,
    SIP_MT_SUBSCRIBE,
    SIP_MT_UPDATE,
    SIP_MT_PUBLISH,
    SIP_MT_NONE,
};


typedef enum _sip_ver sip_ver;
enum _sip_ver {
    SIP_VER_2_0,
    SIP_VER_NONE
};


typedef enum _sip_status sip_status;
enum _sip_status {
    SIP_ST_NONE, /* uncknow staus */
    SIP_ST_1XX,  /* Provisional */
    SIP_ST_2XX,  /* Success */
    SIP_ST_3XX,  /* Redirection */
    SIP_ST_4XX,  /* Client Error */
    SIP_ST_5XX,  /* Server Error */
    SIP_ST_6XX   /* Global Failure */
};

/* media type */
typedef enum {
    MT_NONE = 0,
    MT_AUDIO,
    MT_VIDEO
} media_tp;



/* sip message */
typedef struct _sip_msg sip_msg;
struct _sip_msg {
    sip_mthd mtd;                  /* req method */
    sip_status status;             /* resp status */
    char call_id[SIP_HEADER_LINE]; /* Call-ID */
    char cseq[SIP_HEADER_LINE];    /* CSeq */
    char ltag[SIP_HEADER_LINE];    /* local tag */
    char rtag[SIP_HEADER_LINE];    /* remote tag */
    bool hdr;                      /* header complete or not */
    bool compl;                    /* message completed or not */
    char *start_line;              /* start-line */
    char *header;                  /* message-header */
    char *body;                    /* message-body */
    unsigned long hdr_size;        /* header size */
    unsigned long bd_size;         /* body size */
    sip_msg *nxt;                  /* next msg with same call-id */
};


typedef struct _media_storage media_storage;
struct _media_storage {
    char file_name[SIP_FILENAME_PATH_SIZE];  /* file name ;) */
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


/* sip call */
typedef struct _sip_call sip_call;
struct _sip_call {
    char id[SIP_HEADER_LINE];   /* Call-ID */
    char from[SIP_HEADER_LINE];
    char to[SIP_HEADER_LINE];
    char cmd_file[SIP_FILENAME_PATH_SIZE];
    FILE *cmd_fp;    /* commands file pointer */
    time_t start_time_sec;  /* fist packet time */
    time_t end_time_sec;    /* last packet time */
    sdp_msg *sdp_cr; /* sdp caller */
    sdp_msg *sdp_cd; /* sdp called */
    bool closed;  /* call end */
    /* audio */
    int rule_cr_id;    /* rule (provisional code) */
    int rule_cd_id;    /* rule (provisional code) */
    bool sdp;          /* call with or wtout SDP */
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
    sip_call *nxt;
};


#endif /* __SIP_H__ */
