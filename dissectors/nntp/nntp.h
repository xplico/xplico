/* nntp.h
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


#ifndef __NNTP_H__
#define __NNTP_H__

#include <stdio.h>

/* standard port */
#define TCP_PORT_NNTP                  119

/* path buffer size */
#define NNTP_FILENAME_PATH_SIZE        256
#define NNTP_CMD_NAME                  20
#define NNTP_PKT_TIMEOUT               100
#define NNTP_DATA_BUFFER               20480

/* packets limit for NntpVerify, NntpCheck */
#define NNTP_PKT_VER_LIMIT              10

typedef enum _nntp_cmd nntp_cmd;
enum _nntp_cmd {
    NNTP_CMD_ARTICLE = 0, /* RFC 3977 */
    NNTP_CMD_AUTHINFO,
    NNTP_CMD_BODY,
    NNTP_CMD_CAPABILITIES,
    NNTP_CMD_CHECK,
    NNTP_CMD_DATE,
    NNTP_CMD_GROUP,
    NNTP_CMD_HDR,
    NNTP_CMD_HEAD,
    NNTP_CMD_HELP,
    NNTP_CMD_IHAVE,
    NNTP_CMD_LAST,
    NNTP_CMD_LIST,
    NNTP_CMD_LISTGROUP,
    NNTP_CMD_MODE,
    NNTP_CMD_NEWGROUPS,
    NNTP_CMD_NEWNEWS,
    NNTP_CMD_NEXT,
    NNTP_CMD_OVER,
    NNTP_CMD_POST,
    NNTP_CMD_QUIT,
    NNTP_CMD_SLAVE,
    NNTP_CMD_STAT,
    NNTP_CMD_TAKETHIS,
    NNTP_CMD_XGTITLE,
    NNTP_CMD_XINDEX,
    NNTP_CMD_XPAT,
    NNTP_CMD_XROVER,
    NNTP_CMD_XREPLIC,
    NNTP_CMD_XTHREAD,
    NNTP_CMD_XHDR,
    NNTP_CMD_XOVER,
    NNTP_CMD_WILDMAT,
    NNTP_CMD_NONE
};

typedef enum _nntp_repl nntp_repl;
enum _nntp_repl {
    NNTP_REP_100,      /**< help text follows */
    NNTP_REP_101,      /**< capabilities list follows */
    NNTP_REP_111,      /**< server date and time */
    NNTP_REP_200,      /**< service available, posting allowed */
    NNTP_REP_201,      /**< service available, posting prohibited */
    NNTP_REP_205,      /**< connection closing*/
    NNTP_REP_211,      /**< response code has two completely different forms */
    NNTP_REP_215,      /**< information follows */
    NNTP_REP_218,      /**< tin-style index follows */
    NNTP_REP_220,      /**< article follows */
    NNTP_REP_221,      /**< article headers follow */
    NNTP_REP_222,      /**< article body follows */
    NNTP_REP_223,      /**< article exists and selected */
    NNTP_REP_224,      /**< overview information follows */
    NNTP_REP_225,      /**< headers follow */
    NNTP_REP_230,      /**< list of new articles follows*/
    NNTP_REP_231,      /**< list of new newsgroups follows */
    NNTP_REP_235,      /**< article transferred OK */
    NNTP_REP_239,      /**< article transferred OK */
    NNTP_REP_240,      /**< article received OK */
    NNTP_REP_282,      /**< list of groups and descriptions follows */
    NNTP_REP_335,      /**< send article to be transferred */
    NNTP_REP_340,      /**< send article to be posted */
    NNTP_REP_400,      /**< service not available or no longer available */
    NNTP_REP_401,      /**< the server is in the wrong mode */
    NNTP_REP_403,      /**< internal fault or problem preventing action being taken */
    NNTP_REP_411,      /**< no such newsgroup */
    NNTP_REP_412,      /**< no newsgroup selected */
    NNTP_REP_418,      /**< no tin-style index is available for this news group */
    NNTP_REP_420,      /**< current article number is invalid */
    NNTP_REP_421,      /**< no next article in this group */
    NNTP_REP_422,      /**< no previous article in this group */
    NNTP_REP_423,      /**< no article with that number or in that range*/
    NNTP_REP_430,      /**< no article with that message-id */
    NNTP_REP_435,      /**< article not wanted */
    NNTP_REP_436,      /**< transfer not possible */
    NNTP_REP_437,      /**< transfer rejected */
    NNTP_REP_439,      /**< article transfer failed */
    NNTP_REP_440,      /**< posting not permitted */
    NNTP_REP_441,      /**< posting failed */
    NNTP_REP_480,      /**< command unavailable until the client has authenticated itself */
    NNTP_REP_481,      /**< Groups and descriptions unavailable */
    NNTP_REP_483,      /**< command unavailable until suitable privacy has been arranged */
    NNTP_REP_500,      /**< unknown command */
    NNTP_REP_501,      /**< syntax error in command */
    NNTP_REP_502,      /**< command not permitted */
    NNTP_REP_503,      /**< feature not supported */
    NNTP_REP_504,      /**< error in base64-encoding of an argument */
    NNTP_REP_NONE
};


typedef struct _nntp_rep_code nntp_rep_code;
struct _nntp_rep_code {
    int num;          /* reply code number */
    nntp_repl rep;    /* reply */
};


typedef enum _nntp_client_dir  nntp_client_dir;
enum _nntp_client_dir {
    NNTP_CLT_DIR_NONE,
    NNTP_CLT_DIR_OK,
    NNTP_CLT_DIR_REVERS
};



typedef struct _nntp_msg nntp_msg;
struct _nntp_msg {
    char *cmd;                     /* command from client */
    int cmd_size;                  /* command buffer dim */
    char *repl;                    /* reply from server */
    int repl_size;                 /* reply buffer dim */
    char *multp_resp;              /* multi-line response */
    int mlp_res_size;              /* multi-line response size */
    bool first;                    /* first reply */
    nntp_cmd cmdt;                 /* command type */
    nntp_repl st;                  /* reply status */
    bool auth_cont;                /* auth continuation command */
    bool complete;                 /* message complete */
    time_t capt_start;             /* start time of message */
    time_t capt_end;               /* end time of message */
    char *file_data;               /* data file name */
    FILE *fp_data;                 /* file descriptor */
    bool post;                     /* data post */
    char data[2*NNTP_DATA_BUFFER]; /* buffer to find \r\n.\r\n */
    int dsize;                     /* data buffer size */
    nntp_msg *nxt;                 /* next messagge (cmd + repl) */
};


typedef struct _nntp_con nntp_con;
struct _nntp_con {
    char *file_cmd;  /* main comunication; cmd data */
    time_t cap_end;  /* capture end time */
    FILE *fp_cmd;    /* file pointer */
};


typedef struct _nntp_priv nntp_priv;
struct _nntp_priv {
    bool port_diff;         /* connection with different port */
    nntp_client_dir dir;    /* real direction of client */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip_s;             /* ip source */
    ftval ip_d;             /* ip destination */
    unsigned short port_s;  /* source port */
    unsigned short port_d;  /* destination port */
    const pstack_f *stack;  /* protocol stack */
    nntp_msg *grp;   /* group */
};




#endif /* __NNTP_H__ */
