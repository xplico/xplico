/* ftp.h
 *
 * $Id: $
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


#ifndef __FTP_H__
#define __FTP_H__

#include <stdio.h>

/* standard port */
#define TCP_PORT_FTP                  21
#define TCP_PORT_FTPDATA              20

/* path buffer size */
#define FTP_FILENAME_PATH_SIZE        256
#define FTP_USER_PWD_DIM              256
#define FTP_DATA_BUFFER               20480
#define FTP_CMD_NAME                  20
#define FTP_PKT_TIMEOUT               1000

/* packets limit for FtpVerify, FtpCheck */
#define FTP_PKT_VER_LIMIT             10

typedef enum _ftp_cmd ftp_cmd;
enum _ftp_cmd {
    FTP_CMD_USER = 0, /* RFC959 */
    FTP_CMD_PASS,
    FTP_CMD_ACCT,
    FTP_CMD_CWD,
    FTP_CMD_CDUP,
    FTP_CMD_SMNT,
    FTP_CMD_REIN,
    FTP_CMD_QUIT,
    FTP_CMD_PORT,
    FTP_CMD_PASV,
    FTP_CMD_TYPE,
    FTP_CMD_STRU,
    FTP_CMD_MODE,
    FTP_CMD_RETR,
    FTP_CMD_STOR,
    FTP_CMD_STOU,
    FTP_CMD_APPE,
    FTP_CMD_ALLO,
    FTP_CMD_REST,
    FTP_CMD_RNFR,
    FTP_CMD_RNTO,
    FTP_CMD_ABOR,
    FTP_CMD_DELE,
    FTP_CMD_RMD,
    FTP_CMD_MKD,
    FTP_CMD_PWD,
    FTP_CMD_LIST,
    FTP_CMD_NLST,
    FTP_CMD_SITE,
    FTP_CMD_SYST,
    FTP_CMD_STAT,
    FTP_CMD_HELP,
    FTP_CMD_NOOP,
    FTP_CMD_LPRT,  /* RFC 1639 */
    FTP_CMD_LPSV,
    FTP_CMD_EPRT,  /* RFC 2428 */
    FTP_CMD_EPSV,
    FTP_CMD_MDTM,  /* RFC 3659 */
    FTP_CMD_SIZE,
    FTP_CMD_TVFS,
    FTP_CMD_MLST,
    FTP_CMD_MLSD,
    FTP_CMD_FEAT,  /* RFC 2389 */
    FTP_CMD_OPTS,
    FTP_CMD_LANG,  /* RFC 2640 */
    FTP_CMD_ADAT,  /* RFC 2228 */
    FTP_CMD_AUTH,
    FTP_CMD_CCC,
    FTP_CMD_CONF,
    FTP_CMD_ENC,
    FTP_CMD_PBSZ,
    FTP_CMD_PROT,
    FTP_CMD_CLNT,  /* without RFC */
    FTP_CMD_NONE
};

typedef enum _ftp_repl ftp_repl;
enum _ftp_repl {
    FTP_REP_110,        /**< Restart marker reply */
    FTP_REP_120,        /**< Service ready in nnn minutes */
    FTP_REP_125,        /**< Data connection already open; transfer starting */
    FTP_REP_150,        /**< File status okay; about to open data connection */
    FTP_REP_200,        /**< Command okay */
    FTP_REP_202,        /**< Command not implemented, superfluous at this site */
    FTP_REP_211,        /**< System status, or system help reply */
    FTP_REP_212,        /**< Directory status */
    FTP_REP_213,        /**< File status */
    FTP_REP_214,        /**< Help message */
    FTP_REP_215,        /**< NAME system type */
    FTP_REP_220,        /**< Service ready for new user */
    FTP_REP_221,        /**< Service closing control connection */
    FTP_REP_225,        /**< Data connection open; no transfer in progress */
    FTP_REP_226,        /**< Closing data connection */
    FTP_REP_227,        /**< Entering Passive Mode */
    FTP_REP_228,        /**< Entering Long Passive Mode */
    FTP_REP_229,        /**< Entering Extended Passive Mode */
    FTP_REP_230,        /**< User logged in, proceed */
    FTP_REP_250,        /**< Requested file action okay, completed */
    FTP_REP_257,        /**< PATHNAME created */
    FTP_REP_331,        /**< User name okay, need password */
    FTP_REP_332,        /**< Need account for login */
    FTP_REP_350,        /**< Requested file action pending further information */
    FTP_REP_421,        /**< Service not available, closing control connection */
    FTP_REP_425,        /**< Can't open data connection */
    FTP_REP_426,        /**< Connection closed; transfer aborted */
    FTP_REP_450,        /**< Requested file action not taken */
    FTP_REP_451,        /**< Requested action aborted: local error in processing */
    FTP_REP_452,        /**< Requested action not taken. Insufficient storage space in system */
    FTP_REP_500,        /**< Syntax error, command unrecognized */
    FTP_REP_501,        /**< Syntax error in parameters or arguments */
    FTP_REP_502,        /**< Command not implemented */
    FTP_REP_503,        /**< Bad sequence of commands */
    FTP_REP_504,        /**< Command not implemented for that parameter */
    FTP_REP_530,        /**< Not logged in */
    FTP_REP_532,        /**< Need account for storing files */
    FTP_REP_550,        /**< Requested action not taken: File unavailable */
    FTP_REP_551,        /**< Requested action aborted: page type unknown */
    FTP_REP_552,        /**< Requested file action aborted: Exceeded storage allocation */
    FTP_REP_553,        /**< Requested action not taken: File name not allowed */
    FTP_REP_NONE
};


typedef struct _ftp_rep_code ftp_rep_code;
struct _ftp_rep_code {
    int num;          /* reply code number */
    ftp_repl rep;     /* reply */
};


typedef enum _ftp_client_dir  ftp_client_dir;
enum _ftp_client_dir {
    FTP_CLT_DIR_NONE,
    FTP_CLT_DIR_OK,
    FTP_CLT_DIR_REVERS
};


typedef struct _ftp_priv ftp_priv;
struct _ftp_priv {
    bool port_diff;         /* connection with different port */
    ftp_client_dir dir;     /* real direction of client */
    unsigned short port;    /* source port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip;               /* ip source */
    ftval ipd;              /* ip destination */
};


typedef struct _ftp_con ftp_con;
struct _ftp_con {
    char *file_cmd;  /* main comunication; cmd data */
    char *user;      /* user name */
    char *passwd;    /* password */
    ftval ip_clnt;   /* client ip */
    int ipv_id;      /* ftp data IP version type */
    ftval ip;        /* ftp data IP */
    ftval port;      /* ftp data port */
    bool clnt;       /* ftp data setup from client or from server */
    bool data_setup; /* true if setup data connection info ok */
    int up_n;        /* number of file uploaded */
    int down_n;      /* number of file downloaded */          
    int rule;        /* last rule id */
    ftp_cmd cmd_rl;  /* command after rule and before ftp data*/
    bool lost;       /* lost cmd or response */
};


typedef struct _ftp_data ftp_data;
struct _ftp_data {
    int fid;             /* flow id */
    ftp_cmd cmd;         /* command associaton */
    char *buff;          /* tmp buffer */
    unsigned long dim;   /* buffer size */
    char *filename;      /* file name */
    char *file;          /* file path */
    FILE *fp;            /* file pointer */
    unsigned long offset;    /* file offset */
    time_t cap_start;        /* capture start time */
    time_t cap_end;          /* capture end time */
    unsigned long serial;    /* serial pkt num */
    pstack_f *stack;         /* stack info */
    pstack_f *gstack;        /* group stack info */
    bool lost;           /* data lost */
    ftp_data *nxt;       /* next */
};

#endif /* __FTP_H__ */
