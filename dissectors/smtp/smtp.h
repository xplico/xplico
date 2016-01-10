/* smtp.h
 *
 * $Id: smtp.h,v 1.2 2007/09/08 07:15:45 costa Exp $
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


#ifndef __SMTP_H__
#define __SMTP_H__

#include "packet.h"


/* path buffer size */
#define SMTP_FILENAME_PATH_SIZE        256
#define SMTP_DATA_BUFFER               20480

/* standard port */
#define TCP_PORT_SMTP          25

/* packets limit for SmtpVerify, SmtpCheck */
#define SMTP_PKT_VER_LIMIT     10

typedef enum _smtp_cmd smtp_cmd;
enum _smtp_cmd {
    SMTP_CMD_HELO,      /* RFC2821 */
    SMTP_CMD_MAIL,
    SMTP_CMD_RCPT,
    SMTP_CMD_DATA,
    SMTP_CMD_RSET,
    SMTP_CMD_SEND,
    SMTP_CMD_SOML,
    SMTP_CMD_SAML,
    SMTP_CMD_VRFY,
    SMTP_CMD_EXPN,
    SMTP_CMD_HELP,
    SMTP_CMD_NOOP,
    SMTP_CMD_QUIT,
    SMTP_CMD_TURN,
    SMTP_CMD_EHLO,       /* RFC1869 */
    SMTP_CMD_AUTH,       /* RFC2554 */
    SMTP_CMD_STARTTLS,   /* RFC2487 */
    SMTP_CMD_BDAT,       /* RFC3030 */
    SMTP_CMD_AUTH_CONT,  /* unknow command, continuation of AUTH */
    SMTP_CMD_NONE
};


typedef enum _smtp_status smtp_status;
enum _smtp_status {
    SMTP_ST_2XX,
    SMTP_ST_3XX,
    SMTP_ST_4XX,
    SMTP_ST_5XX,
    SMTP_ST_NONE
};


typedef struct _smtp_msg smtp_msg;
struct _smtp_msg {
    char *cmd;                     /* command from client */
    int cmd_size;                  /* command buffer dim */
    char *repl;                    /* reply from server */
    int repl_size;                 /* reply buffer dim */
    bool first;                    /* first reply */
    smtp_cmd cmdt;                 /* command type */
    smtp_status st;                /* reply status */
    bool auth_cont;                /* auth continuation command */
    time_t capt_start;             /* start time of message */
    time_t capt_end;               /* end time of message */
    char *file_eml;                /* data file name */
    int fd_eml;                    /* file descriptor */
    bool err;                      /* error */
    char data[2*SMTP_DATA_BUFFER]; /* buffer to find \r\n.\r\n */
    int dsize;                     /* data buffer size */
    smtp_msg *nxt;                 /* next messagge (cmd + repl) */
};


typedef struct _smtp_con smtp_con;
struct _smtp_con {
    bool port_diff;         /* connection with different port */
    unsigned short port;    /* source port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip;               /* ip source */
    const pstack_f *stack;  /* protocol stack */
};


#endif /* __SMTP_H__ */
