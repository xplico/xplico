/* irc.h
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


#ifndef __IRC_H__
#define __IRC_H__

#include <stdio.h>

#include "istypes.h"
#include "pei.h"

/* standard port */
#define TCP_PORT_IRC                   6667

/* path buffer size */
#define IRC_FILENAME_PATH_SIZE         256
#define IRC_CMD_NAME                   20
#define IRC_PKT_TIMEOUT                100
#define IRC_USER_PWD_DIM               256
#define IRC_DATA_BUFFER                20480
#define IRC_REALNAME_MAX_SIZE	       256
#define IRC_NICKNAME_MAX_SIZE	       40
#define IRC_CHANNEL_NAME_MAX           30

/* packets limit for SipVerify, SipCheck */
#define IRC_PKT_CHECK_LIMIT            10
#define IRC_PKT_VER_LIMIT              40


typedef enum _irc_cmd irc_cmd;
enum _irc_cmd {
    IRC_CMD_ADMIN, /* RFC 1459 */
    IRC_CMD_AWAY, /* RFC 1459 */
    IRC_CMD_CONNECT, /* RFC 1459 */
    IRC_CMD_DIE, /* RFC 2812 */
    IRC_CMD_ERROR, /* RFC 1459 */
    IRC_CMD_INFO, /* RFC 1459 */
    IRC_CMD_INVITE, /* RFC 1459 */
    IRC_CMD_ISON, /* RFC 1459 */
    IRC_CMD_JOIN, /* RFC 1459 */
    IRC_CMD_KICK, /* RFC 1459 */
    IRC_CMD_KILL, /* RFC 1459 */
    IRC_CMD_LINKS, /* RFC 1459 */
    IRC_CMD_LIST, /* RFC 1459 */
    IRC_CMD_LUSERS, /* RFC 2812 */
    IRC_CMD_MODE, /* RFC 1459 */
    IRC_CMD_MOTD, /* RFC 2812 */
    IRC_CMD_NAMES, /* RFC 1459 */
    IRC_CMD_NICK, /* RFC 1459 */
    IRC_CMD_NOTICE, /* RFC 1459 */
    IRC_CMD_OPER, /* RFC 1459 */
    IRC_CMD_PART, /* RFC 1459 */
    IRC_CMD_PASS, /* RFC 1459 */
    IRC_CMD_PING, /* RFC 1459 */
    IRC_CMD_PONG, /* RFC 1459 */
    IRC_CMD_PRIVMSG, /* RFC 1459 */
    IRC_CMD_QUIT, /* RFC 1459 */
    IRC_CMD_REHASH, /* RFC 1459 */
    IRC_CMD_RESTART, /* RFC 1459 */
    IRC_CMD_SERVICE, /* RFC 2812 */
    IRC_CMD_SERVLIST, /* RFC 2812 */
    IRC_CMD_SERVER, /* RFC 1459 */
    IRC_CMD_SQUERY, /* RFC 2812 */
    IRC_CMD_SQUIT, /* RFC 1459 */
    IRC_CMD_STATS, /* RFC 1459 */
    IRC_CMD_SUMMON, /* RFC 2812 */
    IRC_CMD_TIME, /* RFC 1459 */
    IRC_CMD_TOPIC, /* RFC 1459 */
    IRC_CMD_TRACE, /* RFC 1459 */
    IRC_CMD_USER, /* RFC 1459 */
    IRC_CMD_USERHOST, /* RFC 1459 */
    IRC_CMD_USERS, /* RFC 1459, 2812*/
    IRC_CMD_VERSION, /* RFC 1459 */
    IRC_CMD_WALLOPS, /* RFC 1459 */
    IRC_CMD_WHO, /* RFC 1459 */
    IRC_CMD_WHOIS, /* RFC 1459 */
    IRC_CMD_WHOWAS, /* RFC 1459 */
    IRC_CMD_ACCESS, /* IRCX */
    IRC_CMD_AUTH, /* IRCX */
    IRC_CMD_CREATE, /* IRCX */
    IRC_CMD_DATA, /* IRCX */
    IRC_CMD_REQUEST, /* IRCX */
    IRC_CMD_REPLY, /* IRCX */
    IRC_CMD_EVENT, /* IRCX */
    IRC_CMD_IRCX, /* IRCX */
    IRC_CMD_ISIRCX, /* IRCX */
    IRC_CMD_LISTX, /* IRCX */
    IRC_CMD_PROP, /* IRCX */
    IRC_CMD_WHISPER, /* IRCX */
    IRC_CMD_NONE
};

/* server replay code */
#define IRC_RPL_WELCOME          001
#define IRC_RPL_YOURHOST         002
#define IRC_RPL_CREATED          003
#define IRC_RPL_MYINFO           004
#define IRC_RPL_BOUNCE           005
#define IRC_RPL_LUSERCLIENT      251
#define IRC_RPL_LUSERME          255
#define IRC_RPL_265              265
#define IRC_RPL_266              266
#define IRC_RPL_TOPIC            332
#define IRC_RPL_NAMREPLY         353
#define IRC_RPL_MOTD             372
#define IRC_RPL_MOTDSTART        375

typedef enum _irc_client_dir  irc_client_dir;
enum _irc_client_dir {
    IRC_CLT_DIR_NONE,
    IRC_CLT_DIR_OK,
    IRC_CLT_DIR_REVERS
};

typedef struct _irc_msg irc_msg;
struct _irc_msg {
    char *prefix; /* teminate with a space */
    unsigned short p_size;
    irc_cmd cmd;
    short repl;
    char *params;
    unsigned short prm_size;
};


typedef struct _irc_chat irc_chat;
struct _irc_chat {
    bool private; /* private channel */
    bool secret; /* secret channel */
    bool user; /* user private chat */
    char channel[IRC_CHANNEL_NAME_MAX]; /* channel name or private nick name */
    char chat_msg[IRC_FILENAME_PATH_SIZE]; /* chat messages */
    FILE *msg_fp;
    char users[IRC_FILENAME_PATH_SIZE]; /* chat users */
    FILE *users_fp;
    char nick[IRC_FILENAME_PATH_SIZE]; /* chat nick name */
    FILE *nick_fp;
    time_t start_time; /* start time */
    time_t end_time; /* end time */
    pei *cpei; /* pei */
    irc_chat *nxt; /* next chat */
};


typedef struct _irc_priv irc_priv;
struct _irc_priv {
    bool port_diff;         /* connection with different port */
    irc_client_dir dir;     /* real direction of client */
    unsigned short port;    /* source port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip;               /* ip source */
};


typedef struct _irc_con irc_con;
struct _irc_con {
    char *file_cmd;  /* main comunication; cmd data */
    char *user;      /* user name */
    char *passwd;    /* password */
    bool lost;       /* lost cmd or response */
    char nick[IRC_NICKNAME_MAX_SIZE]; /* actual nick name */
    unsigned short nchat; /* total number of chats */
    irc_chat *chat;  /* chats */
    pei *mpei;       /* master pei */
    int flow_id;     /* flow id */
};


#endif /* __IRC_H__ */
