/* paltalk.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on: Paltalk Protocol Plugin for Gaim 
 *   (C) 2004,2005 Tim Hentenaar <tim@hentsoft.com>
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


#ifndef __PALTALK_H__
#define __PALTALK_H__

#include <stdio.h>

#include "istypes.h"
#include "pei.h"

/* path buffer size */
#define PTLK_FILENAME_PATH_SIZE        256
#define PTLK_IP_STR_SIZE               100
#define PTLK_USER_DIM                  256
#define PTLK_DATA_BUFFER               20480
#define PTLK_CMD_NAME                  20
#define PTLK_PKT_TIMEOUT               100

/* packets limit for PaltalkVerify, PaltalkCheck */
#define PTLK_PKT_VER_LIMIT             6

/* protocol carateristics */
#define PTLK_HEADER_SIZE               6
#define PTLK_SERVER_HELLO              "Hello-From:PaLTALK"
#define PTLK_USER_DATA_UID             "uid="
#define PTLK_USER_DATA_UID_L           4
#define PTLK_USER_DATA_NICK            "nickname="
#define PTLK_USER_DATA_NICK_L          9
#define PTLK_USER_DATA_EMAIL           "email="
#define PTLK_USER_DATA_EMAIL_L         6
#define PTLK_USER_DATA_GID             "group_id="
#define PTLK_USER_DATA_GID_L           9

/* message type */
#define PACKET_FILE_XFER_RECV_INIT	0x0000		/* This is the same as XFER_REJECT */
#define PACKET_FILE_XFER_REJECT		-5002
#define PACKET_FILE_XFER_SEND_INIT	-5001
#define PACKET_GET_SERVICE_URL		-2600
#define PACKET_VERSION_INFO		-2128		
#define PACKET_CHECKSUMS		-2123		
#define PACKET_ECHO_RESPONSE		-2103		
#define PACKET_VERSIONS			-2102		
#define PACKET_UIN_FONTDEPTH_ETC	-2100		
#define PACKET_LOGIN			-1148
#define PACKET_GET_UIN			-1131
#define PACKET_LYMERICK			-1130
#define PACKET_ROOM_CLOSE		-940
#define PACKET_ROOM_NEW_USER_MIC	-932
#define PACKET_ROOM_RED_DOT_VIDEO	-931
#define PACKET_ROOM_RED_DOT_TEXT	-930
#define PACKET_ROOM_UNBAN_USER		-921
#define PACKET_ROOM_BAN_USER		-920
#define PACKET_ROOM_UNBOUNCE_USER	-911
#define PACKET_ROOM_GET_ADMIN_INFO	-900
#define PACKET_CHANGE_STATUS		-620
#define PACKET_UNBLOCK_BUDDY		-520
#define PACKET_BLOCK_BUDDY		-500
#define PACKET_EMAIL_VERIFICATION	-432
#define PACKET_ROOM_UNREQUEST_MIC	-399
#define PACKET_ROOM_REQUEST_MIC		-398
#define PACKET_ROOM_UNRED_DOT_USER	-397
#define PACKET_ROOM_BOUNCE_REASON	-390
#define PACKET_ROOM_MEDIA_SERVER_ACK	-383
#define PACKET_ROOM_REMOVE_ALL_HANDS	-382
#define PACKET_ROOM_RED_DOT_USER	-381
#define PACKET_ROOM_BOUNCE_USER		-380
#define PACKET_ROOM_INVITE_OUT		-360
#define PACKET_ROOM_TOGGLE_ALL_MICS	-355
#define PACKET_ROOM_SET_TOPIC		-351
#define PACKET_ROOM_MESSAGE_OUT		-350
#define PACKET_DO_LIST_CATEGORY		-330
#define PACKET_ROOM_LEAVE		-320
#define PACKET_ROOM_JOIN_AS_ADMIN	-316
#define PACKET_ROOM_JOIN		-310
#define PACKET_ROOM_PRIVATE_INVITE	-302
#define PACKET_LOGIN_NOT_COMPLETED	-160
#define PACKET_REDIRECT			-119
#define PACKET_HELLO			-117
#define PACKET_CLIENT_HELLO		-100
#define PACKET_DO_SEARCH		-69
#define PACKET_SEARCH_ERROR		-69
#define PACKET_ADD_BUDDY		-67		
#define PACKET_REMOVE_BUDDY		-66
#define PACKET_ANNOUNCEMENT		-39
#define PACKET_IM_OUT			-20
#define PACKET_IM_IN			0x0014
#define PACKET_MAINTENANCE_KICK		0x002A
#define PACKET_BUDDY_REMOVED		0x0042
#define PACKET_BUDDY_LIST		0x0043
#define PACKET_SEARCH_RESPONSE		0x0045
#define PACKET_LOOKAHEAD		0x0064
#define PACKET_UPGRADE			0x0078		/* Ignored               */
#define PACKET_ROOM_JOINED		0x0136
#define PACKET_ROOM_USER_JOINED		0x0137
#define PACKET_ROOM_TRANSMITTING_VIDEO	0x0138
#define PACKET_ROOM_MEDIA_SERVER	0x013B
#define PACKET_ROOM_USER_LEFT		0x0140
#define PACKET_ROOM_LIST		0x014C
#define PACKET_ROOM_USERLIST		0x0154
#define PACKET_ROOM_MESSAGE_IN		0x015E
#define PACKET_ROOM_TOPIC		0x015F
#define PACKET_ROOM_MIC_GIVEN_REMOVED	0x0163
#define PACKET_ROOM_INVITE_IN		0x0168
#define PACKET_ROOM_CLOSED		0x017C
#define PACKET_ROOM_USER_RED_DOT_ON	0x017D
#define PACKET_ROOM_USER_MUTE		0x017F
#define PACKET_ROOM_USER_RED_DOT_OFF	0x018D
#define PACKET_ROOM_USER_MICREQUEST_ON	0x018E
#define PACKET_ROOM_USER_MICREQUEST_OFF	0x018F
#define PACKET_BUDDY_STATUSCHANGE	0x0190
#define PACKET_USER_DATA		0x019A		/* Ignored - Until I find it useful.	*/
#define PACKET_CATEGORY_LIST		0x019C
#define PACKET_BLOCK_SUCCESSFUL		0x01F4
#define PACKET_BLOCKED_BUDDIES		0x01FE
#define PACKET_USER_STATUS		0x026C		/* Obselete in Gaim			*/
#define PACKET_FORCED_IM		0x0294		/* Kindof like a system message         */
#define PACKET_WM_MESSAGE		0x02B2		/* Ignored				*/
#define PACKET_ROOM_BANNER_URL		0x0320		/* Ignored               		*/
#define PACKET_ROOM_ADMIN_INFO		0x0384
#define PACKET_SERVER_ERROR		0x044C
#define PACKET_UIN_RESPONSE		0x046B
#define PACKET_SERVER_KEY		0x0474
#define PACKET_LOGIN_UNKNOWN		0x04A6		/* 0-length Unknown sent after login    */
#define PACKET_ROOM_PREMIUM		0x0528		/* Some Details Unknown  		*/
#define PACKET_USER_STATS		0x05DC		/* Ignored               		*/
#define PACKET_ECHO			0x0837		/* Some Details Unknown  		*/
#define PACKET_ROOM_UNKNOWN_ENCODED	0x084A		/* What the hell?                       */
#define PACKET_INTEROP_URL		0x0850		/* Obselete in Gaim      		*/
#define PACKET_POPUP_URL		0x09C4		/* Ignored               		*/
#define PACKET_SERVICE_URL		0x0A28
#define PACKET_FILE_XFER_REQUEST	0x1389
#define PACKET_FILE_XFER_REFUSED	0x138B
#define PACKET_FILE_XFER_ACCEPTED	0x138C
#define PACKET_FILE_XFER_ERROR		0x138D


typedef enum _pltk_client_dir  pltk_client_dir;
enum _pltk_client_dir {
    PLTK_CLT_DIR_NONE,
    PLTK_CLT_DIR_OK,
    PLTK_CLT_DIR_REVERS
};


typedef struct _pltk_msg pltk_msg;
struct _pltk_msg {
    short type;
    unsigned short version;
    unsigned short length;
    char payload[1];    /* null teminated! */
};


typedef struct _pltk_room_msg_in pltk_room_msg_in;
struct _pltk_room_msg_in {
    unsigned long gid;  /* group/room ID */
    unsigned long uid;  /* user ID */
    char message[1];
};


typedef struct _pltk_im_msg pltk_im_msg;
struct _pltk_im_msg {
    unsigned long uid;  /* user ID */
    char message[1];
};


typedef struct _pltk_msg_info pltk_msg_info;
struct _pltk_msg_info {
    pltk_msg *msg; /* message */
    unsigned int size;    /* total message size */
    bool client;          /* client message */
    unsigned long serial; /* serial number (used in pei) */
    time_t start_cap;     /* start capture time */
    time_t end_cap;       /* end capture time */
    pltk_msg_info *nxt;   /* next message */
};


typedef struct _pltk_chat_user pltk_chat_usr;
struct _pltk_chat_user {
    unsigned long uid;  /* user ID */
    char nick[PTLK_USER_DIM];  /* actual nick name */
    pltk_chat_usr *nxt;
};


typedef struct _pltk_chat pltk_chat;
struct _pltk_chat {
    unsigned long gid;  /* group/room ID */
    pltk_chat_usr *userl; /* users list */
    unsigned short num_userl;
    char channel[PTLK_USER_DIM]; /* channel/room name or private nick name */
    char chat_msg[PTLK_FILENAME_PATH_SIZE]; /* chat messages */
    FILE *msg_fp;
    char users[PTLK_FILENAME_PATH_SIZE]; /* chat users */
    FILE *users_fp;
    char nick[PTLK_FILENAME_PATH_SIZE]; /* chat nick name */
    FILE *nick_fp;
    time_t start_time; /* start time */
    time_t end_time ; /* end time */
    pei *cpei; /* pei */
    pltk_chat *nxt; /* next chat */
};


typedef struct _pltk_private pltk_private;
struct _pltk_private {
    unsigned long uid;        /* user ID */
    char nick[PTLK_USER_DIM]; /* actual user nick name */
    char priv_msg[PTLK_FILENAME_PATH_SIZE]; /* chat messages */
    FILE *msg_fp;
    char users[PTLK_FILENAME_PATH_SIZE]; /* chat users */
    FILE *users_fp;
    time_t start_time; /* start time */
    time_t end_time ; /* end time */
    pei *cpei; /* pei */
    pltk_private *nxt; /* next chat */
};


typedef struct _pltk_priv pltk_priv;
struct _pltk_priv {
    bool port_diff;         /* connection with different port */
    pltk_client_dir dir;    /* real direction of client */
    unsigned short port;    /* source port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip;               /* ip source */
    bool clost;             /* client packets lost */
    bool slost;             /* server packets lost */
};


typedef struct _pltk_con pltk_con;
struct _pltk_con {
    int flow_id;            /* flow id */
    unsigned long uid;      /* user id */
    char uid_s[PTLK_USER_DIM]; /* string user id */
    char email[PTLK_USER_DIM]; /* user email */
    char nick[PTLK_USER_DIM];  /* actual nick name */
    unsigned short nchat;   /* total number of chats */
    pltk_chat *chat;        /* chats */
    pltk_chat_usr *buddy;   /* buddy */
    pltk_private *private;  /* private chat */
};

#endif /* __PALTALK_H__ */
