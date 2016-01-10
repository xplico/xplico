/* irc.c
 * IRC packet dissection
 * RFC 1459, RFC 2810, RFC 2811, RFC 2812 and RFC 2813
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

#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "irc.h"
#include "strutil.h"
#include "pei.h"
#include "dnsdb.h"
#include "genfun.h"

#define IRC_TMP_DIR    "irc"

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int tcp_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int clnt_id;
static int irc_id;

/* pei id */
static int pei_url_id;           /* server url */
static int pei_server_id;        /* commands sent to/from user */
static int pei_channels_num_id;  /* channel number */
static int pei_channel_id;       /* channel name and messages file */
static int pei_channel_users_id; /* channel users */
static int pei_channel_nick_id;  /* nick names of the user */

static volatile unsigned int incr;
static volatile unsigned int incr_channel;


static void IrcConInit(irc_con *irc)
{
    memset(irc, 0, sizeof(irc_con));
    irc->file_cmd = DMemMalloc(IRC_FILENAME_PATH_SIZE);
    irc->file_cmd[0] = '\0';
    irc->user = DMemMalloc(IRC_USER_PWD_DIM);
    irc->user[0] = '\0';
    irc->passwd = DMemMalloc(IRC_USER_PWD_DIM);
    irc->passwd[0] = '\0';
    irc->lost = FALSE;
    irc->nchat = 0;
    irc->chat = NULL;
}


static void IrcConFree(irc_con *irc)
{
    if (irc->file_cmd != NULL)
        DMemFree(irc->file_cmd);
    irc->file_cmd = NULL;
    
    if (irc->user != NULL)
        DMemFree(irc->user);
    irc->user = NULL;

    if (irc->passwd != NULL)
        DMemFree(irc->passwd);
    irc->passwd = NULL;
}


static irc_chat *IrcNewChannel(char *name)
{
    irc_chat *channel;
    time_t t;

    channel = xmalloc(sizeof(irc_chat));
    if (channel != NULL) {
        t = time(NULL);
        memset(channel, 0, sizeof(irc_chat));
        channel->private = FALSE;
        channel->secret = FALSE;
        strcpy(channel->channel, name);
        sprintf(channel->chat_msg, "%s/%s/channel_%s_%lld_%i_%p.txt", ProtTmpDir(), IRC_TMP_DIR, name, (long long)t, ++incr_channel, channel);
        channel->msg_fp = fopen(channel->chat_msg, "w");
        if (channel->msg_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            LogPrintf(LV_ERROR, "Unable to open file %s", channel->chat_msg);
            xfree(channel);
            return NULL;
        }
        sprintf(channel->users, "%s/%s/channel_%s_users_%lld_%i_%p.txt", ProtTmpDir(), IRC_TMP_DIR, name, (long long)t, incr_channel, channel);
        channel->users_fp = fopen(channel->users, "w");
        if (channel->users_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            LogPrintf(LV_ERROR, "Unable to open file %s", channel->users);
            xfree(channel);
            return NULL;
        }
        sprintf(channel->nick, "%s/%s/channel_%s_nick_%lld_%i_%p.txt", ProtTmpDir(), IRC_TMP_DIR, name, (long long)t, incr_channel, channel);
        channel->nick_fp = fopen(channel->nick, "w");
        if (channel->nick_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            LogPrintf(LV_ERROR, "Unable to open file %s", channel->nick);
            xfree(channel);
            return NULL;
        }
        channel->cpei = NULL;
        channel->nxt = NULL;
    }
    else {
        LogPrintf(LV_ERROR, "Memory finished");
    }

    return channel;
}


static int IrcMsg(char *line, int linelen, irc_msg *msg)
{
    char *ptr, *cmd;
    int	index, clen, val;
    
    ptr = line;
    index = 0;
    clen = 0;
    msg->prefix = NULL;
    msg->cmd = IRC_CMD_NONE;
    msg->repl = -1;
    msg->params = NULL;

    /* Look prefix before the command */
    if (*ptr == ':') {
        while (index < linelen) {
            if (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
                break;
            else {
                ptr++;
                index++;
            }
        }
        if (*ptr != ' ')
            return -1;
        ptr++;
        index++;
        cmd = ptr;
        msg->prefix = line + 1;
        msg->p_size = cmd - line - 1;
    }
    else
        cmd = line;
    
    /* Look for the space following the command */
    while (index < linelen) {
        if (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
            break;
        else {
            ptr++;
            index++;
            clen++;
        }
    }
    if (isdigit(cmd[0])) {
        if (sscanf(cmd, "%i", &val) == 1) {
            msg->repl = val;
        }
    }
    else {
        if (clen == 4) {
            switch (cmd[0]) {
            case 'A':
            case 'a':
                if (strncasecmp(cmd, "AWAY", clen) == 0) {
                    msg->cmd = IRC_CMD_AWAY;
                }
                else  if (strncasecmp(cmd, "AUTH", clen) == 0) {
                    msg->cmd = IRC_CMD_AUTH;
                }
                break;

            case 'D':
            case 'd':
                if (strncasecmp(cmd, "DATA", clen) == 0) {
                    msg->cmd = IRC_CMD_DATA;
                }
                break;
                
            case 'I':
            case 'i':
                if (strncasecmp(cmd, "INFO", clen) == 0) {
                    msg->cmd = IRC_CMD_INFO;
                }
                else if (strncasecmp(cmd, "ISON", clen) == 0) {
                    msg->cmd = IRC_CMD_ISON;
                }
                else if (strncasecmp(cmd, "IRCX", clen) == 0) {
                    msg->cmd = IRC_CMD_IRCX;
                }
                break;
                
            case 'J':
            case 'j':
                if (strncasecmp(cmd, "JOIN", clen) == 0) {
                    msg->cmd = IRC_CMD_JOIN;
                }
                break;
                
            case 'K':
            case 'k':
                if (strncasecmp(cmd, "KICK", clen) == 0) {
                    msg->cmd = IRC_CMD_KICK;
                }
                else if (strncasecmp(cmd, "KILL", clen) == 0) {
                    msg->cmd = IRC_CMD_KILL;
                }
                break;

            case 'L':
            case 'l':
                if (strncasecmp(cmd, "LIST", clen) == 0) {
                    msg->cmd = IRC_CMD_LIST;
                }
                break;

            case 'M':
            case 'm':
                if (strncasecmp(cmd, "MODE", clen) == 0) {
                    msg->cmd = IRC_CMD_MODE;
                }
                else if (strncasecmp(cmd, "MOTD", clen) == 0) {
                    msg->cmd = IRC_CMD_MOTD;
                }
                break;

            case 'N':
            case 'n':
                if (strncasecmp(cmd, "NICK", clen) == 0) {
                    msg->cmd = IRC_CMD_NICK;
                }
                break;

            case 'O':
            case 'o':
                if (strncasecmp(cmd, "OPER", clen) == 0) {
                    msg->cmd = IRC_CMD_OPER;
                }
                break;

            case 'P':
            case 'p':
                if (strncasecmp(cmd, "PART", clen) == 0) {
                    msg->cmd = IRC_CMD_PART;
                }
                else if (strncasecmp(cmd, "PASS", clen) == 0) {
                    msg->cmd = IRC_CMD_PASS;
                }
                else if (strncasecmp(cmd, "PING", clen) == 0) {
                    msg->cmd = IRC_CMD_PING;
                }
                else if (strncasecmp(cmd, "PONG", clen) == 0) {
                    msg->cmd = IRC_CMD_PONG;
                }
                else if (strncasecmp(cmd, "PROP", clen) == 0) {
                    msg->cmd = IRC_CMD_PROP;
                }
                break;

            case 'Q':
            case 'q':
                if (strncasecmp(cmd, "QUIT", clen) == 0) {
                    msg->cmd = IRC_CMD_QUIT;
                }
                break;

            case 'T':
            case 't':
                if (strncasecmp(cmd, "TIME", clen) == 0) {
                    msg->cmd = IRC_CMD_TIME;
                }
                break;

            case 'U':
            case 'u':
                if (strncasecmp(cmd, "USER", clen) == 0) {
                    msg->cmd = IRC_CMD_USER;
                }
                break;
            }
        }
        else if (clen == 5) {
            switch (cmd[0]) {
            case 'A':
            case 'a':
                if (strncasecmp(cmd, "ADMIN", clen) == 0) {
                    msg->cmd = IRC_CMD_ADMIN;
                }
                break;
            
            case 'E':
            case 'e':
                if (strncasecmp(cmd, "ERROR", clen) == 0) {
                    msg->cmd = IRC_CMD_ERROR;
                }
                else if (strncasecmp(cmd, "EVENT", clen) == 0) {
                    msg->cmd = IRC_CMD_EVENT;
                }
                break;
            
            case 'I':
            case 'i':
                if (strncasecmp(cmd, "INVITE", clen) == 0) {
                    msg->cmd = IRC_CMD_INVITE;
                }
                break;
            
            case 'L':
            case 'l':
                if (strncasecmp(cmd, "LINKS", clen) == 0) {
                    msg->cmd = IRC_CMD_LINKS;
                }
                else if (strncasecmp(cmd, "LISTX", clen) == 0) {
                    msg->cmd = IRC_CMD_LISTX;
                }
                break;
            
            case 'N':
            case 'n':
                if (strncasecmp(cmd, "NAMES", clen) == 0) {
                    msg->cmd = IRC_CMD_NAMES;
                }
                break;
            
            case 'R':
            case 'r':
                if (strncasecmp(cmd, "REPLY", clen) == 0) {
                    msg->cmd = IRC_CMD_REPLY;
                }
                break;
            
            case 'S':
            case 's':
                if (strncasecmp(cmd, "SQUIT", clen) == 0) {
                    msg->cmd = IRC_CMD_SQUIT;
                }
                else if (strncasecmp(cmd, "STATS", clen) == 0) {
                    msg->cmd = IRC_CMD_STATS;
                }
                break;
            
            case 'T':
            case 't':
                if (strncasecmp(cmd, "TOPIC", clen) == 0) {
                    msg->cmd = IRC_CMD_TOPIC;
                }
                else if (strncasecmp(cmd, "TRACE", clen) == 0) {
                    msg->cmd = IRC_CMD_TRACE;
                }
                break;
            
            case 'U':
            case 'u':
                if (strncasecmp(cmd, "USERS", clen) == 0) {
                    msg->cmd = IRC_CMD_USERS;
                }
                break;
            
            case 'W':
            case 'w':
                if (strncasecmp(cmd, "WHOIS", clen) == 0) {
                    msg->cmd = IRC_CMD_WHOIS;
                }
                break;
            }
        }
        else if (clen == 6) {
            switch (cmd[0]) {
            case 'A':
            case 'a':
                if (strncasecmp(cmd, "ACCESS", clen) == 0) {
                    msg->cmd = IRC_CMD_ACCESS;
                }
                break;

            case 'C':
            case 'c':
                if (strncasecmp(cmd, "CREATE", clen) == 0) {
                    msg->cmd = IRC_CMD_CREATE;
                }
                break;;

            case 'I':
            case 'i':
                if (strncasecmp(cmd, "ISIRCX", clen) == 0) {
                    msg->cmd = IRC_CMD_ISIRCX;
                }
                break;

            case 'L':
            case 'l':
                if (strncasecmp(cmd, "LUSERS", clen) == 0) {
                    msg->cmd = IRC_CMD_LUSERS;
                }
                break;
        
            case 'N':
            case 'n':
                if (strncasecmp(cmd, "NOTICE", clen) == 0) {
                    msg->cmd = IRC_CMD_NOTICE;
                }
                break;

            case 'R':
            case 'r':
                if (strncasecmp(cmd, "REHASH", clen) == 0) {
                    msg->cmd = IRC_CMD_REHASH;
                }
                break;

            case 'S':
            case 's':
                if (strncasecmp(cmd, "SERVER", clen) == 0) {
                    msg->cmd = IRC_CMD_SERVER;
                }
                else if (strncasecmp(cmd, "SQUERY", clen) == 0) {
                    msg->cmd = IRC_CMD_SQUERY;
                }
                else if (strncasecmp(cmd, "SUMMON", clen) == 0) {
                    msg->cmd = IRC_CMD_SUMMON;
                }
                break;

            case 'W':
            case 'w':
                if (strncasecmp(cmd, "WHOWAS", clen) == 0) {
                    msg->cmd = IRC_CMD_WHOWAS;
                }
                break;
            }
        }
        else if (clen == 7) {
            switch (cmd[0]) {
            case 'C':
            case 'c':
                if (strncasecmp(cmd, "CONNECT", clen) == 0) {
                    msg->cmd = IRC_CMD_CONNECT;
                }
                break;

            case 'P':
            case 'p':
                if (strncasecmp(cmd, "PRIVMSG", clen) == 0) {
                    msg->cmd = IRC_CMD_PRIVMSG;
                }
                break;

            case 'R':
            case 'r':
                if (strncasecmp(cmd, "RESTART", clen) == 0) {
                    msg->cmd = IRC_CMD_RESTART;
                }
                else if (strncasecmp(cmd, "REQUEST", clen) == 0) {
                    msg->cmd = IRC_CMD_REQUEST;
                }
                break;

            case 'S':
            case 's':
                if (strncasecmp(cmd, "SERVICE", clen) == 0) {
                    msg->cmd = IRC_CMD_SERVICE;
                }
                break;

            case 'V':
            case 'v':
                if (strncasecmp(cmd, "VERSION", clen) == 0) {
                    msg->cmd = IRC_CMD_VERSION;
                }
                break;

            case 'W':
            case 'w':
                if (strncasecmp(cmd, "WALLOPS", clen) == 0) {
                    msg->cmd = IRC_CMD_WALLOPS;
                }
                else if (strncasecmp(cmd, "WHISPER", clen) == 0) {
                    msg->cmd = IRC_CMD_WHISPER;
                }
                break;
            }
        }
        else if (clen == 3) {
            switch (cmd[0]) {
            case 'D':
            case 'd':
                if (strncasecmp(cmd, "DIE", clen) == 0) {
                    msg->cmd = IRC_CMD_DIE;
                }
                break;

            case 'W':
            case 'w':
                if (strncasecmp(cmd, "WHO", clen) == 0) {
                    msg->cmd = IRC_CMD_WHO;
                }
                break;
            }
        }
        else if (clen == 8) {
            switch (cmd[0]) {
            case 'S':
            case 's':
                if (strncasecmp(cmd, "SERVLIST", clen) == 0) {
                    msg->cmd = IRC_CMD_SERVLIST;
                }
                break;

            case 'U':
            case 'u':
                if (strncasecmp(cmd, "USERHOST", clen) == 0) {
                    msg->cmd = IRC_CMD_USERHOST;
                }
                break;
            }
        }
    }
    while (index < linelen) {
        if (*ptr == ' ') {
            ptr++;
            index++;
        }
        else
            break;
    }
    if (index != linelen) {
        msg->params = ptr;
        msg->prm_size = linelen - index;
    }
    
    return 0;
}


static bool IrcClientPkt(irc_priv *priv, packet *pkt)
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
    if (priv->dir == IRC_CLT_DIR_NONE) {
        if (TCP_PORT_IRC == priv->port) {
            priv->dir = IRC_CLT_DIR_REVERS;
            ret = TRUE;
        }
        else {
            if (ret == TRUE)
                priv->dir = IRC_CLT_DIR_OK;
            else {
                priv->dir = IRC_CLT_DIR_REVERS;
                ret = TRUE;
            }
        }
    }
    else {
        if (priv->dir == IRC_CLT_DIR_REVERS)
            ret = !ret;
    }
    
    return ret;
}


static int IrcTargetTrailing(const char *params, unsigned short len, char *target, char **trailing)
{
    unsigned short i;

    if (params == NULL) {
        *trailing = NULL;
        return -1;
    }
    if (params[0] == ' ') {
        params++;
        len--;
    }
    /* serach ' ' */
    i = 0;
    while (i != len && params[i] != ' ') {
        target[i] = params[i];
        i++;
    }
    if (i != len) {
        target[i] = '\0';
        /* search */
        *trailing = strstr(params, " :");
        if (*trailing != NULL)
            *trailing = (*trailing)+2;
    }
    else {
        *trailing = NULL;
    }
    
    return 0;
}


static void IrcNick(char *nick, irc_con *irc, time_t t)
{
    irc_chat *chat;
    struct tm tmm;

    if (strcmp(irc->nick, nick) != 0) {
        strcpy(irc->nick, nick);
        chat = irc->chat;
        while (chat != NULL) {
            gmtime_r(&t, &tmm);
            fprintf(chat->nick_fp, " [%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nick);
            chat = chat->nxt;
        }
    }
}


static int IrcTopic(char *params, unsigned short len, char *target, char **channel, char **trailing)
{
    unsigned short i, chn;

    if (params == NULL) {
        *channel = NULL;
        *trailing = NULL;
        return -1;
    }
    if (params[0] == ' ') {
        params++;
        len--;
    }
    /* serach ' ' */
    i = 0;
    while (i != len && params[i] != ' ') {
        target[i] = params[i];
        i++;
    }
    target[i] = '\0';
    /* channel name */
    if (i != len) {
        i++;
        *channel = params + i;
        while (i != len && params[i] != ' ')
            i++;
    }
    else {
        *channel = NULL;
    }
    if (i != len) {
        chn = i;
        /* search */
        *trailing = strstr(params, " :");
        if (*trailing != NULL)
            *trailing = (*trailing)+2;
        params[chn] = '\0';
    }
    else {
        *trailing = NULL;
    }
    
    return 0;
}


static int IrcPrivmsg(char *params, unsigned short len, char **channel, char **trailing)
{
    unsigned short i, chn;

    if (params == NULL) {
        *channel = NULL;
        *trailing = NULL;
        return -1;
    }
    if (params[0] == ' ') {
        params++;
        len--;
    }
    /* serach ' ' */
    i = 0;
    *channel = params;
    while (i != len && params[i] != ' ')
        i++;
    if (i != len) {
        chn = i;
        /* search */
        *trailing = strstr(params, " :");
        if (*trailing != NULL)
            *trailing = (*trailing)+2;
        params[chn] = '\0';
    }
    else {
        *trailing = NULL;
    }
    
    return 0;
}


static char *IrcPrefNickname(char *prefix, unsigned short len)
{
    unsigned short i;
    char *nickname;

#if 0
    if (prefix == NULL) {
        extern unsigned long crash_pkt_cnt;
        printf("Merda: %lu\n", crash_pkt_cnt);
        exit(-1);
    }
#endif

    nickname = prefix++;
    i = 1;
    while (i != len && prefix[i] != '!' && prefix[i] != '@')
        i++;
    if (i == len)
        return NULL;
    prefix[i] = '\0';
    
    return nickname;
}


static int IrcChannel(irc_con *irc, packet *pkt, char *from, char *channel, char *buffer, bool client)
{
    irc_chat *chat;
    bool priv_chat;
    char *chnnl;
    struct tm tmm;
    pei_component *cmpn;

    /* type of channel/private messages */
    if (channel[0] != '#' && channel[0] != '&' && channel[0] != '!' && channel[0] != '+') {
        /* private mesdages */
        priv_chat = TRUE;
        if (client)
            chnnl = channel;
        else
            chnnl = from;
    }
    else {
        priv_chat = FALSE;
        chnnl = channel;
    }
        
    /* channel search */
    chat = irc->chat;
    while (chat != NULL) {
        if (strcasecmp(chat->channel, chnnl) == 0)
            break;
        chat = chat->nxt;
    }
    if (chat == NULL) {
        /* new channel */
        chat = IrcNewChannel(chnnl);
        if (chat != NULL) {
            chat->user = priv_chat;
            chat->start_time = pkt->cap_sec;
            chat->nxt = irc->chat;
            irc->chat = chat;
            irc->nchat++;
            /* pei */
            PeiNew(&(chat->cpei), irc_id);
            PeiCapTime(chat->cpei, pkt->cap_sec);
            PeiMarker(chat->cpei, pkt->serial);
            PeiStackFlow(chat->cpei, FlowStack(irc->flow_id));
            PeiParent(chat->cpei, irc->mpei);
            PeiSetReturn(chat->cpei, TRUE);
            /* pei components */
            PeiNewComponent(&cmpn, pei_channel_id);
            PeiCompCapTime(cmpn, pkt->cap_sec);
            PeiCompAddFile(cmpn, chat->channel, chat->chat_msg, 0);
            PeiAddComponent(chat->cpei, cmpn);

            PeiNewComponent(&cmpn, pei_channel_users_id);
            PeiCompCapTime(cmpn, pkt->cap_sec);
            PeiCompAddFile(cmpn, "users.txt", chat->users, 0);
            PeiAddComponent(chat->cpei, cmpn);

            PeiNewComponent(&cmpn, pei_channel_nick_id);
            PeiCompCapTime(cmpn, pkt->cap_sec);
            PeiCompAddFile(cmpn, "nick.txt", chat->nick, 0);
            PeiAddComponent(chat->cpei, cmpn);

            PeiIns(chat->cpei);

            /* nick name */
            gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
            fprintf(chat->nick_fp, "[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, irc->nick);
        }
        else {
            return -1;
        }
    }
    if (buffer) {
        if (from != NULL) {
            gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
            fprintf(chat->msg_fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, from);
        }
        fwrite(buffer, 1, strlen(buffer), chat->msg_fp);
        fwrite("\n", 1, 1, chat->msg_fp);
    }
    
    return 0;
}


void IrcCloseChannel(irc_con *irc, char *channel, time_t end)
{
    irc_chat *chat, *pre;
    pei_component *cmpn;
    
    chat = irc->chat;
    pre = NULL;
    while (chat != NULL && strcasecmp(channel, chat->channel)) {
        pre = chat;
        chat = chat->nxt;
    }
    if (chat != NULL) {
        fclose(chat->msg_fp);
        fclose(chat->users_fp);
        fclose(chat->nick_fp);
        chat->end_time = end;
        if (chat->cpei != NULL) {
            /* complete PEI */
            cmpn = PeiCompSearch(chat->cpei, pei_channel_id);
            if (cmpn != NULL) {
                PeiCompAddFile(cmpn, chat->channel, chat->chat_msg, 0);
                PeiCompCapEndTime(cmpn, end);
                PeiCompUpdated(cmpn);
            }
            cmpn = PeiCompSearch(chat->cpei, pei_channel_users_id);
            if (cmpn != NULL) {
                PeiCompAddFile(cmpn, "users.txt", chat->users, 0);
                PeiCompCapEndTime(cmpn, end);
                PeiCompUpdated(cmpn);
            }
            cmpn = PeiCompSearch(chat->cpei, pei_channel_nick_id);
            if (cmpn != NULL) {
                PeiCompAddFile(cmpn, "nick.txt", chat->nick, 0);
                PeiCompCapEndTime(cmpn, end);
                PeiCompUpdated(cmpn);
            }
        
            PeiSetReturn(chat->cpei, FALSE);
            PeiIns(chat->cpei);
        }
        else {
            LogPrintf(LV_ERROR, "Bug: channel with out data");
        }
        
        if (pre == NULL) {
            irc->chat = chat->nxt;
        }
        else {
            pre->nxt = chat->nxt;
        }
        xfree(chat);
    }
}


static int IrcPart(irc_con *irc, char *params, unsigned short len, time_t end)
{
    char *chn;
    unsigned short i;

    /* find channels */
    chn = params;
    i = 0;
    while (i!=len) {
        if (params[i] == ' ' || params[i] == ',') {
            params[i] = '\0';
            IrcCloseChannel(irc, chn, end);
            chn = params + i + 1;
        }
        i++;
    }
    if (chn == params) {
        IrcCloseChannel(irc, chn, end);
    }
    
    return 0;
}


static int IrcChatUsers(irc_con *irc, char *params, unsigned short len, packet *pkt)
{
    unsigned short i;
    char *channel;
    char *nick;
    struct tm tmm;
    irc_chat *chat;
    bool priv_chat;
    pei_component *cmpn;

    if (params == NULL) {
        return -1;
    }
    if (params[0] == ' ') {
        params++;
        len--;
    }
    /* serach ' ' */
    nick = params;
    i = 0;
    while (i != len && params[i] != ' ') {
        i++;
    }
    if (i == len)
        return -1;
    nick[i] = '\0';
    IrcNick(nick, irc, pkt->cap_sec);

    /* search '=' or '*' or '@' */
    while (i != len && params[i] != '=' && params[i] != '*' && params[i] != '@') {
        i++;
    }
    if (i == len)
        return -1;
    i++;
    while (i != len && params[i] == ' ') {
        i++;
    }
    if (i == len)
        return -1;
    channel = params + i;
    while (i != len && params[i] != ' ') {
        i++;
    }
    if (i == len)
        return -1;
    params[i] = '\0';
    /* search channel */
    chat = irc->chat;
    while (chat != NULL && strcasecmp(channel, chat->channel)) {
        chat = chat->nxt;
    }
    if (chat == NULL) {
        /* new channel */
        chat = IrcNewChannel(channel);
        if (chat != NULL) {
            priv_chat = FALSE;
            if (channel[0] != '#' && channel[0] != '&' && channel[0] != '!' && channel[0] != '+') {
                /* private mesdages */
                priv_chat = TRUE;
            }
            chat->user = priv_chat;
            chat->start_time = pkt->cap_sec;
            chat->nxt = irc->chat;
            irc->chat = chat;
            irc->nchat++;
            /* pei */
            PeiNew(&(chat->cpei), irc_id);
            PeiCapTime(chat->cpei, pkt->cap_sec);
            PeiMarker(chat->cpei, pkt->serial);
            PeiStackFlow(chat->cpei, FlowStack(irc->flow_id));
            PeiParent(chat->cpei, irc->mpei);
            PeiSetReturn(chat->cpei, TRUE);
            /* pei components */
            PeiNewComponent(&cmpn, pei_channel_id);
            PeiCompCapTime(cmpn, pkt->cap_sec);
            PeiCompAddFile(cmpn, chat->channel, chat->chat_msg, 0);
            PeiAddComponent(chat->cpei, cmpn);

            PeiNewComponent(&cmpn, pei_channel_users_id);
            PeiCompCapTime(cmpn, pkt->cap_sec);
            PeiCompAddFile(cmpn, "users.txt", chat->users, 0);
            PeiAddComponent(chat->cpei, cmpn);

            PeiNewComponent(&cmpn, pei_channel_nick_id);
            PeiCompCapTime(cmpn, pkt->cap_sec);
            PeiCompAddFile(cmpn, "nick.txt", chat->nick, 0);
            PeiAddComponent(chat->cpei, cmpn);

            /* nick name */
            gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
            fprintf(chat->nick_fp, "[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, irc->nick);
        }
        else
            return -1;
    }
    while (i != len && params[i] != ':') {
        i++;
    }
    i++;
    if (i == len)
        return -1;
    while (i != len && params[i] == ' ') {
        i++;
    }
    if (i == len)
        return -1;
    
    /* store the nick name of the channel */
    gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
    do {
        nick = params + i;
        while (i != len && params[i] != ' ') {
            i++;
        }
        if (params[i] == ' ') {
            params[i] = '\0';
            i++;
            if (nick[0] == '@' || nick[0] == '+')
                nick = nick + 1;
            fprintf(chat->users_fp, "[%.2i:%.2i:%.2i]%s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nick);
        }
    } while (i != len);

    return 0;
}


static int IrcJoin(irc_con *irc, irc_msg *msg, packet *pkt, bool clnt)
{
    unsigned short i, len;
    char *channel, *params, *nickname;
    struct tm tmm;
    irc_chat *chat;
    bool priv_chat;
    pei_component *cmpn;
    
    if (msg == NULL || msg->params == NULL) {
        return -1;
    }
    params = msg->params;
    len = msg->prm_size;
    i = 0;
    do {
        while (i != len && params[i] != '#' && params[i] != '&' && params[i] != '!' && params[0] != '+') {
            i++;
        }
        if (i != len) {
            /* channel */
            channel = params + i;
            while (i != len && params[i] != ' ' && params[i] != '\r' && params[i] != '\n') {
                i++;
            }
            if (i != len) {
                params[i] = '\0';
                i++;
                /* search channel */
                chat = irc->chat;
                while (chat != NULL && strcasecmp(channel, chat->channel)) {
                    chat = chat->nxt;
                }
                if (chat == NULL) {
                    /* new channel */
                    chat = IrcNewChannel(channel);
                    if (chat != NULL) {
                        priv_chat = FALSE;
                        if (channel[0] != '#' && channel[0] != '&' && channel[0] != '!' && channel[0] != '+') {
                            /* private mesdages */
                            priv_chat = TRUE;
                        }
                        chat->user = priv_chat;
                        chat->start_time = pkt->cap_sec;
                        chat->nxt = irc->chat;
                        irc->chat = chat;
                        irc->nchat++;
                        /* pei */
                        PeiNew(&(chat->cpei), irc_id);
                        PeiCapTime(chat->cpei, pkt->cap_sec);
                        PeiMarker(chat->cpei, pkt->serial);
                        PeiStackFlow(chat->cpei, FlowStack(irc->flow_id));
                        PeiParent(chat->cpei, irc->mpei);
                        PeiSetReturn(chat->cpei, TRUE);
                        /* pei components */
                        PeiNewComponent(&cmpn, pei_channel_id);
                        PeiCompCapTime(cmpn, pkt->cap_sec);
                        PeiCompAddFile(cmpn, chat->channel, chat->chat_msg, 0);
                        PeiAddComponent(chat->cpei, cmpn);
                        
                        PeiNewComponent(&cmpn, pei_channel_users_id);
                        PeiCompCapTime(cmpn, pkt->cap_sec);
                        PeiCompAddFile(cmpn, "users.txt", chat->users, 0);
                        PeiAddComponent(chat->cpei, cmpn);
                        
                        PeiNewComponent(&cmpn, pei_channel_nick_id);
                        PeiCompCapTime(cmpn, pkt->cap_sec);
                        PeiCompAddFile(cmpn, "nick.txt", chat->nick, 0);
                        PeiAddComponent(chat->cpei, cmpn);

                        /* nick name */
                        gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
                        fprintf(chat->nick_fp, "[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, irc->nick);
                    }
                }
                if (chat != NULL) {
                    /* user name */
                    nickname = IrcPrefNickname(msg->prefix, msg->p_size);
                    gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
                    fprintf(chat->users_fp, "[%.2i:%.2i:%.2i]%s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nickname);
                }
            }
        }
    } while (i != len);
    
    return 0;
}


static int IrcSerPart(irc_con *irc, irc_msg *msg, packet *pkt)
{
    unsigned short i, len;
    char *channel, *params, *nickname;
    struct tm tmm;
    irc_chat *chat;
    bool priv_chat;
    pei_component *cmpn;
    
    if (msg == NULL || msg->params == NULL) {
        return -1;
    }
    params = msg->params;
    len = msg->prm_size;
    i = 0;
    do {
        while (i != len && params[i] != '#' && params[i] != '&' && params[i] != '!' && params[0] != '+' && params[0] != ':') {
            i++;
        }
        if (i != len) {
            if (params[i] == ':') {
                break;
            }
            /* channel */
            channel = params + i;
            while (i != len && params[i] != ' ' && params[i] != '\r' && params[i] != '\n') {
                i++;
            }
            if (i != len) {
                params[i] = '\0';
                i++;
                /* search channel */
                chat = irc->chat;
                while (chat != NULL && strcasecmp(channel, chat->channel)) {
                    chat = chat->nxt;
                }
                if (chat == NULL) {
                    nickname = IrcPrefNickname(msg->prefix, msg->p_size);
                    if (strcmp(nickname, irc->nick)) {
                        /* new channel */
                        chat = IrcNewChannel(channel);
                        if (chat != NULL) {
                            priv_chat = FALSE;
                            if (channel[0] != '#' && channel[0] != '&' && channel[0] != '!' && channel[0] != '+') {
                                /* private mesdages */
                                priv_chat = TRUE;
                            }
                            chat->user = priv_chat;
                            chat->start_time = pkt->cap_sec;
                            chat->nxt = irc->chat;
                            irc->chat = chat;
                            irc->nchat++;
                            /* pei */
                            PeiNew(&(chat->cpei), irc_id);
                            PeiCapTime(chat->cpei, pkt->cap_sec);
                            PeiMarker(chat->cpei, pkt->serial);
                            PeiStackFlow(chat->cpei, FlowStack(irc->flow_id));
                            PeiParent(chat->cpei, irc->mpei);
                            PeiSetReturn(chat->cpei, TRUE);
                            /* pei components */
                            PeiNewComponent(&cmpn, pei_channel_id);
                            PeiCompCapTime(cmpn, pkt->cap_sec);
                            PeiCompAddFile(cmpn, chat->channel, chat->chat_msg, 0);
                            PeiAddComponent(chat->cpei, cmpn);
                            
                            PeiNewComponent(&cmpn, pei_channel_users_id);
                            PeiCompCapTime(cmpn, pkt->cap_sec);
                            PeiCompAddFile(cmpn, "users.txt", chat->users, 0);
                            PeiAddComponent(chat->cpei, cmpn);
                            
                            PeiNewComponent(&cmpn, pei_channel_nick_id);
                            PeiCompCapTime(cmpn, pkt->cap_sec);
                            PeiCompAddFile(cmpn, "nick.txt", chat->nick, 0);
                            PeiAddComponent(chat->cpei, cmpn);
                        }
                    }
                }
                if (chat != NULL) {
                    /* user name */
                    nickname = IrcPrefNickname(msg->prefix, msg->p_size);
                    gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
                    fprintf(chat->users_fp, "E[%.2i:%.2i:%.2i]%s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nickname);
                }
            }
        }
    } while (i != len);
    
    return 0;
}


static int IrcNewNick(irc_con *irc, irc_msg *msg, packet *pkt, bool clnt)
{
    unsigned short i, len;
    char *new, *params, *nickname;
    struct tm tmm;
    irc_chat *chat;
    bool ow;
    
    if (msg == NULL || msg->params == NULL) {
        return -1;
    }
    params = msg->params;
    len = msg->prm_size;
    i = 0;
    while (i != len && (params[i] == ' ' || params[i] == ':')) {
        i++;
    }
    if (i != len) {
        /* new nick */
        new = params + i;
        while (i != len && params[i] != ' ' && params[i] != '\r' && params[i] != '\n') {
            i++;
        }
        if (i != len) {
            params[i] = '\0';
            i++;
            /* user name */
            nickname = IrcPrefNickname(msg->prefix, msg->p_size);
            if (strcmp(nickname, irc->nick) == 0) {
                ow = TRUE;
            }
            else {
                ow = FALSE;
            }
            gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
            chat = irc->chat;
            while (chat != NULL) {
                fprintf(chat->users_fp, "M[%.2i:%.2i:%.2i]%s -> %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nickname, new);
                if (ow) {
                    fprintf(chat->nick_fp, "[%.2i:%.2i:%.2i]%s -> %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nickname, new);
                }
                chat = chat->nxt;
            }
        }
    }
    
    return 0;
}


static int IrcQuit(irc_con *irc, irc_msg *msg, packet *pkt)
{
    char *nickname;
    struct tm tmm;
    irc_chat *chat;
    
    if (msg == NULL || msg->prefix == NULL) {
        return -1;
    }
    /* user name */
    nickname = IrcPrefNickname(msg->prefix, msg->p_size);
    gmtime_r((time_t *)&(pkt->cap_sec), &tmm);
    chat = irc->chat;
    while (chat != NULL) {
        fprintf(chat->users_fp, "Q[%.2i:%.2i:%.2i]%s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nickname);
        chat = chat->nxt;
    }
    
    return 0;
}


static int IrcConnec(int flow_id, irc_priv *priv)
{
    packet *pkt;
    ftval lost, val;
    const pstack_f *ip;
    pei *mpei;
    pei_component *cmpn, *ccount;
    int ret, i, data_id;
    FILE *fp_cmd;
    unsigned long serial, cap_end;
    bool clnt, first;
    char *filename, *url;
    char *buff_c, *buff_s, *swap;
    char *line, *trailing, *channel, *from;
    unsigned int buff_c_len, buff_c_dim, buff_s_len, buff_s_dim, swap_i;
    const char *eol, *lend, *end;
    irc_msg msg;
    irc_con irc;
    char nick[IRC_NICKNAME_MAX_SIZE]; /* actual nick name */
    irc_chat *chat;
    
    /* init */
    ret = 0;
    IrcConInit(&irc);
    data_id = -1;
    first = TRUE;
    filename = NULL;
    mpei = NULL;
    nick[0] = '\0';
    
    /* cmd file path and name, creates the directory and  */
    sprintf(irc.file_cmd, "%s/%s/irc_%lld_%p_%i.txt", ProtTmpDir(), IRC_TMP_DIR, (long long)time(NULL), &irc, incr);
    incr++;

    /* open file , correct rights on writing and reading */
    fp_cmd = fopen(irc.file_cmd, "w");
    if (fp_cmd == NULL) {
        /* we are having an error on opening the file, log it and free resources */
        LogPrintf(LV_ERROR, "Unable to open file %s", irc.file_cmd);
        IrcConFree(&irc);
        return -1;
    }
    
    /* url */
    url = xmalloc(IRC_DATA_BUFFER);
    ip = ProtGetNxtFrame(FlowStack(flow_id));
    if (ProtFrameProtocol(ip) == ip_id) {
        ProtGetAttr(ip, ip_dst_id, &val);
        if (DnsDbSearch(&val, FT_IPv4, url, IRC_DATA_BUFFER) != 0) {
            FTString(&val, FT_IPv4, url);
        }
    }
    else {
        ProtGetAttr(ip, ipv6_dst_id, &val);
        if (DnsDbSearch(&val, FT_IPv6, url, IRC_DATA_BUFFER) != 0) {
            FTString(&val, FT_IPv6, url);
        }
    }
    /* first tcp packet, we take the flow and assign it to "pkt" */
    pkt = FlowGetPkt(flow_id);
    
    /* master pei */
    PeiNew(&mpei, irc_id);
    PeiCapTime(mpei, pkt->cap_sec);
    PeiMarker(mpei, pkt->serial);
    PeiStackFlow(mpei, FlowStack(flow_id));    
    PeiSetReturn(mpei, TRUE); /* neccesary */
    /* components */
    PeiNewComponent(&cmpn, pei_url_id);
    PeiCompCapTime(cmpn, pkt->cap_sec);
    PeiCompAddStingBuff(cmpn, url);
    PeiAddComponent(mpei, cmpn);
    
    PeiNewComponent(&cmpn, pei_server_id);
    PeiCompCapTime(cmpn, pkt->cap_sec);
    PeiCompAddFile(cmpn, "server_commands.txt", irc.file_cmd, 0);
    PeiAddComponent(mpei, cmpn);

    PeiNewComponent(&ccount, pei_channels_num_id);
    PeiCompCapTime(ccount, pkt->cap_sec);
    PeiCompAddStingBuff(ccount, "0");
    PeiAddComponent(mpei, ccount);

    PeiIns(mpei);
    irc.mpei = mpei;
    irc.flow_id = flow_id;
    xfree(url);
    url = NULL;

    /* main loop */
    buff_c = xmalloc(IRC_DATA_BUFFER);
    buff_c[0] = '\0';
    buff_c_len = 0;
    buff_c_dim = IRC_DATA_BUFFER;
    buff_s = xmalloc(IRC_DATA_BUFFER);
    buff_s[0] = '\0';
    buff_s_len = 0;
    buff_s_dim = IRC_DATA_BUFFER;
    
    do {
        serial = pkt->serial;
        cap_end = pkt->cap_sec;
        clnt = IrcClientPkt(priv, pkt); /* Decide direction of transmission */
        /* check if there are packet lost */
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == TRUE) {
            //ProtStackFrmDisp(pkt->stk, TRUE);
            /* packet lost */
            irc.lost = TRUE;
            if (clnt)
                fwrite("------------Xplico: Client packet lost---------\n\r", 1, 48, fp_cmd);
            else
                fwrite("------------Xplico: Server packet lost---------\n\r", 1, 48, fp_cmd);
        }
        else if (pkt->len != 0) {
            if (clnt) {
                /* client */
                if (buff_c_len + pkt->len > buff_c_dim) {
                    buff_c = xrealloc(buff_c, buff_c_dim + IRC_DATA_BUFFER);
                    buff_c_dim += IRC_DATA_BUFFER;
                }
                memcpy(buff_c+buff_c_len, pkt->data, pkt->len);
                buff_c_len += pkt->len;
                buff_c[buff_c_len] = '\0';
                end = buff_c + buff_c_len;
                line = buff_c;
                do {
                    lend = find_line_end(line, end, &eol); /* looks for a line terminator and returns a pointer to end-of-line */
                    if (*eol == '\r' || *eol == '\n') {
                        *((char *)eol) = '\0';
                        IrcMsg(line, lend-line, &msg);
                        if (msg.repl != -1) {
                            /* this is a server message */
                            /* swap buffer */
                            swap = buff_c;
                            buff_c = buff_s;
                            buff_s = swap;
                            swap_i = buff_c_len;
                            buff_c_len = buff_s_len;
                            buff_s_len = swap_i;
                            swap_i = buff_c_dim;
                            buff_c_dim = buff_s_dim;
                            buff_s_dim = swap_i;
                            lend = end;
                            LogPrintf(LV_ERROR, "Server-Client Swap");
                            priv->dir = IRC_CLT_DIR_REVERS;
                            clnt = FALSE;
                            break;
                        }
			switch(msg.cmd) {
                        case IRC_CMD_JOIN:
                            break;

                        case IRC_CMD_PRIVMSG:
                            if (!IrcPrivmsg(msg.params, msg.prm_size, &channel, &trailing)) {
                                IrcChannel(&irc, pkt, nick, channel, trailing, TRUE);
                            }
                            break;

                        case IRC_CMD_NOTICE:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_PART:
                            IrcPart(&irc, msg.params, msg.prm_size, pkt->cap_sec);
                            break;

                        case IRC_CMD_PASS:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_MODE:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_TOPIC:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_NICK:
                            break;

                        case IRC_CMD_USER:
                            //IrcUser(&irc, line, lend-line);
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_WHOIS:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_OPER:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_WHO:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;

                        case IRC_CMD_NONE:
                            LogPrintf(LV_WARNING, "command unknow: %s", line);
                            break;
                            
                        default:
                            fwrite(line, 1, lend-line, fp_cmd);
                            break;
                        }
                        for (i=0; lend!=end; i++) {
                            buff_c[i] = *lend;
                            lend++;
                        }
                        buff_c_len = i;
                        end = buff_c + buff_c_len;
                        buff_c[buff_c_len] = '\0';
                        lend = NULL;
                    }
		} while (lend != end);
            }
            if (!clnt) {
                /* server */
                if (buff_s_len + pkt->len > buff_s_dim) {
                    buff_s = xrealloc(buff_s, buff_s_dim + IRC_DATA_BUFFER);
                    buff_s_dim += IRC_DATA_BUFFER;
                }
                memcpy(buff_s+buff_s_len, pkt->data, pkt->len);
                buff_s_len += pkt->len;
                buff_s[buff_s_len] = '\0';
                end = buff_s + buff_s_len;
                line = buff_s;
                do {
                    lend = find_line_end(line, end, &eol); /* looks for a line terminator and returns a pointer to end-of-line */
                    if (*eol == '\r' || *eol == '\n') {
                       *((char *)eol) = '\0';
                        IrcMsg(line, lend-line, &msg);
                        if (msg.repl != -1) {
                            switch (msg.repl) {
                            case IRC_RPL_NAMREPLY: /* nick name list */
                                IrcChatUsers(&irc, msg.params, msg.prm_size, pkt);
                                break;
                                
                            case IRC_RPL_WELCOME:
                            case IRC_RPL_YOURHOST:
                            case IRC_RPL_CREATED:
                            case IRC_RPL_MYINFO:
                                /*case IRC_RPL_BOUNCE:*/
                            case IRC_RPL_MOTD:
                            case IRC_RPL_MOTDSTART:
                            case IRC_RPL_LUSERCLIENT:
                            case IRC_RPL_LUSERME:
                            case IRC_RPL_265:
                            case IRC_RPL_266:
                                if (IrcTargetTrailing(msg.params, msg.prm_size, nick, &trailing) == 0) {
                                    if (trailing != NULL) {
                                        fwrite(trailing, 1, strlen(trailing), fp_cmd);
                                        fwrite("\r\n", 1, 2, fp_cmd);
                                    }
                                    IrcNick(nick, &irc, pkt->cap_sec);
                                }
                                break;
                                
                            case IRC_RPL_TOPIC:
                                if (!IrcTopic(msg.params, msg.prm_size, nick, &channel, &trailing)) {
                                    IrcChannel(&irc, pkt, NULL, channel, trailing, FALSE);
                                    IrcNick(nick, &irc, pkt->cap_sec);
                                }
                                break;
                                
                            default:
                                fwrite(line, 1, lend-line, fp_cmd);
                                break;
                            }
                        }
                        else {
                            switch (msg.cmd) {
                            case IRC_CMD_JOIN: /* new nick  name*/
                                IrcJoin(&irc, &msg, pkt, FALSE);
                                break;

                            case IRC_CMD_NICK: /* nick change */
                                IrcNewNick(&irc, &msg, pkt, FALSE);
                                break;

                            case IRC_CMD_PRIVMSG:
                                if (!IrcPrivmsg(msg.params, msg.prm_size, &channel, &trailing)) {
                                    from = IrcPrefNickname(msg.prefix, msg.p_size);
                                    IrcChannel(&irc, pkt, from, channel, trailing, FALSE);
                                }
                                break;

                            case IRC_CMD_PART: /* nick name out */
                                IrcSerPart(&irc, &msg, pkt);
                                break;
                                
                            case IRC_CMD_QUIT: /* nick name out */
                                IrcQuit(&irc, &msg, pkt);
                                break;
                                
                            default:
                                fwrite(line, 1, lend-line, fp_cmd);
                                break;
                            }
                        }
                        for (i=0; lend!=end; i++) {
                            buff_s[i] = *lend;
                            lend++;
                        }
                        buff_s_len = i;
                        end = buff_s + buff_s_len;
                        buff_s[buff_s_len] = '\0';
                        lend = NULL;
                    }
		} while (lend != end);
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    } while (pkt != NULL);
    
    /* close all channel */
    chat = irc.chat;
    while (chat != NULL) {
        IrcCloseChannel(&irc, chat->channel, cap_end);
        chat = irc.chat;
    }

    /* update master pei */
    fclose(fp_cmd);
    PeiCompAddFile(cmpn, "server_commands.txt", irc.file_cmd, 0);
    PeiCompCapEndTime(cmpn, cap_end);
    PeiCompUpdated(cmpn);
    PeiCompCapEndTime(ccount, cap_end);
    sprintf(nick, "%i", irc.nchat);
    PeiCompAddStingBuff(ccount, nick);
    PeiCompUpdated(ccount);

    PeiSetReturn(mpei, FALSE);
    PeiIns(mpei);

    /* free memory */
    IrcConFree(&irc);
    
    return -1;
}


static packet* IrcDissector(int flow_id)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, ip_dst;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    irc_priv *priv;
    packet *pkt;

    LogPrintf(LV_DEBUG, "IRC id: %d", flow_id);
    priv = DMemMalloc(sizeof(irc_priv));
    memset(priv, 0, sizeof(irc_priv));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv->port = port_src.uint16;
    priv->dir = IRC_CLT_DIR_NONE;
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
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip);
        ProtGetAttr(ip, ipv6_dst_id, &ip_dst);
        memcpy(ipv6_addr.s6_addr, priv->ip.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, ip_dst.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);

    if (IrcConnec(flow_id, priv) != 0) {
        /* raw irc file */
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
	    PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }

    /* free memory */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "IRC... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool IrcVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    bool ipv4, client;
    ftval lost, ips, ip_s;
    bool ret, fr_data;
    char *data, *new;
    short verify_step; /* 0: none; 1: command client ok;  2: server ok; */
    int cmp;
    unsigned long len;
    const char *eol, *lineend;
    irc_msg irc_msg;

    ipv4 = FALSE;
    client = TRUE; /* first packet without lost packet is a client packet */
    ret = FALSE;
    fr_data = FALSE;
    verify_step = 0;
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
        while (lost.uint8 == TRUE || pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL)
                break;
            ProtGetAttr(pkt->stk, lost_id, &lost);
        }
    }
    if (pkt != NULL  && lost.uint8 == FALSE) {
        ip = ProtGetNxtFrame(pkt->stk);
        if (ipv4 == TRUE) {
            ProtGetAttr(ip, ip_src_id, &ip_s);
            cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
        }
        else {
            ProtGetAttr(ip, ipv6_src_id, &ip_s);
            cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
        }
        if (cmp != 0) {
            /* first packet (with data) is server packet */
            client = FALSE;
            if (check == FALSE) {
                verify_step = 1;
            }
        }

        data = (char *)pkt->data;
        len = pkt->len;
        do {
            lineend = find_line_end(data, data+len, &eol);
            if (*eol == '\r' || *eol == '\n') {
                if (verify_step == 0 && client == TRUE) {
                    /* first step verify client */
                    IrcMsg(data, lineend-data, &irc_msg);
                    if (irc_msg.cmd != IRC_CMD_NONE) {
                        if (check == FALSE) {
                            ret = TRUE;
                            break;
                        }
                        verify_step = 1;
                    }
                    else {
                        break;
                    }
                }
                else if (verify_step == 1) {
                    if (client == FALSE) {
                        /* second step verify command from server */
                        IrcMsg(data, lineend-data, &irc_msg);
                        if (irc_msg.cmd != IRC_CMD_NONE || irc_msg.repl != -1) {
                            ret = TRUE;
                            break;
                        }
                        else {
                            break;
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
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt != NULL) {
                ProtGetAttr(pkt->stk, lost_id, &lost);
                while (lost.uint8 == TRUE || pkt->len == 0) {
                    PktFree(pkt);
                    pkt = FlowGetPktCp(flow_id);
                    if (pkt == NULL)
                        break;
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                }
            }
            if (pkt != NULL) {
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
                    /* client to server */
                    if (client == FALSE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    new = xrealloc(data, len+pkt->len+1);
                    if (new == NULL) {
                        LogPrintf(LV_WARNING, "Memmory unavailable");
                        break;
                    }
                    data = new;
                    memcpy(data+len, pkt->data, pkt->len);
                    len += pkt->len;
                    data[len] = '\0';
                    client = TRUE;
                }
                else {
                    /* server to client */
                    if (client == TRUE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    new = xrealloc(data, len+pkt->len+1);
                    if (new == NULL) {
                        LogPrintf(LV_WARNING, "Memmory unavailable");
                        break;
                    }
                    data = new;
                    memcpy(data+len, pkt->data, pkt->len);
                    len += pkt->len;
                    data[len] = '\0';
                    client = FALSE;
                }
            }
        } while (pkt != NULL && len < 1024); /* 1k: max irc server presentation */

        /* free memory */
        if (data != NULL && fr_data == TRUE) {
            xfree(data);
        }
    }
    
    if (pkt != NULL)
        PktFree(pkt);

    return ret;
}


static bool IrcVerify(int flow_id)
{
    return IrcVerifyCheck(flow_id, FALSE);
}


static bool IrcCheck(int flow_id)
{
    return IrcVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));

    /* protocol name */
    ProtName("Internet Relay Chat", "irc");
    
    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_IRC;
    dep.ProtCheck = IrcVerify;
    dep.pktlim = IRC_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = IrcCheck;
    hdep.pktlim = IRC_PKT_CHECK_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "IRC server url";
    ProtPeiComponent(&peic);
    peic.abbrev = "cmd";
    peic.desc = "Client-Server Commands";
    ProtPeiComponent(&peic);
    peic.abbrev = "channel";
    peic.desc = "channel comunications messages";
    ProtPeiComponent(&peic);
    peic.abbrev = "chnl_num";
    peic.desc = "total channel's number";
    ProtPeiComponent(&peic);
    peic.abbrev = "cusers";
    peic.desc = "channel users";
    ProtPeiComponent(&peic);
    peic.abbrev = "cnick";
    peic.desc = "channel nick names";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, IrcDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char irc_dir[256];

    /* part of file name */
    incr = 0;
    incr_channel = 0;

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
    clnt_id = ProtAttrId(tcp_id, "tcp.clnt");
    irc_id = ProtId("irc");

    /* pei id */
    /* Initialization of PEI components*/
    pei_url_id = ProtPeiComptId(irc_id, "url");
    pei_server_id = ProtPeiComptId(irc_id, "cmd");
    pei_channel_id = ProtPeiComptId(irc_id, "channel");
    pei_channels_num_id = ProtPeiComptId(irc_id, "chnl_num");
    pei_channel_users_id = ProtPeiComptId(irc_id, "cusers");
    pei_channel_nick_id= ProtPeiComptId(irc_id, "cnick");

    /* irc tmp directory */
    sprintf(irc_dir, "%s/%s", ProtTmpDir(), IRC_TMP_DIR);
    mkdir(irc_dir, 0x01FF);

    return 0;
}
