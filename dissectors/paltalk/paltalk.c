/* paltalk.c
 * paltalk packet dissection
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * reverse engineering by Tim Hentenaar	<tim@hentsoft.com> (Paltalk Protocol Plugin for Gaim)
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
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

#include "etypes.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "dnsdb.h"
#include "paltalk.h"
#include "pei.h"
#include "genfun.h"

#define PLTK_TMP_DIR    "paltalk"
#define PACKET_GET_LONG(X,O)          (long)ntohl(*(long *)(X+O))

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int tcp_id;
static int tcp_port_src_id;
static int tcp_port_dst_id;
static int tcp_lost_id;
static int tcp_clnt_id;
static int paltalk_id;

/* pei id */
static int pei_room_id;          /* room name and messages file */
static int pei_room_users_id;    /* room users */
static int pei_room_nick_id;     /* nick names of the user */
static int pei_room_duration_id; /* room time */

static volatile unsigned int incr;
static volatile unsigned int incr_room;

static const char *PaltalkTagDel(const char *str)
{
    char *start, *end;
    unsigned char *ascii;
    bool new;
    
    /* skip '>>' */
    start = strstr(str, "<<(");
    end = strstr(str, ")>>");
    if (end != NULL && start != NULL && start < end ) {
         end++;
         strcpy(start, end);
    }
    
    new = FALSE;
    do {
        start = strchr(str, '<');
        end = strchr(str, '>');
        if (end != NULL && start != NULL && start < end) {
            ascii = (unsigned char *)str;
            while ((char *)ascii < start) {
                if (*ascii < 32 || *ascii > 126) {
                    new = TRUE;
                    strcpy((char *)ascii, (char *)ascii + 1);
                    start--;
                    end--;
                }
                else
                    ascii++;
            }
            end++;
            strcpy(start, end);
        }
        else {
            break;
        }
    } while (1);

    return str;
}


static void PltkConInit(pltk_con *pltk)
{
    memset(pltk, 0, sizeof(pltk_con));
    pltk->flow_id = -1;
    pltk->uid_s[0] = '\0';
    pltk->email[0] = '\0';
    pltk->nick[0] = '\0';
    pltk->nchat = 0;
    pltk->chat = NULL;
    pltk->buddy = NULL;
    pltk->private = NULL;
}


static void PltkMsgConvert(pltk_msg *msg)
{
    msg->type = ntohs(msg->type);
    msg->version = ntohs(msg->version);
    msg->length = ntohs(msg->length);
}


static void PltkRoomMsgInConvert(pltk_room_msg_in *msg)
{
    msg->uid = ntohl(msg->uid);
    msg->gid = ntohl(msg->gid);
}


static void PltkImMsgConvert(pltk_im_msg *msg)
{
    msg->uid = ntohl(msg->uid);
}


static void PltkMsgPrint(pltk_msg *msg)
{
#if 0
    unsigned short i;

    LogPrintf(LV_DEBUG, "  type: %i (0x%x)", (short)msg->type, msg->type);
    LogPrintf(LV_DEBUG, "  ver: %i", msg->version);
    LogPrintf(LV_DEBUG, "  len: %i", msg->length);
    LogPrintf(LV_DEBUG, "  %s", msg->payload);
# if 0
    for (i=0; i!= msg->length; i++) {
        printf("%c", msg->payload[i]);
    }
    printf("\n");
# endif
#endif
}


static void PltkMsgInfoFree(pltk_msg_info **pmsg, bool client, bool server)
{
    pltk_msg_info *tmp, *pre, *msg;
    
    if (client == server) {
        msg = *pmsg;
        while (msg != NULL) {
            if (msg->msg != NULL)
                xfree(msg->msg);
            tmp = msg->nxt;
            DMemFree(msg);
            msg = tmp;
        }
        *pmsg = NULL;
    }
    else {
        pre = NULL;
        msg = *pmsg;
        while (msg != NULL) {
            if (msg->client == client) {
                if (msg->msg != NULL)
                    xfree(msg->msg);
            }
            tmp = msg->nxt;
            if (msg->client == client) {
                DMemFree(msg);
                if (pre != NULL)
                    pre->nxt = tmp;
                else
                    *pmsg = tmp; 
            }
            else {
                pre = msg;
            }
            msg = tmp;
        }
    }
}


static bool PltkClientPkt(pltk_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, tcp_port_src_id, &port);
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

    /* first time, the verify function verify that first pkt is a server pkt */
    if (priv->dir == PLTK_CLT_DIR_NONE) {
        if (ret == FALSE)
            priv->dir = PLTK_CLT_DIR_OK;
        else {
            priv->dir = PLTK_CLT_DIR_REVERS;
            ret = TRUE;
            LogPrintf(LV_WARNING, "Acqusition file has an error!");
            if (pkt != NULL)
                ProtStackFrmDisp(pkt->stk, TRUE);
        }
    }
    else {
        if (priv->dir == PLTK_CLT_DIR_REVERS)
            ret = !ret;
    }
    
    return ret;
}


static pltk_msg_info *PltkMsg(int flow_id, pltk_msg_info **lst, pltk_priv *priv)
{
    packet *pkt;
    pltk_msg_info *msg, *pre, *msg_c, *msg_s;
    ftval lost;
    unsigned int offset, len;
    unsigned char *buff;
    bool client;
    
    /* check if exist a message completed */
    do {
        pre = msg_c = msg_s = NULL;
        msg = *lst;
        while (msg != NULL && msg->size != 0) {
            if (msg->size > PTLK_HEADER_SIZE && msg->size == msg->msg->length + PTLK_HEADER_SIZE) {
                if (pre != NULL)
                    pre->nxt = msg->nxt;
                else
                    (*lst) = msg->nxt;
                msg->nxt = NULL;
                
                return msg;
            }
            if (msg->client)
                msg_c = msg;
            else
                msg_s = msg;
            pre = msg;
            msg = msg->nxt;
        }
        pkt = FlowGetPkt(flow_id);
        if (pkt != NULL) {
            if (pkt->len != 0) {
                /* check if there are packet lost */
                ProtGetAttr(pkt->stk, tcp_lost_id, &lost);
                client = PltkClientPkt(priv, pkt);
                if (client) {
                    /* client */
                    if (lost.uint8 == TRUE) {
                        /* remove all partial message */
                        PltkMsgInfoFree(lst, TRUE, FALSE);
                        msg = pre = msg_c = msg_s = NULL;
                        *lst = NULL;
                        priv->clost = TRUE;
                        LogPrintf(LV_DEBUG, "Lost");
                        PktFree(pkt);
                        continue;
                    }
                    if (msg_c != NULL) {
                        msg = msg_c;
                    }
                    else {
                        msg = DMemMalloc(sizeof(pltk_msg_info));
                        memset(msg, 0, sizeof(pltk_msg_info));
                        msg->msg = NULL;
                        msg->size = 0;
                        msg->client = client;
                        msg->serial = pkt->serial;
                        msg->start_cap = pkt->cap_sec;
                        msg->end_cap = pkt->cap_sec;
                        msg->nxt = NULL;
                        if (pre != NULL)
                            pre->nxt = msg;
                        else
                            (*lst) = msg;
                    }
                }
                else {
                    /* server */
                    if (lost.uint8 == TRUE) {
                        /* remove all partial message */
                        PltkMsgInfoFree(lst, FALSE, TRUE);
                        msg = pre = msg_c = msg_s = NULL;
                        *lst = NULL;
                        priv->slost = TRUE;
                        LogPrintf(LV_DEBUG, "Lost");
                        PktFree(pkt);
                        continue;
                    }
                    if (msg_s != NULL) {
                        msg = msg_s;
                    }
                    else {
                        msg = DMemMalloc(sizeof(pltk_msg_info));
                        memset(msg, 0, sizeof(pltk_msg_info));
                        msg->msg = NULL;
                        msg->size = 0;
                        msg->client = client;
                        msg->serial = pkt->serial;
                        msg->start_cap = pkt->cap_sec;
                        msg->end_cap = pkt->cap_sec;
                        msg->nxt = NULL;
                        if (pre != NULL)
                            pre->nxt = msg;
                        else
                            (*lst) = msg;
                    }
                }
                pre = msg;
                
                offset = 0;
                if (msg->size >= PTLK_HEADER_SIZE) {
                    len = msg->msg->length - msg->size + PTLK_HEADER_SIZE;
                    if (len <= pkt->len) {
                        buff = (unsigned char *)msg->msg;
                        memcpy(buff + msg->size, pkt->data, len);
                        msg->size += len;
                        ((char *)(msg->msg))[msg->size] = '\0';
                        offset = len;
                    }
                    else {
                        buff = (unsigned char *)msg->msg;
                        memcpy(buff + msg->size, pkt->data, pkt->len);
                        msg->size += pkt->len;
                        offset = pkt->len;
                    }
                    msg = NULL;
                }
                else if (msg->size != 0) {
                    if (msg->size + pkt->len >= PTLK_HEADER_SIZE) {
                        buff = (unsigned char *)msg->msg;
                        memcpy(buff + msg->size, pkt->data, PTLK_HEADER_SIZE - msg->size);
                        len = ntohs(msg->msg->length) + PTLK_HEADER_SIZE + 1;
                        msg->msg = xrealloc(msg->msg, len);
                        len = ntohs(msg->msg->length) - msg->size;
                        if (len <= pkt->len) {
                            buff = (unsigned char *)msg->msg;
                            memcpy(buff + msg->size, pkt->data, len);
                            msg->size += len;
                            ((char *)(msg->msg))[msg->size] = '\0';
                            offset = len;
                        }
                        else {
                            buff = (unsigned char *)msg->msg;
                            memcpy(buff + msg->size, pkt->data, pkt->len);
                            msg->size += pkt->len;
                            offset = pkt->len;
                        }
                        PltkMsgConvert(msg->msg);
                        msg = NULL;
                    }
                    else {
                        buff = (unsigned char *)msg->msg;
                        memcpy(buff + msg->size, pkt->data, pkt->len);
                        msg->size += pkt->len;
                        offset = pkt->len;
                    }
                }
                
                if (offset != pkt->len) {
                    if (msg == NULL) {
                        msg = DMemMalloc(sizeof(pltk_msg_info));
                        memset(msg, 0, sizeof(pltk_msg_info));
                        msg->msg = NULL;
                        msg->size = 0;
                        msg->client = client;
                        msg->serial = pkt->serial;
                        msg->start_cap = pkt->cap_sec;
                        msg->end_cap = pkt->cap_sec;
                        msg->nxt = NULL;
                        pre->nxt = msg;
                        pre = msg;
                    }
                    while (offset != pkt->len) {
                        if ((pkt->len - offset) >= PTLK_HEADER_SIZE) {
                            len = ntohs(((pltk_msg *)(pkt->data + offset))->length) + PTLK_HEADER_SIZE;
                            msg->msg = xmalloc(len + 1);
                            if (len <= pkt->len - offset) {
                                memcpy(msg->msg, pkt->data + offset, len);
                                msg->size = len;
                            }
                            else {
                                msg->size = pkt->len - offset;
                                memcpy(msg->msg, pkt->data + offset, msg->size);
                                
                            }
                            ((char *)(msg->msg))[msg->size] = '\0';
                            offset += msg->size;
                            PltkMsgConvert(msg->msg);
                        }
                        else {
                            msg->size = pkt->len - offset;
                            msg->msg = xmalloc(PTLK_HEADER_SIZE + 1);
                            memcpy(msg->msg, pkt->data + offset, msg->size);
                            ((char *)(msg->msg))[msg->size] = '\0';
                            offset += msg->size;
                        }
                        if (offset != pkt->len) {
                            msg = DMemMalloc(sizeof(pltk_msg_info));
                            memset(msg, 0, sizeof(pltk_msg_info));
                            msg->msg = NULL;
                            msg->size = 0;
                            msg->client = client;
                            msg->serial = pkt->serial;
                            msg->start_cap = pkt->cap_sec;
                            msg->end_cap = pkt->cap_sec;
                            msg->nxt = NULL;
                            pre->nxt = msg;
                            pre = msg;
                        }
                    }
                }
            }
            
            PktFree(pkt);
        }
    } while (pkt != NULL);
    
    return NULL;
}


static void PltkMsgUserData(pltk_msg *msg, pltk_con *pltk)
{
    char *tkn, *end;

    tkn = strstr(msg->payload, PTLK_USER_DATA_UID);
    if (tkn != NULL) {
        end = strstr(tkn, "\n");
        if (end != NULL) {
            end[0] = '\0';
            strncpy(pltk->uid_s, tkn+PTLK_USER_DATA_UID_L, PTLK_USER_DIM);
            pltk->uid = atol(pltk->uid_s);
            end[0] = '\n';
        }
    }
    tkn = strstr(msg->payload, PTLK_USER_DATA_NICK);
    if (tkn != NULL) {
        end = strstr(tkn, "\n");
        if (end != NULL) {
            end[0] = '\0';
            strncpy(pltk->nick, tkn+PTLK_USER_DATA_NICK_L, PTLK_USER_DIM);
            end[0] = '\n';
        }
    }
    tkn = strstr(msg->payload, PTLK_USER_DATA_EMAIL);
    if (tkn != NULL) {
        end = strstr(tkn, "\n");
        if (end != NULL) {
            end[0] = '\0';
            strncpy(pltk->email, tkn+PTLK_USER_DATA_EMAIL_L, PTLK_USER_DIM);
            end[0] = '\n';
        }
    }
}


static void PltkAddUser(pltk_chat_usr *new, pltk_con *pltk, unsigned long gid, time_t start)
{
    pltk_chat *room;
    pltk_chat_usr *usr;
    struct tm tmm;

    /* find the room */
    for (room=pltk->chat; room != NULL; room=room->nxt) {
        if (room->gid == gid) {
            break;
        }
    }
    if (room == NULL) {
        LogPrintf(LV_WARNING, "Room unknow!");
        return;
    }
    /* find user */
    for (usr=room->userl; usr != NULL; usr=usr->nxt) {
        if (usr->uid == new->uid) {
            break;
        }
    }
    if (usr == NULL) {
        new->nxt = room->userl;
        room->userl = new;
        room->num_userl++;
        gmtime_r((time_t *)&(start), &tmm);
        fprintf(room->users_fp, "[%.2i:%.2i:%.2i]%s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, new->nick);
    }
    else {
        xfree(new);
    }
}


static void PltkBuddyUser(pltk_chat_usr *new, pltk_con *pltk, time_t start)
{
    pltk_chat_usr *usr;
    
    /* find user */
    for (usr=pltk->buddy; usr != NULL; usr=usr->nxt) {
        if (usr->uid == new->uid) {
            break;
        }
    }
    if (usr == NULL) {
        new->nxt = pltk->buddy;
        pltk->buddy = new;
    }
    else {
        xfree(new);
    }
}


static void PltkMsgUserList(pltk_msg *msg, pltk_con *pltk, time_t start)
{
    char *elem, *end, *cls, *tkn, *tend;
    unsigned long gid;
    unsigned long uid;
    pltk_chat_usr *new;

    elem = msg->payload;
    end = msg->payload + msg->length;
    while (elem < end) {
        cls = strchr(elem, 0xC8);
        if (cls == NULL)
            break;
        *cls = '\0';
        tkn = strstr(elem, PTLK_USER_DATA_GID);
        if (tkn != NULL) {
            tend = strstr(tkn, "\n");
            if (tend != NULL) {
                tend[0] = '\0';
                gid = atol(tkn + PTLK_USER_DATA_GID_L);
                tend[0] = '\n';
            }
        }
        tkn = strstr(elem, PTLK_USER_DATA_UID);
        if (tkn != NULL) {
            tend = strstr(tkn, "\n");
            if (tend != NULL) {
                tend[0] = '\0';
                uid = atol(tkn + PTLK_USER_DATA_UID_L);
                tend[0] = '\n';
            }
        }
        tkn = strstr(elem, PTLK_USER_DATA_NICK);
        if (tkn != NULL) {
            tend = strstr(tkn, "\n");
            if (tend != NULL) {
                tend[0] = '\0';
            }
        }
        new = xmalloc(sizeof(pltk_chat_usr));
        if (new != NULL) {
            new->uid = uid;
            strncpy(new->nick, tkn + PTLK_USER_DATA_NICK_L, PTLK_USER_DIM);
            PltkAddUser(new, pltk, gid, start);
        }
            
        elem = cls + 1;
    }
}

static void PltkBuddyList(pltk_msg *msg, pltk_con *pltk, time_t start)
{
    char *elem, *end, *cls, *tkn, *tend;
    unsigned long uid;
    pltk_chat_usr *new;

    elem = msg->payload;
    end = msg->payload + msg->length;
    while (elem < end) {
        cls = strchr(elem, 0xC8);
        if (cls == NULL)
            break;
        *cls = '\0';
        tkn = strstr(elem, PTLK_USER_DATA_UID);
        if (tkn != NULL) {
            tend = strstr(tkn, "\n");
            if (tend != NULL) {
                tend[0] = '\0';
                uid = atol(tkn + PTLK_USER_DATA_UID_L);
                tend[0] = '\n';
            }
        }
        tkn = strstr(elem, PTLK_USER_DATA_NICK);
        if (tkn != NULL) {
            tend = strstr(tkn, "\n");
            if (tend != NULL) {
                tend[0] = '\0';
            }
        }
        new = xmalloc(sizeof(pltk_chat_usr));
        if (new != NULL) {
            new->uid = uid;
            strncpy(new->nick, tkn + PTLK_USER_DATA_NICK_L, PTLK_USER_DIM);
            PltkBuddyUser(new, pltk, start);
        }
            
        elem = cls + 1;
    }
}


static int PltkMsgRoom(unsigned long gid, const char *name, pltk_con *pltk, time_t start, unsigned long serial)
{
    pltk_chat *room;
    time_t t;
    struct tm tmm;
    pei_component *cmpn;
    
    /* find the room */
    for (room=pltk->chat; room != NULL; room=room->nxt) {
        if (room->gid == gid) {
            break;
        }
    }
    if (room == NULL) {
        /* new */
        room = xmalloc(sizeof(pltk_chat));
        if (room == NULL) {
            LogPrintf(LV_ERROR, "Memory");
            return -1;
        }
        t = time(NULL);
        memset(room, 0, sizeof(pltk_chat));
        room->gid = gid;
        room->userl = NULL;
        room->num_userl = 0;
        room->start_time = start;
        sprintf(room->chat_msg, "%s/%s/room_%s_%lld_%i_%p.txt", ProtTmpDir(), PLTK_TMP_DIR, name, (long long)t, ++incr_room, name);
        room->msg_fp = fopen(room->chat_msg, "w");
        if (room->msg_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            LogPrintf(LV_ERROR, "Unable to open file %s", room->chat_msg);
            xfree(room);
            return -1;
        }
        sprintf(room->users, "%s/%s/users_%s_%lld_%i_%p.txt", ProtTmpDir(), PLTK_TMP_DIR, name, (long long)t, ++incr_room, name);
        room->users_fp = fopen(room->users, "w");
        if (room->users_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            fclose(room->msg_fp);
            LogPrintf(LV_ERROR, "Unable to open file %s", room->users);
            xfree(room);
            return -1;
        }
        sprintf(room->nick, "%s/%s/nick_%s_%lld_%i_%p.txt", ProtTmpDir(), PLTK_TMP_DIR, name, (long long)t, ++incr_room, name);
        room->nick_fp = fopen(room->nick, "w");
        if (room->nick_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            fclose(room->msg_fp);
            fclose(room->users_fp);
            LogPrintf(LV_ERROR, "Unable to open file %s", room->nick);
            xfree(room);
            return -1;
        }
    
        strcpy(room->channel, name);
        room->nxt = pltk->chat;
        pltk->chat = room;
         /* nick name */
        gmtime_r((time_t *)&(start), &tmm);
        fprintf(room->nick_fp, "[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, pltk->nick);
        
        /* pei */
        PeiNew(&(room->cpei), paltalk_id);
        PeiCapTime(room->cpei, start);
        PeiMarker(room->cpei, serial);
        PeiStackFlow(room->cpei, FlowStack(pltk->flow_id));
        PeiSetReturn(room->cpei, TRUE);
        /* pei components */
        PeiNewComponent(&cmpn, pei_room_id);
        PeiCompCapTime(cmpn, start);
        PeiCompAddFile(cmpn, room->channel, room->chat_msg, 0);
        PeiAddComponent(room->cpei, cmpn);
        
        PeiNewComponent(&cmpn, pei_room_users_id);
        PeiCompCapTime(cmpn, start);
        PeiCompAddFile(cmpn, "users.txt", room->users, 0);
        PeiAddComponent(room->cpei, cmpn);
        
        PeiNewComponent(&cmpn, pei_room_nick_id);
        PeiCompCapTime(cmpn, start);
        PeiCompAddFile(cmpn, "nick.txt", room->nick, 0);
        PeiAddComponent(room->cpei, cmpn);
        
        PeiIns(room->cpei);
    }

    return 0;
}


static int PltkRoomMsgIn(pltk_room_msg_in *msg_in, pltk_con *pltk, time_t start, unsigned long serial)
{
    pltk_chat *room;
    struct tm tmm;
    const char *smsg, *nick;
    pltk_chat_usr *usr;

    /* find the room */
    for (room=pltk->chat; room != NULL; room=room->nxt) {
        if (room->gid == msg_in->gid) {
            break;
        }
    }
    if (room == NULL) {
        if (PltkMsgRoom(msg_in->gid, "", pltk, start, serial) == -1)
            return -1;
    }
    if (room->msg_fp == NULL)
        return -1;
    /* find user nick name */
    nick = "Unknow";
    for (usr=room->userl; usr != NULL; usr=usr->nxt) {
        if (usr->uid == msg_in->uid) {
            nick = usr->nick;
            break;
        }
    }
    
    smsg = PaltalkTagDel(msg_in->message);
    room->end_time = start;
    gmtime_r(&(start), &tmm);
    fprintf(room->msg_fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nick);
    fwrite(smsg, 1, strlen(smsg), room->msg_fp);
    fwrite("\n", 1, 1, room->msg_fp);
    
    return 0;
}


static int PltkImMsg(pltk_im_msg *msg_in, pltk_con *pltk, time_t start, unsigned long serial, bool in)
{
    pltk_private *private;
    struct tm tmm;
    const char *smsg, *nick;
    pltk_chat_usr *usr;
    pltk_chat *chat;
    time_t t;
    char priv_chat[PTLK_USER_DIM*2];
    pei_component *cmpn;

    /* find private chat */
    for (private=pltk->private; private!=NULL; private=private->nxt) {
        if (private->uid == msg_in->uid)
            break;
    }

    if (private == NULL) {
        /* find user nick name from buddy */
        nick = NULL;
        for (usr=pltk->buddy; usr!=NULL; usr=usr->nxt) {
            if (usr->uid == msg_in->uid) {
                nick = usr->nick;
                break;
            }
        }
        /* fing the user nick from the chat room users */
        if (nick == NULL) {
            for (chat=pltk->chat; chat!=NULL && nick == NULL; chat=chat->nxt) {
                for (usr=chat->userl; usr!=NULL; usr=usr->nxt) {
                    if (usr->uid == msg_in->uid) {
                        nick = usr->nick;
                        break;
                    }
                }
            }
        }
        if (nick == NULL)
            nick = "Unknow";
        /* create pei */
        private = xmalloc(sizeof(pltk_private));
        if (private == NULL) {
            LogPrintf(LV_ERROR, "Memory");
            return -1;
        }
        t = time(NULL);
        memset(private, 0, sizeof(pltk_private));
        private->uid = msg_in->uid;
        strcpy(private->nick, nick);
        private->start_time = start;
        sprintf(private->priv_msg, "%s/%s/private_%s_%lld_%i_%p.txt", ProtTmpDir(), PLTK_TMP_DIR, nick, (long long)t, ++incr_room, nick);
        private->msg_fp = fopen(private->priv_msg, "w");
        if (private->msg_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            LogPrintf(LV_ERROR, "Unable to open file %s", private->priv_msg);
            xfree(private);
            return -1;
        }
        sprintf(private->users, "%s/%s/users_%s_%lld_%i_%p.txt", ProtTmpDir(), PLTK_TMP_DIR, nick, (long long)t, ++incr_room, nick);
        private->users_fp = fopen(private->users, "w");
        if (private->users_fp == NULL) {
            /* we are having an error on opening the file, log it and free resources */
            fclose(private->msg_fp);
            LogPrintf(LV_ERROR, "Unable to open file %s", private->users);
            xfree(private);
            return -1;
        }
        
        /* insert new private chat in the list */
        private->nxt = pltk->private;
        pltk->private = private;
        sprintf(priv_chat, "Private chat: %s - %s", pltk->nick, nick);
        /* pei */
        PeiNew(&(private->cpei), paltalk_id);
        PeiCapTime(private->cpei, start);
        PeiMarker(private->cpei, serial);
        PeiStackFlow(private->cpei, FlowStack(pltk->flow_id));
        PeiSetReturn(private->cpei, TRUE);
        /* pei components */
        PeiNewComponent(&cmpn, pei_room_id);
        PeiCompCapTime(cmpn, start);
        PeiCompAddFile(cmpn, priv_chat, private->priv_msg, 0);
        PeiAddComponent(private->cpei, cmpn);
        
        PeiNewComponent(&cmpn, pei_room_users_id);
        PeiCompCapTime(cmpn, start);
        PeiCompAddFile(cmpn, "users.txt", private->users, 0);
        PeiAddComponent(private->cpei, cmpn);
        
        PeiIns(private->cpei);
    }
    
    smsg = PaltalkTagDel(msg_in->message);
    private->end_time = start;
    gmtime_r(&(start), &tmm);
    if (in)
        fprintf(private->msg_fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, private->nick);
    else
        fprintf(private->msg_fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, pltk->nick);
    fwrite(smsg, 1, strlen(smsg), private->msg_fp);
    fwrite("\n", 1, 1, private->msg_fp);
    
    return 0;
}


static int PltkRoomMsgOut(unsigned long gid, const char *message, pltk_con *pltk, time_t start, unsigned long serial)
{
    pltk_chat *room;
    struct tm tmm;
    const char *smsg;

    /* find the room */
    for (room=pltk->chat; room != NULL; room=room->nxt) {
        if (room->gid == gid) {
            break;
        }
    }
    if (room == NULL) {
        if (PltkMsgRoom(gid, "", pltk, start, serial) == -1)
            return -1;
    }
    if (room->msg_fp == NULL)
        return -1;
    
    smsg = PaltalkTagDel(message);
    room->end_time = start;
    gmtime_r(&(start), &tmm);
    fprintf(room->msg_fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, pltk->nick);
    fwrite(smsg, 1, strlen(smsg), room->msg_fp);
    fwrite("\n", 1, 1, room->msg_fp);
    
    return 0;
}


static int PltkUeserJoined(pltk_msg *msg, pltk_con *pltk, time_t start)
{
    char *elem, *end, *tkn, *tend;
    unsigned long gid;
    unsigned long uid;
    pltk_chat_usr *new;

    elem = msg->payload;
    end = msg->payload + msg->length;

    tkn = strstr(elem, PTLK_USER_DATA_GID);
    if (tkn != NULL) {
        tend = strstr(tkn, "\n");
        if (tend != NULL) {
            tend[0] = '\0';
            gid = atol(tkn + PTLK_USER_DATA_GID_L);
            tend[0] = '\n';
        }
    }
    tkn = strstr(elem, PTLK_USER_DATA_UID);
    if (tkn != NULL) {
        tend = strstr(tkn, "\n");
        if (tend != NULL) {
            tend[0] = '\0';
            uid = atol(tkn + PTLK_USER_DATA_UID_L);
            tend[0] = '\n';
        }
    }
    tkn = strstr(elem, PTLK_USER_DATA_NICK);
    if (tkn != NULL) {
        tend = strstr(tkn, "\n");
        if (tend != NULL) {
            tend[0] = '\0';
        }
    }
    new = xmalloc(sizeof(pltk_chat_usr));
    if (new != NULL) {
        new->uid = uid;
        strncpy(new->nick, tkn + PTLK_USER_DATA_NICK_L, PTLK_USER_DIM);
        PltkAddUser(new, pltk, gid, start);
    }
    
    return 0;
}


static void PltkConFree(pltk_con *pltk)
{
    pltk_chat_usr *usr, *nuser;
    pltk_chat *chat;
    pltk_private *private;
    pei_component *cmp;
    char dur[PTLK_USER_DIM];
    
    for (private=pltk->private; private!=NULL; private=private->nxt) {
        fclose(private->msg_fp);
        fclose(private->users_fp);
        cmp = PeiCompSearch(private->cpei, pei_room_id);
        if (cmp != NULL) {
            PeiCompCapEndTime(cmp, private->end_time);
            PeiCompUpdated(cmp);
        }
        cmp = PeiCompSearch(private->cpei, pei_room_users_id);
        if (cmp != NULL) {
            PeiCompCapEndTime(cmp, private->end_time);
            PeiCompUpdated(cmp);
        }
        PeiNewComponent(&cmp, pei_room_duration_id);
        PeiCompCapTime(cmp, private->start_time);
        PeiCompCapEndTime(cmp, private->end_time);
        sprintf(dur, "%lld", (long long)private->end_time-private->start_time);
        PeiCompAddStingBuff(cmp, dur);
        PeiAddComponent(private->cpei, cmp);
        PeiSetReturn(private->cpei, FALSE);
        PeiIns(private->cpei);
    }
    for (chat=pltk->chat; chat!=NULL; chat=chat->nxt) {
        fclose(chat->msg_fp);
        fclose(chat->users_fp);
        fclose(chat->nick_fp);
        cmp = PeiCompSearch(chat->cpei, pei_room_id);
        if (cmp != NULL) {
            PeiCompCapEndTime(cmp, chat->end_time);
            PeiCompUpdated(cmp);
        }
        cmp = PeiCompSearch(chat->cpei, pei_room_users_id);
        if (cmp != NULL) {
            PeiCompCapEndTime(cmp, chat->end_time);
            PeiCompUpdated(cmp);
        }
        cmp = PeiCompSearch(chat->cpei, pei_room_nick_id);
        if (cmp != NULL) {
            PeiCompCapEndTime(cmp, chat->end_time);
            PeiCompUpdated(cmp);
        }
        PeiNewComponent(&cmp, pei_room_duration_id);
        PeiCompCapTime(cmp, chat->start_time);
        PeiCompCapEndTime(cmp, chat->end_time);
        sprintf(dur, "%lld", (long long)chat->end_time-chat->start_time);
        PeiCompAddStingBuff(cmp, dur);
        PeiAddComponent(chat->cpei, cmp);
        PeiSetReturn(chat->cpei, FALSE);
        PeiIns(chat->cpei);

        /* free users */
        usr = chat->userl;
        while (usr != NULL) {
            nuser = usr->nxt;
            xfree(usr);
            usr = nuser;
        }
    }
    
    /* free buddy users */
    usr = pltk->buddy;
    while (usr != NULL) {
        nuser = usr->nxt;
        xfree(usr);
        usr = nuser;
    }
}


static int PltkMsgDec(pltk_msg_info *msg, pltk_con *pltk)
{
    pltk_msg *pmsg;
    pltk_room_msg_in *msg_in;
    pltk_im_msg *im_msg;
    char *tmp;
    unsigned long gid;
    
    pmsg = msg->msg;
    if (msg->client) {
        switch (pmsg->type) {
        case PACKET_ROOM_MESSAGE_OUT:
            LogPrintf(LV_DEBUG, "c PACKET_ROOM_MESSAGE_OUT");
            gid = PACKET_GET_LONG(pmsg->payload, 0);
            PltkRoomMsgOut(gid, pmsg->payload+4, pltk, msg->start_cap, msg->serial);
            break;
            
        case PACKET_USER_DATA:
            LogPrintf(LV_DEBUG, "c PACKET_USER_DATA");
            PltkMsgPrint(pmsg);
            break;
            
        case PACKET_ROOM_JOIN:
            LogPrintf(LV_DEBUG, "c PACKET_ROOM_JOIN");
            PltkMsgPrint(pmsg);
            break;

        case PACKET_LOGIN:
            LogPrintf(LV_DEBUG, "c PACKET_LOGIN");
            PltkMsgPrint(pmsg);
            break;

        case PACKET_VERSIONS:
            LogPrintf(LV_DEBUG, "c PACKET_VERSION");
            PltkMsgPrint(pmsg);
            break;

        case PACKET_VERSION_INFO:
            LogPrintf(LV_DEBUG, "c PACKET_VERSION_INFO");
            PltkMsgPrint(pmsg);
            break;
            
        case PACKET_IM_OUT:
            LogPrintf(LV_DEBUG, "c PACKET_IM_OUT");
            im_msg = (pltk_im_msg *)pmsg->payload;
            PltkImMsgConvert(im_msg);
            PltkImMsg(im_msg, pltk, msg->start_cap, msg->serial, FALSE);
            break;

        case PACKET_ROOM_CLOSE:
            LogPrintf(LV_DEBUG, "c PACKET_CLOSE");
            PltkMsgPrint(pmsg);
            break;

        case -162:
            LogPrintf(LV_DEBUG, "-162");
            PltkMsgPrint(pmsg);
            break;

        default:
            LogPrintf(LV_DEBUG, "cType: %i (0x%x)", pmsg->type, (unsigned short)pmsg->type);
            PltkMsgPrint(pmsg);
            break;
        }
    }
    else {
        switch (pmsg->type) {
        case PACKET_ROOM_MESSAGE_IN:
            LogPrintf(LV_DEBUG, "PACKET_ROOM_MESSAGE_IN");
            msg_in = (pltk_room_msg_in *)pmsg->payload;
            PltkRoomMsgInConvert(msg_in);
            PltkRoomMsgIn(msg_in, pltk, msg->start_cap, msg->serial);
            break;

        case PACKET_ROOM_JOINED:
            LogPrintf(LV_DEBUG, "PACKET_ROOM_JOINED");
            gid = PACKET_GET_LONG(pmsg->payload, 0);
            tmp = strchr(pmsg->payload + 23, '\n');
            if (tmp != NULL)
                *tmp = '\0';
            PltkMsgRoom(gid, pmsg->payload + 23, pltk, msg->start_cap, msg->serial);
            break;
            
        case PACKET_ROOM_USER_JOINED:
            LogPrintf(LV_DEBUG, "PACKET_ROOM_USER_JOINED");
            PltkUeserJoined(pmsg, pltk, msg->start_cap);
            break;

        case PACKET_USER_DATA:
            PltkMsgUserData(pmsg, pltk);
            break;

        case PACKET_BUDDY_LIST:
            LogPrintf(LV_DEBUG, "PACKET_BUDDY_LIST");
            PltkBuddyList(pmsg, pltk, msg->start_cap);
            break;

        case PACKET_ROOM_USERLIST:
            LogPrintf(LV_DEBUG, "PACKET_ROOM_USERLIST");
            PltkMsgUserList(pmsg, pltk, msg->start_cap);
            break;

        case PACKET_ROOM_LIST:
            LogPrintf(LV_DEBUG, "PACKET_ROOM_LIST");
            PltkMsgPrint(pmsg);
            break;

        case PACKET_ROOM_MEDIA_SERVER:
            LogPrintf(LV_DEBUG, "PACKET_ROOM_MEDIA_SERVER");
            PltkMsgPrint(pmsg);
            /*
            printf("gid: %ld\n", PACKET_GET_LONG(pmsg->payload, 0));
            printf("ip: %s\n", inet_ntoa(*((struct in_addr *)(pmsg->payload+4))));
            printf("port: %d\n", ntohs(*(short *)(pmsg->payload+14)));
            */
            break;

        case PACKET_ROOM_TOPIC:
            LogPrintf(LV_DEBUG, "PACKET_ROOM_TOPIC");
            msg_in = (pltk_room_msg_in *)pmsg->payload;
            PltkRoomMsgInConvert(msg_in);
            /*
            printf("uid:%ld\n", msg_in->uid);
            printf("gid:%ld\n", msg_in->gid);
            printf("msg:%s\n", msg_in->message);
            */
            PltkRoomMsgIn(msg_in, pltk, msg->start_cap, msg->serial);
            break;

        case PACKET_IM_IN:
            LogPrintf(LV_DEBUG, "PACKET_IM_IN");
            im_msg = (pltk_im_msg *)pmsg->payload;
            PltkImMsgConvert(im_msg);
            PltkImMsg(im_msg, pltk, msg->start_cap, msg->serial, TRUE);
            break;
            
        default:
            LogPrintf(LV_DEBUG, "sType: %i (0x%x)", pmsg->type, (unsigned short)pmsg->type);
            PltkMsgPrint(pmsg);
            break;
        }
    }
    return 0;
}


static packet *PltkDissector(int flow_id)
{
    const pstack_f *tcp, *ip;
    packet *pkt;
    pltk_msg_info *pltk_data, *lst;
    pltk_priv *priv;
    ftval port_src, port_dst, ip_dst;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    pltk_con pltk;

    /* init */
    pltk_data = lst = NULL;
    priv = NULL;
    
    /* statup */
    LogPrintf(LV_DEBUG, "Paltalk id: %d", flow_id);
    priv = DMemMalloc(sizeof(pltk_priv));
    memset(priv, 0, sizeof(pltk_priv));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, tcp_port_src_id, &port_src);
    ProtGetAttr(tcp, tcp_port_dst_id, &port_dst);
    priv->port = port_src.uint16;
    priv->dir = PLTK_CLT_DIR_NONE;
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
    priv->clost = FALSE;
    priv->slost = FALSE;
    
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);

    PltkConInit(&pltk);
    pltk.flow_id = flow_id;

    pltk_data = PltkMsg(flow_id, &lst, priv);
    while (pltk_data != NULL) {
        /* decode message */
        PltkMsgDec(pltk_data, &pltk);
        PltkMsgInfoFree(&pltk_data, TRUE, TRUE);
        pltk_data = PltkMsg(flow_id, &lst, priv);
    }
    
    /* raw paltalk file */
    pkt = FlowGetPkt(flow_id);
    while (pkt != NULL) {
#warning "to complete"
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    /* free */
    PltkMsgInfoFree(&lst, TRUE, TRUE);
    PltkConFree(&pltk);
    DMemFree(priv);
    
    LogPrintf(LV_DEBUG, "Paltalk... bye bye  fid:%d", flow_id);
    
    return NULL;
}


static bool PltkVerifyCheck(int flow_id, bool check)
{
    packet *pkt;
    pltk_msg *msg;
    unsigned short len;
    ftval lost;
    
    pkt = NULL;
    do {
        if (pkt) {
            PktFree(pkt);
        }
        pkt = FlowGetPktCp(flow_id);
        if (pkt != NULL) {
            ProtGetAttr(pkt->stk, tcp_lost_id, &lost);
            if (lost.uint8 == TRUE) {
                return FALSE;
            }
        }
    } while (pkt != NULL && pkt->len == 0);
    
    if (pkt != NULL) {
        if (pkt->len > PTLK_HEADER_SIZE) {
            msg = (pltk_msg *)pkt->data;
            PltkMsgConvert(msg);
            if (msg->type == PACKET_HELLO) {
                if (msg->length + PTLK_HEADER_SIZE > pkt->len)
                    len = pkt->len - PTLK_HEADER_SIZE;
                else
                    len = msg->length;
                if (strncasecmp(msg->payload, PTLK_SERVER_HELLO, len) == 0)
                    return TRUE;
            }
        }
        PktFree(pkt);
    }

    return FALSE;
}


static bool PltkCheck(int flow_id)
{
    return PltkVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));
    
    /* protocol name */
    ProtName("PalTalk Instant Messaging", "paltalk");

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = PltkCheck;
    hdep.pktlim = PTLK_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "room";
    peic.desc = "room comunications messages";
    ProtPeiComponent(&peic);
    peic.abbrev = "users";
    peic.desc = "room users";
    ProtPeiComponent(&peic);
    peic.abbrev = "nick";
    peic.desc = "room nick names";
    ProtPeiComponent(&peic);
    peic.abbrev = "duration";
    peic.desc = "room duration";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, PltkDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char dirn[256];

    /* part of file name */
    incr = 0;
    incr_room = 0;

    /* protocols and attributes */
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    tcp_id = ProtId("tcp");
    tcp_port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    tcp_port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    tcp_lost_id = ProtAttrId(tcp_id, "tcp.lost");
    tcp_clnt_id = ProtAttrId(tcp_id, "tcp.clnt");
    paltalk_id = ProtId("paltalk");
    
    /* pei id */
    pei_room_id = ProtPeiComptId(paltalk_id, "room");
    pei_room_users_id = ProtPeiComptId(paltalk_id, "users");
    pei_room_nick_id= ProtPeiComptId(paltalk_id, "nick");
    pei_room_duration_id = ProtPeiComptId(paltalk_id, "duration");

    /* irc tmp directory */
    sprintf(dirn, "%s/%s", ProtTmpDir(), PLTK_TMP_DIR);
    mkdir(dirn, 0x01FF);
    
    return 0;
}
