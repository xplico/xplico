/* fbwchat.c
 * Facebook Chat from web interface
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "pei.h"
#include "http.h"
#include "fbwchat.h"
#include "fileformat.h"

static int prot_id;
static int pei_user_id;
static int pei_friend_id;
static int pei_uid_id;
static int pei_fid_id;
static int pei_from_id;
static int pei_to_id;
static int pei_time_id;


static packet *FbwchatV1(char *message, packet *pkt)
{
    pei *ppei;
    pei_component *cmpn;
    char *cid, *fid, *text, *user, *friend, *mtime, *end, *jolly;
    bool send; 

    ppei = NULL;
    cid = fid = text = user = friend = jolly = end = mtime = NULL;

    /* search client id */
    cid = strstr(message, ",\"c\":\"");
    if (cid != NULL) {
        cid += 8; /* eliminate p_ characters */
        end = strchr(cid, '"');
        *end = '\0';
        /* message search */
        text = strstr(end+1, "msg\":{\"text\"");
        if (text != NULL) {
            text += 14;
            end = strchr(text, '"');
            *end = '\0';
            if (cid == NULL) {
                LogPrintf(LV_ERROR, "No client ID!");
            }
            /* time of message (client time)*/
            mtime = strstr(end+1, "clientTime\":");
            if (mtime != NULL) {
                mtime += 12;
                end = strchr(mtime, ',');
                *end = '\0';
                /* from id */
                jolly = strstr(end+1, "from\":");
                if (jolly != NULL) {
                    jolly += 6;
                    end = strchr(jolly, ',');
                    *end = '\0';
                    send = FALSE;
                    if (strcmp(jolly, cid) == 0) {
                        send = TRUE;
                        /* search to id (fid) */
                        jolly = strstr(end+1, "to\":");
                        if (jolly != NULL) {
                            jolly += 4;
                            end = strchr(jolly, ',');
                            *end = '\0';
                            fid = jolly;
                        }
                    }
                    else {
                        fid = jolly;
                    }
                    /* from name */
                    jolly = strstr(end+1, "from_name\":\"");
                    if (jolly != NULL) {
                        jolly += 12;
                        end = strchr(jolly, '"');
                        *end = '\0';
                        if (send) {
                            user = jolly;
                        }
                        else {
                            friend = jolly;
                        }
                        /* from name */
                        jolly = strstr(end+1, "to_name\":\"");
                        if (jolly != NULL) {
                            jolly += 10;
                            end = strchr(jolly, '"');
                            *end = '\0';
                            if (!send) {
                                user = jolly;
                            }
                            else {
                                friend = jolly;
                            }
                        }
                    }
                }
            }
        }
    }
#ifdef XPL_CHECK_CODE
    if (friend == NULL && text != NULL) {
        LogPrintf(LV_ERROR, "Message without users!");
    }
#endif
    
    /* compose pei */
    if (friend != NULL && user != NULL) {
        PeiNew(&ppei, prot_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, pkt->stk);
        
        /* cid */
        PeiNewComponent(&cmpn, pei_uid_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, cid);
        PeiAddComponent(ppei, cmpn);
        
        /* fid */
        PeiNewComponent(&cmpn, pei_fid_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, fid);
        PeiAddComponent(ppei, cmpn);
        
        /* user */
        PeiNewComponent(&cmpn, pei_user_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, user);
        PeiAddComponent(ppei, cmpn);
        
        /* friend */
        PeiNewComponent(&cmpn, pei_friend_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, friend);
        PeiAddComponent(ppei, cmpn);
        
        /* from/to message*/
        if (send)
            PeiNewComponent(&cmpn, pei_from_id);
        else
            PeiNewComponent(&cmpn, pei_to_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, text);
        PeiAddComponent(ppei, cmpn);
        
        /* time */
        PeiNewComponent(&cmpn, pei_time_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, mtime);
        PeiAddComponent(ppei, cmpn);
        
        /* insert pei */
        PeiIns(ppei);
    }
    else {
        /* if there is only message check */
        PeiNew(&ppei, prot_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, pkt->stk);
        
        /* cid */
        PeiNewComponent(&cmpn, pei_uid_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, cid);
        PeiAddComponent(ppei, cmpn);
        
        /* insert pei */
        PeiIns(ppei);
    }

    return NULL;
}


static packet *FbwchatV2(char *message, char *rq_hdr, packet *pkt)
{
    pei *ppei;
    pei_component *cmpn;
    char *cid, *fid, *text, *user, *friend, *mtime, *end, *jolly;
    bool send;
    FILE *fp;
    char *hdr;
    size_t size;
    

    ppei = NULL;
    cid = fid = text = user = friend = jolly = end = mtime = NULL;
    send = FALSE;
    hdr = NULL;

    /* read the client ID */
    fp = fopen(rq_hdr, "r");
    if (fp != NULL) {
        hdr = xmalloc(FBWC_MAXBUF_SIZE);
        size = fread(hdr, 1, FBWC_MAXBUF_SIZE, fp);
        fclose(fp);
        if (size != -1) {
            hdr[size] = '\0';
            cid = strstr(hdr, "c_user=");
            if (cid != NULL) {
                cid += 7;
                jolly = strstr(cid, ";");
                if (jolly != NULL)
                    *jolly = '\0';
            }
        }
    }

    /* message search */
    text = strstr(message, "msg\":{\"text\"");
    if (text != NULL) {
        text += 14;
        end = strchr(text, '"');
        *end = '\0';
        /* time of message (client time)*/
        mtime = strstr(end+1, "clientTime\":");
        if (mtime != NULL) {
            mtime += 12;
            end = strchr(mtime, ',');
            *end = '\0';
            /* from id */
            jolly = strstr(end+1, "from\":");
            if (jolly != NULL) {
                jolly += 6;
                end = strchr(jolly, ',');
                *end = '\0';
                send = FALSE;
                if (strcmp(jolly, cid) == 0) {
                    send = TRUE;
                    /* search to id (fid) */
                    jolly = strstr(end+1, "to\":");
                    if (jolly != NULL) {
                        jolly += 4;
                        end = strchr(jolly, ',');
                        *end = '\0';
                        fid = jolly;
                    }
                }
                else {
                    fid = jolly;
                }
                /* from name */
                jolly = strstr(end+1, "from_name\":\"");
                if (jolly != NULL) {
                    jolly += 12;
                    end = strchr(jolly, '"');
                    *end = '\0';
                    if (send) {
                        user = jolly;
                    }
                    else {
                        friend = jolly;
                    }
                    /* from name */
                    jolly = strstr(end+1, "to_name\":\"");
                    if (jolly != NULL) {
                        jolly += 10;
                        end = strchr(jolly, '"');
                        *end = '\0';
                        if (!send) {
                            user = jolly;
                        }
                        else {
                            friend = jolly;
                        }
                    }
                }
            }
        }
    }
#ifdef XPL_CHECK_CODE
    if (friend == NULL && text != NULL) {
        LogPrintf(LV_ERROR, "Message without users!");
    }
#endif
    
    /* compose pei */
    if (friend != NULL && user != NULL) {
        PeiNew(&ppei, prot_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, pkt->stk);
        
        /* uid */
        PeiNewComponent(&cmpn, pei_uid_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, cid);
        PeiAddComponent(ppei, cmpn);
        
        /* fid */
        PeiNewComponent(&cmpn, pei_fid_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, fid);
        PeiAddComponent(ppei, cmpn);
        
        /* user */
        PeiNewComponent(&cmpn, pei_user_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, user);
        PeiAddComponent(ppei, cmpn);
        
        /* friend */
        PeiNewComponent(&cmpn, pei_friend_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, friend);
        PeiAddComponent(ppei, cmpn);
        
        /* from/to message*/
        if (send)
            PeiNewComponent(&cmpn, pei_from_id);
        else
            PeiNewComponent(&cmpn, pei_to_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, text);
        PeiAddComponent(ppei, cmpn);
        
        /* time */
        PeiNewComponent(&cmpn, pei_time_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, mtime);
        PeiAddComponent(ppei, cmpn);
        
        /* insert pei */
        PeiIns(ppei);
    }
    else {
        /* if there is only message check */
        PeiNew(&ppei, prot_id);
        PeiCapTime(ppei, pkt->cap_sec);
        PeiMarker(ppei, pkt->serial);
        PeiStackFlow(ppei, pkt->stk);
        
        /* uid */
        PeiNewComponent(&cmpn, pei_uid_id);
        PeiCompCapTime(cmpn, pkt->cap_sec);
        PeiCompAddStingBuff(cmpn, cid);
        PeiAddComponent(ppei, cmpn);
        
        /* insert pei */
        PeiIns(ppei);
    }

    if (hdr != NULL)
        xfree(hdr);

    return NULL;
}


static packet *FbwchatDissector(packet *pkt)
{
    http_msg *msg;
    size_t size;
    char *message, *orig_file;
    FILE *fp;
    char new_path[FBWC_FILE_PATH];
    bool rm;
    packet *ret;

    rm = FALSE;
    orig_file = NULL;
    ret = NULL;

    /* display info */
    msg = (http_msg *)pkt->data;
    
#ifdef XPL_CHECK_CODE
    if (msg->serial == 0) {
        LogPrintf(LV_FATAL, "Fbwchat FbchatDissector serial error");
        exit(-1);
    }
#endif

    /* decode message body */
    size = msg->res_body_size;
    if (size >= FBWC_MAXBUF_SIZE) {
        LogPrintf(LV_WARNING, "Buffer size limited");
        size = FBWC_MAXBUF_SIZE;
    }
    if (msg->content_encoding[1] != NULL) {
        size = size*10;
    }
    message = xmalloc(size+1);
    if (message == NULL) {
        LogPrintf(LV_ERROR, "No memory");
        /* free memory */
        HttpMsgFree(msg);
        PktFree(pkt);
        return NULL;
    }
    orig_file = msg->res_body_file;
    /* encoding */
    if (msg->content_encoding[1] != NULL) {
        /* compressed */
        sprintf(new_path, "%s.dec", msg->res_body_file);
        FFormatUncompress(msg->content_encoding[1], msg->res_body_file, new_path);
        rm = TRUE;
        orig_file = new_path;
    }
    fp = fopen(orig_file, "r");
    if (fp == NULL) {
        if (size != 0)
            LogPrintf(LV_ERROR, "File %s error", orig_file);
        if (rm)
            remove(new_path);
        /* free memory */
        HttpMsgFree(msg);
        PktFree(pkt);
        return NULL;
    }
    size = fread(message, 1, size, fp);
    fclose(fp);
    if (size != -1) {
        message[size] = '\0';
        /* check version */
        if (strstr(message, "{\"t\":\"msg\",\"c\":") != NULL) {
            /* first version */
            ret = FbwchatV1(message, pkt);
        }
        else if (strstr(message, ",\"ms\":[{\"msg\":{\"text\"") != NULL || strstr(message, "},{\"msg\":{\"text\"")) {
            /* second version */
            ret = FbwchatV2(message, msg->req_hdr_file, pkt);
        }
        else {
            /* last version */
            //printf("%s\n", message);
        }
    }
    /* remove tmp file */
    if (rm)
        remove(new_path);
    /* free memory */
    xfree(message);
    HttpMsgFree(msg);
    PktFree(pkt);

    return ret;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Facebook Web Chat", "fbwchat");

    /* http dependence */
    /* dep: http */
    dep.name = "http";
    dep.attr = "http.host";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(FBWC_HOST_NAME_REX)+1);
    strcpy(dep.val.str, FBWC_HOST_NAME_REX);
    ProtDep(&dep);

    /* PEI components */
    peic.abbrev = "user";
    peic.desc = "User";
    ProtPeiComponent(&peic);

    peic.abbrev = "friend";
    peic.desc = "User friend";
    ProtPeiComponent(&peic);

    peic.abbrev = "uid";
    peic.desc = "User ID";
    ProtPeiComponent(&peic);

    peic.abbrev = "fid";
    peic.desc = "Friend ID";
    ProtPeiComponent(&peic);

    peic.abbrev = "from";
    peic.desc = "Message from";
    ProtPeiComponent(&peic);

    peic.abbrev = "to";
    peic.desc = "Message to";
    ProtPeiComponent(&peic);

    peic.abbrev = "time";
    peic.desc = "User time in Unix time expressed in ms";
    ProtPeiComponent(&peic);
    
    /* dissectors registration */
    ProtDissectors(FbwchatDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    prot_id = ProtId("fbwchat");

    /* pei id */
    pei_user_id = ProtPeiComptId(prot_id, "user");
    pei_friend_id = ProtPeiComptId(prot_id, "friend");
    pei_uid_id = ProtPeiComptId(prot_id, "uid");
    pei_fid_id = ProtPeiComptId(prot_id, "fid");
    pei_from_id = ProtPeiComptId(prot_id, "from");
    pei_to_id = ProtPeiComptId(prot_id, "to");
    pei_time_id = ProtPeiComptId(prot_id, "time");

    return 0;
}
