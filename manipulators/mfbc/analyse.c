/* analyse.c
 * analyse stack and time to realise pei
 *
 * $Id:  $
 *
 * Xplico System
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

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>

#include "proto.h"
#include "log.h"
#include "analyse.h"
#include "dmemory.h"
#include "pei.h"
#include "genfun.h"


static volatile fb_chat * volatile fbwc_list;
static volatile int fbwc_dim;
static volatile int pei_ins;
static int pei_rec;

static int fbwc_id;
static int pei_fbwc_user_id;
static int pei_fbwc_friend_id;
static int pei_fbwc_uid_id;
static int pei_fbwc_fid_id;
static int pei_fbwc_from_id;
static int pei_fbwc_to_id;
static int pei_fbwc_time_id;
static int pei_fbwc_chat_id;
static int pei_fbwc_duration_id;


static int FbwcExtend(void)
{
    fb_chat *new;
    int i;

    /* in this point the mutex is in lock */
    new = xrealloc((void *)fbwc_list, sizeof(fb_chat)*(fbwc_dim + FBC_ADD_CHAT));
    if (new != NULL) {
        for (i=0; i!=FBC_ADD_CHAT; i++) {
            memset(&(new[fbwc_dim+i]), 0, sizeof(fb_chat));
        }
        fbwc_list = new;
        fbwc_dim += FBC_ADD_CHAT;
        return 0;
    }
    
    return -1;
}


static pei *FbwcIns(fb_chat_msg *msg, char *cid, char *fid, char *user, char *friend, const pei *mpei)
{
    int i, j, k, ins;
    FILE *fp;
    struct tm tmm;
    pei *new;
    pei_component *cmpn;

    new = NULL;
    ins = -1;
    for (i=0; i!=fbwc_dim; i++) {
        if (fbwc_list[i].cid != NULL) {
            if (strcmp(fbwc_list[i].cid, cid) == 0) {
                if (strcmp(fbwc_list[i].fid, fid) == 0) {
                    ins = i;
                    break;
                }
            }
        }
        else if (ins == -1) {
            ins = i;
        }
    }
    if (i == fbwc_dim) {
        /* new chat */
        if (ins == -1) {
            ins = fbwc_dim;
            if (FbwcExtend() != 0) {
                LogPrintf(LV_ERROR, "No memory");
                return NULL;
            }
        }
        /* set up chat data */
        fbwc_list[ins].cid = xmalloc(strlen(cid)+1);
        if (fbwc_list[ins].cid == NULL) {
            LogPrintf(LV_ERROR, "Memory off");
            return NULL;
        }
        strcpy(fbwc_list[ins].cid, cid);
        fbwc_list[ins].fid = xmalloc(strlen(fid)+1);
        if (fbwc_list[ins].fid == NULL) {
            xfree(fbwc_list[ins].cid);
            fbwc_list[ins].cid = NULL;
            LogPrintf(LV_ERROR, "Memory off");
            return NULL;
        }
        strcpy(fbwc_list[ins].fid, fid);
        fbwc_list[ins].file = xmalloc(FBC_STR_DIM);
        if (fbwc_list[ins].file == NULL) {
            xfree(fbwc_list[ins].cid);
            fbwc_list[ins].cid = NULL;
            xfree(fbwc_list[ins].fid);
            fbwc_list[ins].fid = NULL;
            LogPrintf(LV_ERROR, "Memory off");
            return NULL;
        }
        fbwc_list[ins].ind = 0;
        for (i=0; i!=FBC_MSG_QUEUE; i++) {
            fbwc_list[ins].msg[i] = NULL;
        }
        fbwc_list[ins].ppei = NULL;
        sprintf(fbwc_list[ins].file, "%s/facebook_chat_%s_%s_%lld.txt", ProtTmpDir(), cid, fid, (long long)time(NULL));
        fp = fopen(fbwc_list[ins].file, "a");
        if (fp != NULL) {
            fprintf(fp, "\n");
            fclose(fp);
        }
        fbwc_list[ins].first = msg->mtime;
        /* create a PEI */
        PeiNew(&new, fbwc_id);
        fbwc_list[ins].ppei = new;
        PeiSetReturn(new, TRUE);
        PeiCapTime(new, mpei->time_cap);
        PeiMarker(new, mpei->serial);
        PeiStackFlow(new, mpei->stack);
        /* user */
        PeiNewComponent(&cmpn, pei_fbwc_user_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddStingBuff(cmpn, user);
        PeiAddComponent(new, cmpn);
        /* cid */
        PeiNewComponent(&cmpn, pei_fbwc_uid_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddStingBuff(cmpn, cid);
        PeiAddComponent(new, cmpn);
        /* friend */
        PeiNewComponent(&cmpn, pei_fbwc_friend_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddStingBuff(cmpn, friend);
        PeiAddComponent(new, cmpn);
        /* chat component */
        PeiNewComponent(&cmpn, pei_fbwc_chat_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddFile(cmpn, "facebook_chat.txt", fbwc_list[ins].file, 0);
        PeiAddComponent(new, cmpn);
        /* insert */
        PeiIns(new);
    }
    
    /* insert message in the chat queue/file */
    i = fbwc_list[ins].ind;
    if (fbwc_list[ins].msg[i] != NULL) {
        pei_ins++;
        /* write message in to the file */
        fp = fopen(fbwc_list[ins].file, "a");
        if (fp != NULL) {
            gmtime_r((time_t *)&(fbwc_list[ins].msg[i]->mtime), &tmm);
            fprintf(fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, fbwc_list[ins].msg[i]->from);
            fwrite(fbwc_list[ins].msg[i]->msg, 1, fbwc_list[ins].msg[i]->size, fp);
            fclose(fp);
        }
        xfree(fbwc_list[ins].msg[i]->from);
        xfree(fbwc_list[ins].msg[i]->msg);
        xfree(fbwc_list[ins].msg[i]);
        fbwc_list[ins].msg[i] = NULL;
        /* update PEI */
        cmpn = PeiCompSearch(fbwc_list[ins].ppei, pei_fbwc_chat_id);
        PeiCompUpdated(cmpn);
        PeiIns(fbwc_list[ins].ppei);
    }
    /* search message time position */
    k = i;
    j = (i + FBC_MSG_QUEUE - 1)%FBC_MSG_QUEUE;
    do {
        if (fbwc_list[ins].msg[j] == NULL)
            break;
        if (msg->mtime >= fbwc_list[ins].msg[j]->mtime)
            break;
        fbwc_list[ins].msg[k] = fbwc_list[ins].msg[j];
        fbwc_list[ins].msg[j] = NULL;
        k = j;
        j = (j + FBC_MSG_QUEUE - 1)%FBC_MSG_QUEUE;
    } while (j != i);
    fbwc_list[ins].msg[k] = msg;
    /* add stack */
    PeiAddStkGrp(fbwc_list[ins].ppei, mpei->stack);
    fbwc_list[ins].ind++;
    fbwc_list[ins].ind = fbwc_list[ins].ind % FBC_MSG_QUEUE;
    if (fbwc_list[ins].last < msg->mtime)
        fbwc_list[ins].last = msg->mtime;
    fbwc_list[ins].store = time(NULL);

    return NULL;
}


static int FbwcEnd(void)
{
    int i, j;
    FILE *fp;
    struct tm tmm;
    pei_component *cmpn;
    char duration[FBC_STR_DIM];

    for (i=0; i!=fbwc_dim; i++) {
        if (fbwc_list[i].cid != NULL) {
            j = fbwc_list[i].ind;
            fp = fopen(fbwc_list[i].file, "a");
            /* first message */
            while (fbwc_list[i].msg[j] == NULL) {
                j = (j + 1) % FBC_MSG_QUEUE;
                if (j == fbwc_list[i].ind)
                    break;
            }
            while (fbwc_list[i].msg[j] != NULL) {
                pei_ins++;
                /* write message in to the file */
                if (fp != NULL) {
                    gmtime_r((time_t *)&(fbwc_list[i].msg[j]->mtime), &tmm);
                    fprintf(fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, fbwc_list[i].msg[j]->from);
                    fwrite(fbwc_list[i].msg[j]->msg, 1, fbwc_list[i].msg[j]->size, fp);
                }
                xfree(fbwc_list[i].msg[j]->from);
                xfree(fbwc_list[i].msg[j]->msg);
                xfree(fbwc_list[i].msg[j]);
                fbwc_list[i].msg[j] = NULL;
                j = (j + 1) % FBC_MSG_QUEUE;
            }
            if (fp != NULL)
                fclose(fp);
            xfree(fbwc_list[i].cid);
            xfree(fbwc_list[i].fid);
            fbwc_list[i].cid = NULL;
            fbwc_list[i].fid = NULL;
            if (fbwc_list[i].ppei != NULL) {
                /* duration */
                sprintf(duration, "%lld", (long long)(fbwc_list[i].last - fbwc_list[i].first));
                PeiNewComponent(&cmpn, pei_fbwc_duration_id);
                PeiCompCapTime(cmpn, fbwc_list[i].ppei->time_cap);
                PeiCompAddStingBuff(cmpn, duration);
                PeiAddComponent(fbwc_list[i].ppei, cmpn);
                /* update components */
                cmpn = PeiCompSearch(fbwc_list[i].ppei, pei_fbwc_chat_id);
                PeiCompAddFile(cmpn, "facebook_chat.txt", fbwc_list[i].file, 0);
                PeiCompCapEndTime(cmpn, fbwc_list[i].last);
                PeiCompUpdated(cmpn);
                PeiSetReturn(fbwc_list[i].ppei, FALSE); /* destroy */
                PeiIns(fbwc_list[i].ppei);
                fbwc_list[i].ppei = NULL;
            }
        }
    }
    xfree((void *)fbwc_list);
    fbwc_dim = 0;

    return 0;
}


static void FbwcMsgTimeout(int sig)
{
    time_t now;
    int i, j;
    FILE *fp;
    struct tm tmm;
    pei_component *cmpn;

    now = time(NULL);
    
    for (i=0; i!=fbwc_dim; i++) {
        if (fbwc_list[i].cid != NULL) {
            if (now - fbwc_list[i].store < FBC_MSG_TO)
                continue;
                
            j = fbwc_list[i].ind;
            fp = fopen(fbwc_list[i].file, "a");
            /* first message */
            if (fbwc_list[i].msg[j] == NULL) {
                j = (j + 1) % FBC_MSG_QUEUE;
                if (j == fbwc_list[i].ind)
                    break;
            }
            while (fbwc_list[i].msg[j] != NULL) {
                pei_ins++;
                /* write message in to the file */
                if (fp != NULL) {
                    gmtime_r((time_t *)&(fbwc_list[i].msg[j]->mtime), &tmm);
                    fprintf(fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, fbwc_list[i].msg[j]->from);
                    fwrite(fbwc_list[i].msg[j]->msg, 1, fbwc_list[i].msg[j]->size, fp);
                }
                xfree(fbwc_list[i].msg[j]->from);
                xfree(fbwc_list[i].msg[j]->msg);
                xfree(fbwc_list[i].msg[j]);
                fbwc_list[i].msg[j] = NULL;
                j = (j + 1) % FBC_MSG_QUEUE;
            }
            if (fp != NULL)
                fclose(fp);
            /* update PEI */
            cmpn = PeiCompSearch(fbwc_list[i].ppei, pei_fbwc_chat_id);
            PeiCompUpdated(cmpn);
            PeiIns(fbwc_list[i].ppei);
        }
    }
}


int AnalyseInit(void)
{
    pei_rec = 0;
    pei_ins = 0;
    fbwc_list = NULL;
    fbwc_dim = 0;
    FbwcExtend();
    fbwc_id = ProtId("fbwchat");
    if (fbwc_id != -1) {
        pei_fbwc_user_id = ProtPeiComptId(fbwc_id, "user");
        pei_fbwc_friend_id = ProtPeiComptId(fbwc_id, "friend");
        pei_fbwc_uid_id = ProtPeiComptId(fbwc_id, "uid");
        pei_fbwc_fid_id = ProtPeiComptId(fbwc_id, "fid");
        pei_fbwc_from_id = ProtPeiComptId(fbwc_id, "from");
        pei_fbwc_to_id = ProtPeiComptId(fbwc_id, "to");
        pei_fbwc_time_id = ProtPeiComptId(fbwc_id, "time");
        /* components added */
        pei_fbwc_chat_id = ProtPeiComptId(fbwc_id, "chat");
        pei_fbwc_duration_id = ProtPeiComptId(fbwc_id, "duration");
    }

    signal(SIGALRM, FbwcMsgTimeout);

    return 0;
}


int AnalysePei(pei *ppei)
{
    pei_component *cmpn;
    char *user, *friend, *cid, *fid, *from, *to, *stime, *end;
    fb_chat_msg *msg;
    int size;

    if (ppei == NULL)
        return 0;

    alarm(0);
    
    if (ppei->ret == TRUE) {
        ProtStackFrmDisp(ppei->stack, TRUE);
        LogPrintf(LV_WARNING, "Pei with return!");
    }

    user = friend = cid = fid = from = to = stime = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_fbwc_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_friend_id) {
            friend = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_uid_id) {
            cid = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_fid_id) {
            fid = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_from_id) {
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_to_id) {
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_time_id) {
            stime = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }

    /* create new message */
    if (user != NULL) {
        pei_rec++;
        msg = xmalloc(sizeof(fb_chat_msg));
        if (msg != NULL) {
            stime[strlen(stime)-3] = '\0'; /* convert time of facebook in unix time */
            msg->mtime = (time_t)atoi(stime);
            /* sender */
            if (from != NULL) {
                /* from users to fiend */
                size = strlen(user) + 1;
                msg->from = xmalloc(size);
                memcpy(msg->from, user, size);
            }
            else {
                /* from fiend to user */
                size = strlen(friend) + 1;
                msg->from = xmalloc(size);
                memcpy(msg->from, friend, size);
            }
            end = strchr(msg->from, ' ');
            if (end != NULL) {
                /* only the name */
                *end = '\0';
            }
            /* message */
            if (from != NULL) {
                size = strlen(from) + 1;
                msg->msg = xmalloc(size);
                memcpy(msg->msg, from, size);
            }
            else {
                size = strlen(to) + 1;
                msg->msg = xmalloc(size);
                memcpy(msg->msg, to, size);
            }
            msg->size = size - 1;
            /* message insert */
            FbwcIns(msg, cid, fid, user, friend, ppei);
        }
    }
    PeiFree(ppei);

    FbwcMsgTimeout(-1);
    alarm(FBC_MSG_TO);
    
    return 0;
}


int AnalyseEnd(void)
{
    FbwcEnd();
    LogPrintf(LV_STATUS, "Total FB messages: %i/%i", pei_ins, pei_rec);
    
    return 0;
}

