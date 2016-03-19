/* analyse.c
 * analyse stack and time to realise pei
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2011-2014 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#define _GNU_SOURCE
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <json-c/json.h>
#include <json-c/json_object_private.h>

#include "log.h"
#include "analyse.h"
#include "proto.h"
#include "dmemory.h"
#include "pei.h"
#include "fileformat.h"
#include "genfun.h"


static volatile wymsg_chat * volatile wymsg_list;
static volatile int wymsg_dim;
static char *msg_raw;

/* http id */
static int http_id;
static int http_encoding_id;
/* webymsg */
static int prot_id;
static int pei_url_id;
static int pei_client_id;
static int pei_host_id;
static int pei_req_header_id;
static int pei_req_body_id;
static int pei_res_header_id;
static int pei_res_body_id;
static int pei_wymsg_user_id;
static int pei_wymsg_friend_id;
static int pei_wymsg_chat_id;
static int pei_wymsg_duration_id;


static int WebYMsgExtend(void)
{
    wymsg_chat *new;
    int i;

    /* in this point the mutex is in lock */
    new = xrealloc((void *)wymsg_list, sizeof(wymsg_chat)*(wymsg_dim + WYMSG_ADD_CHAT));
    if (new != NULL) {
        for (i=0; i!=WYMSG_ADD_CHAT; i++) {
            memset(&(new[wymsg_dim+i]), 0, sizeof(wymsg_chat));
        }
        wymsg_list = new;
        wymsg_dim += WYMSG_ADD_CHAT;
        return 0;
    }
    
    return -1;
}


static void WebYMsgRQ(char *strq)
{
    int i = 0;
    
    if (strq == NULL)
        return;

    while (strq[i] != '\0') {
        if (strq[i] == '"') {
            strq[i] = ' ';
        }
        i++;
    }
}


static int WebYMsgRcv(wymsg_chat_msg *nmsg, const char *url)
{
    char *name, *end, *rec;
    int len;
    
    if (nmsg->to != NULL) {
        return 0;
    }
    name = strstr(url, "message/yahoo/");
    if (name != NULL) {
        name += 14;
        end = strchr(name, '?');
        if (end != NULL) {
            len = end - name;
            rec = calloc(1, len + 3);
            if (rec != NULL) {
                rec[0] = ' ';  
                strncpy(rec+1, name, len);
                rec[len+1] = ' ';  
                rec[len+2] = '\0';
                nmsg->to = rec;
                LogPrintf(LV_DEBUG, "St: %s", nmsg->to);
            }
        }
    }
    
    return 0;
}


static wymsg_chat_msg *WebYMsgMsgSent(char *file, size_t size)
{
    FILE *fp;
    const char *from, *msg;
    int msg_len;
    wymsg_chat_msg *ret;
    struct json_object *json_msg, *jm_txt, *jm_from;
    
    if (size > WYMSG_MSG_MAX_SIZE)
        return NULL;
    
    memset(msg_raw, 0, WYMSG_MSG_MAX_SIZE);
    fp = fopen(file, "r");
    if (fp == NULL)
        return NULL;
    size = fread(msg_raw, 1, WYMSG_MSG_MAX_SIZE, fp);
    fclose(fp);
    if (size == -1)
        return NULL;
    msg_raw[size] = '\0';

    /* new msg ?*/
    json_msg = json_tokener_parse(msg_raw);
    if (!json_object_object_get_ex(json_msg, "message", &jm_txt)) {
        json_object_put(json_msg);
        return NULL;
    }
    if (!json_object_object_get_ex(json_msg, "sendAs", &jm_from)) {
        json_object_put(json_msg);
        return NULL;
    }
    
    /* from */
    from = json_object_to_json_string(jm_from);
    LogPrintf(LV_DEBUG, "Sf: %s", from);
    
    /* message */
    msg = json_object_to_json_string(jm_txt);
    
    /* compose end data */
    ret = xcalloc(1, sizeof(wymsg_chat_msg));
    if (ret == NULL) {
        json_object_put(json_msg);
        return NULL;
    }
    ret->from = xcalloc(1, strlen(from)+1);
    strcpy(ret->from, from);
    WebYMsgRQ(ret->from);
    ret->to = NULL;
    msg_len = strlen(msg);
    ret->msg = xcalloc(1, msg_len+1);
    strcpy(ret->msg, msg);
    LogPrintf(LV_DEBUG, "%s", msg);
    ret->size = msg_len;
    json_object_put(json_msg);
    
    return ret;
}

    
static wymsg_chat_msg *WebYMsgMsg(char *file, size_t size)
{
    FILE *fp;
    const char *to, *from, *msg;
    int msg_len;
    wymsg_chat_msg *ret;
    struct json_object *json_msg, *jresp, *jarr, *jmsg, *jm_txt, *jm_to, *jm_from, *timstmp;
    
    if (size > WYMSG_MSG_MAX_SIZE)
        return NULL;
    
    memset(msg_raw, 0, WYMSG_MSG_MAX_SIZE);
    fp = fopen(file, "r");
    if (fp == NULL)
        return NULL;
    size = fread(msg_raw, 1, WYMSG_MSG_MAX_SIZE, fp);
    fclose(fp);
    if (size == -1)
        return NULL;
    msg_raw[size] = '\0';

    /* new msg ?*/
    json_msg = json_tokener_parse(msg_raw);
    if (json_object_object_get_ex(json_msg, "responses", &jresp)) {
        json_object_put(json_msg);
        return NULL;
    }
    
    jarr = json_object_array_get_idx(jresp, 0);
    json_object_object_get_ex(jarr, "message", &jmsg);
    if (json_object_object_get_ex(jmsg, "msg", &jm_txt)) {
        json_object_put(json_msg);
        return NULL;
    }
    
    /* to */
    json_object_object_get_ex(jmsg, "receiver", &jm_to);
    to = json_object_to_json_string(jm_to);
    LogPrintf(LV_DEBUG, "Rt: %s", to);
    
    /* from */
    json_object_object_get_ex(jmsg, "sender", &jm_from);
    from = json_object_to_json_string(jm_from);
    LogPrintf(LV_DEBUG, "Rf: %s", from);
    
    /* message */
    msg = json_object_to_json_string(jm_txt);
    json_object_object_get_ex(jmsg, "timeStamp", &timstmp);
    LogPrintf(LV_DEBUG, "%s %s", json_object_to_json_string(timstmp), msg);
    
    /* compose end data */
    ret = xcalloc(1, sizeof(wymsg_chat_msg));
    if (ret == NULL) {
        json_object_put(json_msg);
        return NULL;
    }
    ret->from = xcalloc(1, strlen(from)+1);
    strcpy(ret->from, from);
    WebYMsgRQ(ret->from);
    ret->to = xcalloc(1, strlen(to)+1);
    strcpy(ret->to, to);
    WebYMsgRQ(ret->to);
    msg_len = strlen(msg);
    ret->msg = xcalloc(1, msg_len+1);
    strcpy(ret->msg, msg);
    ret->size = msg_len;
    json_object_put(json_msg);
    
    return ret;
}


static pei *WebYMsgIns(wymsg_chat_msg *msg, const pei *mpei)
{
    int i, j, k, ins;
    FILE *fp;
    struct tm tmm;
    pei *new;
    pei_component *cmpn;

    new = NULL;
    ins = -1;
    for (i=0; i!=wymsg_dim; i++) {
        if (wymsg_list[i].user != NULL) {
            if ((strcmp(wymsg_list[i].user, msg->from) == 0 &&
                 strcmp(wymsg_list[i].friend, msg->to) == 0   ) ||
                (strcmp(wymsg_list[i].user, msg->to) == 0 &&
                 strcmp(wymsg_list[i].friend, msg->from) == 0)) {
                ins = i;
                break;
            }
        }
        else if (ins == -1) {
            ins = i;
        }
    }
    if (i == wymsg_dim) {
        /* new chat */
        if (ins == -1) {
            ins = wymsg_dim;
            if (WebYMsgExtend() != 0) {
                LogPrintf(LV_ERROR, "No memory");
                return NULL;
            }
        }
        /* set up chat data */
        wymsg_list[ins].user = xmalloc(strlen(msg->from)+1);
        if (wymsg_list[ins].user == NULL) {
            LogPrintf(LV_ERROR, "Memory off");
            return NULL;
        }
        strcpy(wymsg_list[ins].user, msg->from);
        wymsg_list[ins].friend = xmalloc(strlen(msg->to)+1);
        if (wymsg_list[ins].friend == NULL) {
            xfree(wymsg_list[ins].user);
            wymsg_list[ins].user = NULL;
            LogPrintf(LV_ERROR, "Memory off");
            return NULL;
        }
        strcpy(wymsg_list[ins].friend, msg->to);
        wymsg_list[ins].file = xmalloc(WYMSG_STR_DIM);
        if (wymsg_list[ins].file == NULL) {
            xfree(wymsg_list[ins].user);
            wymsg_list[ins].user = NULL;
            xfree(wymsg_list[ins].friend);
            wymsg_list[ins].friend = NULL;
            LogPrintf(LV_ERROR, "Memory off");
            return NULL;
        }
        wymsg_list[ins].ind = 0;
        for (i=0; i!=WYMSG_MSG_QUEUE; i++) {
            wymsg_list[ins].msg[i] = NULL;
        }
        wymsg_list[ins].ppei = NULL;
        sprintf(wymsg_list[ins].file, "%s/webymsg_chat_%p_%p_%lld.txt", ProtTmpDir(), wymsg_list[ins].user, wymsg_list[ins].friend, (long long)time(NULL));
        fp = fopen(wymsg_list[ins].file, "a");
        if (fp != NULL) {
            fprintf(fp, "\n");
            fclose(fp);
        }
        wymsg_list[ins].first = msg->mtime;
        /* create a PEI */
        PeiNew(&new, prot_id);
        wymsg_list[ins].ppei = new;
        PeiSetReturn(new, TRUE);
        PeiCapTime(new, mpei->time_cap);
        PeiMarker(new, mpei->serial);
        PeiStackFlow(new, mpei->stack);
        /* user */
        PeiNewComponent(&cmpn, pei_wymsg_user_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddStingBuff(cmpn, wymsg_list[ins].user);
        PeiAddComponent(new, cmpn);
        /* friend */
        PeiNewComponent(&cmpn, pei_wymsg_friend_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddStingBuff(cmpn, wymsg_list[ins].friend);
        PeiAddComponent(new, cmpn);
        /* chat component */
        PeiNewComponent(&cmpn, pei_wymsg_chat_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddFile(cmpn, "webymsg_chat.txt", wymsg_list[ins].file, 0);
        PeiAddComponent(new, cmpn);
        /* insert */
        PeiIns(new);
    }
    
    /* insert message in the chat queue/file */
    i = wymsg_list[ins].ind;
    if (wymsg_list[ins].msg[i] != NULL) {
        /* write message in to the file */
        fp = fopen(wymsg_list[ins].file, "a");
        if (fp != NULL) {
            gmtime_r((time_t *)&(wymsg_list[ins].msg[i]->mtime), &tmm);
            fprintf(fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, wymsg_list[ins].msg[i]->from);
            fwrite(wymsg_list[ins].msg[i]->msg, 1, wymsg_list[ins].msg[i]->size, fp);
            fclose(fp);
        }
        xfree(wymsg_list[ins].msg[i]->from);
        xfree(wymsg_list[ins].msg[i]->msg);
        xfree(wymsg_list[ins].msg[i]);
        wymsg_list[ins].msg[i] = NULL;
        /* update PEI */
        cmpn = PeiCompSearch(wymsg_list[ins].ppei, pei_wymsg_chat_id);
        PeiCompUpdated(cmpn);
        PeiIns(wymsg_list[ins].ppei);
    }
    /* search message time position */
    k = i;
    j = (i + WYMSG_MSG_QUEUE - 1)%WYMSG_MSG_QUEUE;
    do {
        if (wymsg_list[ins].msg[j] == NULL)
            break;
        if (msg->mtime >= wymsg_list[ins].msg[j]->mtime)
            break;
        wymsg_list[ins].msg[k] = wymsg_list[ins].msg[j];
        wymsg_list[ins].msg[j] = NULL;
        k = j;
        j = (j + WYMSG_MSG_QUEUE - 1)%WYMSG_MSG_QUEUE;
    } while (j != i);
    wymsg_list[ins].msg[k] = msg;
    /* add stack */
    PeiAddStkGrp(wymsg_list[ins].ppei, mpei->stack);
    wymsg_list[ins].ind++;
    wymsg_list[ins].ind = wymsg_list[ins].ind % WYMSG_MSG_QUEUE;
    if (wymsg_list[ins].last < msg->mtime)
        wymsg_list[ins].last = msg->mtime;
    wymsg_list[ins].store = time(NULL);

    return NULL;
}


static int WebYMsgEnd(void)
{
    int i, j;
    FILE *fp;
    struct tm tmm;
    pei_component *cmpn;
    char duration[WYMSG_STR_DIM];

    for (i=0; i!=wymsg_dim; i++) {
        if (wymsg_list[i].user != NULL) {
            j = wymsg_list[i].ind;
            fp = fopen(wymsg_list[i].file, "a");
            /* first message */
            if (wymsg_list[i].msg[j] == NULL) {
                j = 0;
            }
            while (wymsg_list[i].msg[j] != NULL) {
                /* write message in to the file */
                if (fp != NULL) {
                    gmtime_r((time_t *)&(wymsg_list[i].msg[j]->mtime), &tmm);
                    fprintf(fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, wymsg_list[i].msg[j]->from);
                    fwrite(wymsg_list[i].msg[j]->msg, 1, wymsg_list[i].msg[j]->size, fp);
                }
                xfree(wymsg_list[i].msg[j]->from);
                xfree(wymsg_list[i].msg[j]->msg);
                xfree(wymsg_list[i].msg[j]);
                wymsg_list[i].msg[j] = NULL;
                j = (j + 1) % WYMSG_MSG_QUEUE;
            }
            if (fp != NULL)
                fclose(fp);
            xfree(wymsg_list[i].user);
            xfree(wymsg_list[i].friend);
            wymsg_list[i].user = NULL;
            wymsg_list[i].friend = NULL;
            if (wymsg_list[i].ppei != NULL) {
                /* duration */
                sprintf(duration, "%lld", (long long int)(wymsg_list[i].last - wymsg_list[i].first));
                PeiNewComponent(&cmpn, pei_wymsg_duration_id);
                PeiCompCapTime(cmpn, wymsg_list[i].ppei->time_cap);
                PeiCompAddStingBuff(cmpn, duration);
                PeiAddComponent(wymsg_list[i].ppei, cmpn);
                /* update components */
                cmpn = PeiCompSearch(wymsg_list[i].ppei, pei_wymsg_chat_id);
                PeiCompAddFile(cmpn, "webymsg_chat.txt", wymsg_list[i].file, 0);
                PeiCompCapEndTime(cmpn, wymsg_list[i].last);
                PeiCompUpdated(cmpn);
                PeiSetReturn(wymsg_list[i].ppei, FALSE); /* destroy */
                PeiIns(wymsg_list[i].ppei);
                wymsg_list[i].ppei = NULL;
            }
        }
    }
    xfree((void *)wymsg_list);
    wymsg_dim = 0;

    return 0;
}


static void WebYMsgMsgTimeout(int sig)
{
    time_t now;
    int i, j;
    FILE *fp;
    struct tm tmm;
    pei_component *cmpn;
    
    now = time(NULL);
    
    for (i=0; i!=wymsg_dim; i++) {
        if (wymsg_list[i].user != NULL) {
            if (now - wymsg_list[i].store < WYMSG_MSG_TO)
                continue;
                
            j = wymsg_list[i].ind;
            fp = fopen(wymsg_list[i].file, "a");
            /* first message */
            if (wymsg_list[i].msg[j] == NULL) {
                j = 0;
            }
            while (wymsg_list[i].msg[j] != NULL) {
                /* write message in to the file */
                if (fp != NULL) {
                    gmtime_r((time_t *)&(wymsg_list[i].msg[j]->mtime), &tmm);
                    fprintf(fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, wymsg_list[i].msg[j]->from);
                    fwrite(wymsg_list[i].msg[j]->msg, 1, wymsg_list[i].msg[j]->size, fp);
                }
                xfree(wymsg_list[i].msg[j]->from);
                xfree(wymsg_list[i].msg[j]->to);
                xfree(wymsg_list[i].msg[j]->msg);
                xfree(wymsg_list[i].msg[j]);
                wymsg_list[i].msg[j] = NULL;
                j = (j + 1) % WYMSG_MSG_QUEUE;
            }
            if (fp != NULL)
                fclose(fp);
            /* update PEI */
            cmpn = PeiCompSearch(wymsg_list[i].ppei, pei_wymsg_chat_id);
            PeiCompUpdated(cmpn);
            PeiIns(wymsg_list[i].ppei);
        }
    }
}


int AnalyseInit(void)
{
    wymsg_list = NULL;
    wymsg_dim = 0;
    msg_raw = xmalloc(WYMSG_MSG_MAX_SIZE);
    if (msg_raw == NULL)
        return -1;
    
    WebYMsgExtend();

    http_id = ProtId("http");
    if (http_id != -1) {
        http_encoding_id = ProtAttrId(http_id, "http.content_encoding");
    }
      
    prot_id = ProtId("webymsg");
    if (prot_id != -1) {
        pei_url_id = ProtPeiComptId(prot_id, "url");
        pei_client_id = ProtPeiComptId(prot_id, "client");
        pei_host_id = ProtPeiComptId(prot_id, "host");
        pei_req_header_id = ProtPeiComptId(prot_id, "req.header");
        pei_req_body_id = ProtPeiComptId(prot_id, "req.body");
        pei_res_header_id = ProtPeiComptId(prot_id, "res.header");
        pei_res_body_id = ProtPeiComptId(prot_id, "res.body");
        /* components added */
        pei_wymsg_user_id = ProtPeiComptId(prot_id, "user");
        pei_wymsg_friend_id = ProtPeiComptId(prot_id, "friend");
        pei_wymsg_chat_id = ProtPeiComptId(prot_id, "chat");
        pei_wymsg_duration_id = ProtPeiComptId(prot_id, "duration");
    }

    signal(SIGALRM, WebYMsgMsgTimeout);

    return 0;
}


int AnalysePei(pei *ppei)
{
    pei_component *cmpn;
    char *rqb, *rsb, *url;
    wymsg_chat_msg *nmsg;
    size_t lenq, lens;
    time_t tend;
    
    if (ppei == NULL)
        return 0;
    
    alarm(0);

    if (ppei->ret == TRUE) {
        ProtStackFrmDisp(ppei->stack, TRUE);
        LogPrintfPei(LV_WARNING, ppei, "Pei with return!");
    }
    rqb = rsb = NULL;

    if (prot_id != ppei->prot_id) {
        static long cnt = 0;
        
        printf("-- %li %d\n", cnt++, ppei->prot_id);
        PeiFree(ppei);
        exit(-1);
        return 0;
    }
    
    /* identify the service type */
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
            lenq = cmpn->file_size;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
            lens = cmpn->file_size;
            tend = cmpn->time_cap_end;
        }
        else if (cmpn->eid == pei_req_header_id || cmpn->eid == pei_res_header_id) {
            remove(cmpn->file_path);
        }
        cmpn = cmpn->next;
    }
    
    /* identify the message */
    if (rqb != NULL) {
        nmsg = WebYMsgMsgSent(rqb, lenq);
        if (nmsg != NULL) {
            nmsg->mtime = ppei->time_cap;
            WebYMsgRcv(nmsg, url);
            LogPrintf(LV_DEBUG, "S %lu", ppei->time_cap);
            /* message insert */
            WebYMsgIns(nmsg, ppei);
        }
        remove(rqb);
    }
    if (rsb != NULL) {
        nmsg = WebYMsgMsg(rsb, lens);
        if (nmsg != NULL) {
            LogPrintf(LV_DEBUG, "%s", url);
            nmsg->mtime = tend;
            LogPrintf(LV_DEBUG, "R %lu", tend);
            /* message insert */
            WebYMsgIns(nmsg, ppei);
        }
        remove(rsb);
    }
    PeiFree(ppei);

    WebYMsgMsgTimeout(-1);
    alarm(WYMSG_MSG_TO);

    return 0;
}


int AnalyseEnd(void)
{
    WebYMsgEnd();
    
    return 0;
}

