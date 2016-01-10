/* analyse.c
 * Paltalk Express aggregator
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <ctype.h>

#include "proto.h"
#include "log.h"
#include "analyse.h"
#include "dmemory.h"
#include "pei.h"
#include "log.h"
#include "genfun.h"

/* mutex and pthread manager */
static pthread_attr_t attr;
static pei_msg * volatile list;
static volatile unsigned long pcount;
static volatile bool mend;
static pthread_mutex_t pei_mux;
static pthread_mutex_t end_mux;
static pthread_cond_t cond;
static pt_chat *chats;

/* pei */
static int prot_id;
static int pei_url_id;
static int pei_client_id;
static int pei_host_id;
static int pei_req_header_id;
static int pei_req_body_id;
static int pei_res_header_id;
static int pei_res_body_id;
static int pei_user_id;
static int pei_chat_id;
static int pei_duration_id;

static char *PaltalkExpTagDel(char *str)
{
    char *start, *end;
#if 0
    char *color, *c, *b;
#endif
    unsigned char *ascii;
    bool new;

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
#if 0 /* we can use the color value to identify the users */
            color = strstr(start, "color=");
            if (color != NULL && color < end) {
                color += 7;
                strcpy(start, color);
                end = strchr(str, '>');
                end++;
                c = strchr(start, '"');
                b = strchr(start, '\'');
                if (c != NULL && c < end)
                    strcpy(c, end);
                else if (b != NULL && b < end)
                    strcpy(b, end);
            }
            else
#endif
                strcpy(start, end);
        }
        else {
            break;
        }
    } while (1);

    return str;
}


struct pltk_msg {
    short type;
    unsigned short version;
    unsigned short length;
    char payload[1];    /* null teminated! */
};


static void PltkMsgPrint(char *msg, int len)
{
    int i;
    for (i=0; i!=len; i++) {
        printf("0x%x", msg[i]);
    }
}


static void *PaltalkExpMain(void *arg)
{
    pei_component *cmpn;
    char *url, *rqh, *rsh, *rqb, *rsb;
    pei *ppei;
    time_t t, tw;
    pei_msg *msg;
    struct timespec req;
    char *bufferc, *buffers, *start, *end, *start_chr;
    char *client, *server, *cookie, *header;
    FILE *fp;
    size_t len;
    pt_chat *nxtc;
    struct tm tmm;
    struct pltk_msg *pio;

    bufferc = DMemMalloc(PLTEX_BUFFER_SIZE);
    buffers = DMemMalloc(PLTEX_BUFFER_SIZE);
    header = DMemMalloc(PLTEX_BUFFER_SIZE);
    fp = NULL;
    while (1) {
        tw = PLTEX_WAIT_TIME;
        if (list != NULL) {
            t = time(NULL);
            pthread_mutex_lock(&pei_mux);
            if (list->t + PLTEX_WAIT_TIME < t || mend) {
                ppei = list->pei;
                msg = list;
                list = list->nxt;
                pcount--;
                pthread_mutex_unlock(&pei_mux);
                DMemFree(msg);
                cmpn = ppei->components;
                while (cmpn != NULL) {
                    if (cmpn->eid == pei_url_id) {
                        url = cmpn->strbuf;
                    }
                    else if (cmpn->eid == pei_req_header_id) {
                        rqh = cmpn->file_path;
                    }
                    else if (cmpn->eid == pei_req_body_id) {
                        rqb = cmpn->file_path;
                    }
                    else if (cmpn->eid == pei_res_header_id) {
                        rsh = cmpn->file_path;
                    }
                    else if (cmpn->eid == pei_res_body_id) {
                        rsb = cmpn->file_path;
                    }
                    
                    cmpn = cmpn->next;
                }
                
                /* message extraction */
                client = server = NULL;
                if (rqb != NULL)
                    fp = fopen(rqb, "r");
                if (fp != NULL) {
                    len = fread(bufferc, 1, PLTEX_BUFFER_SIZE-1, fp);
                    if (len > 0) {
                        bufferc[len] = '\0';
                        start_chr = bufferc;
                        do {
                            start_chr = memchr(start_chr, '<', len - (start_chr - bufferc));
                            if (start_chr != NULL) {
                                start = strstr(start_chr, PLTEX_STR_START);
                                if (start != NULL) {
                                    end = (char *)memrchr(start, '>', len - (start - bufferc));
                                    end[1] = '\0';
                                    client = PaltalkExpTagDel(start);
                                    break;
                                }
                                start_chr++;
                            }
                        } while (start_chr != NULL);
                    }
                    fclose(fp);
                    fp = NULL;
                }
                if (rsb != NULL)
                    fp = fopen(rsb, "r");
                if (fp != NULL) {
                    len = fread(buffers, 1, PLTEX_BUFFER_SIZE-1, fp);
                    if (len > 0) {
                        buffers[len] = '\0';
                        pio = (struct pltk_msg *)buffers;
                        PltkMsgPrint(buffers, len);
                        printf("\n");
                        start_chr = buffers;
                        do {
                            start_chr = memchr(start_chr, '<', len - (start_chr - buffers));
                            if (start_chr != NULL) {
                                start = strstr(start_chr, PLTEX_STR_START);
                                if (start != NULL) {
                                    end = (char *)memrchr(start_chr, '>', len - (start_chr - buffers));
                                    end[1] = '\0';
                                    server = PaltalkExpTagDel(start);
                                    break;
                                }
                                start_chr++;
                            }
                        } while (start_chr != NULL);
                    }
                    fclose(fp);
                    fp = NULL;
                }
                if (client != NULL || server != NULL) {
                    /* find ID */
                    if (rqh != NULL)
                        fp = fopen(rqh, "r");
                    if (fp != NULL) {
                        len = fread(header, 1, PLTEX_BUFFER_SIZE-1, fp);
                        cookie = strcasestr(header, "Cookie:");
                        if (cookie != NULL) {
                            end = strchr(cookie, '\n');
                            if (end != NULL) {
                                end[0] = '\0';
                                cookie = strcasestr(cookie, "username=");
                                if (cookie != NULL) {
                                    cookie += 9; /* username= */
                                    end = strchr(cookie, ';');
                                    if (end != NULL) {
                                        end[0] = '\0';
                                    }
                                }
                                nxtc = chats;
                                while (nxtc != NULL) {
                                    if (strcmp(nxtc->id, cookie) == 0) {
                                        break;
                                    }
                                    nxtc = nxtc->nxt;
                                }
                                if (nxtc == NULL) {
                                    nxtc = DMemMalloc(sizeof(pt_chat));
                                    strcpy(nxtc->id, cookie);
                                    sprintf(nxtc->chat, "%s/%s/pltk_exp_%lld_%p.txt", ProtTmpDir(), PLTEX_TMP_DIR, (long long)t, nxtc);
                                    nxtc->fp = fopen(nxtc->chat, "w");
                                    nxtc->nxt = chats;
                                    nxtc->first = ppei->time_cap;
                                    chats = nxtc;
                                    /* new pei */
                                    PeiNew(&nxtc->ppei, prot_id);
                                    PeiSetReturn(nxtc->ppei, TRUE);
                                    PeiCapTime(nxtc->ppei, ppei->time_cap);
                                    PeiMarker(nxtc->ppei, ppei->serial);
                                    PeiStackFlow(nxtc->ppei, ppei->stack);
                                    /* user */
                                    PeiNewComponent(&cmpn, pei_user_id);
                                    PeiCompCapTime(cmpn, ppei->time_cap);
                                    PeiCompAddStingBuff(cmpn, nxtc->id);
                                    PeiAddComponent(nxtc->ppei, cmpn);
                                    /* chat component */
                                    PeiNewComponent(&cmpn, pei_chat_id);
                                    PeiCompCapTime(cmpn, ppei->time_cap);
                                    PeiCompAddFile(cmpn, "paltalk_express_chat.txt", nxtc->chat, 0);
                                    PeiAddComponent(nxtc->ppei, cmpn);
                                    PeiIns(nxtc->ppei);
                                }
                                else {
                                    PeiAddStkGrp(nxtc->ppei, ppei->stack);
                                }
                                if (nxtc->fp != NULL) {
                                    nxtc->last = ppei->time_cap;
                                    gmtime_r(&(ppei->time_cap), &tmm);
                                    if (client != NULL) {
                                        fprintf(nxtc->fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, nxtc->id);
                                        fwrite(client, 1, strlen(client), nxtc->fp);
                                        fwrite("\n", 1, 1, nxtc->fp);
                                    }
                                    if (server != NULL) {
                                        fprintf(nxtc->fp, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, "User and Nick unknown");
                                        fwrite(server, 1, strlen(server), nxtc->fp);
                                        fwrite("\n", 1, 1, nxtc->fp);
                                    }
                                }
                            }
                        }
                    }
                }

                if (rqh != NULL)
                    remove(rqh);
                if (rqb != NULL)
                    remove(rqb);
                if (rsh != NULL)
                    remove(rsh);
                if (rsb != NULL)
                    remove(rsb);
                    
                PeiFree(ppei);
            }
            else
                pthread_mutex_unlock(&pei_mux);
            
            if (list != NULL) {
                if (list->t + PLTEX_WAIT_TIME < t)
                    tw = 0;
                else
                    tw = t - (list->t + PLTEX_WAIT_TIME);
            }
            else
                tw = PLTEX_WAIT_TIME;
        }
        
        /* check end */
        if (mend == TRUE) {
            if (list == NULL)
                break;
        }
        else {
            /* sleep */
            req.tv_sec = tw;
            req.tv_nsec = 50000000;
            nanosleep(&req, NULL);
        }
    }

    /* close all files */
    nxtc = chats;
    while (nxtc != NULL) {
        if (nxtc->fp != NULL) {
            fclose(nxtc->fp);
            nxtc->fp = NULL;
        }
        /* complete and update pei */
        /* add duration */
        sprintf(bufferc, "%lld", (long long)(nxtc->last - nxtc->first));
        PeiNewComponent(&cmpn, pei_duration_id);
        PeiCompCapTime(cmpn, nxtc->first);
        PeiCompAddStingBuff(cmpn, bufferc);
        PeiAddComponent(nxtc->ppei, cmpn);
        /* update components */
        cmpn = PeiCompSearch(nxtc->ppei, pei_chat_id);
        PeiCompAddFile(cmpn, "paltalk_express_chat.txt", nxtc->chat, 0);
        PeiCompCapEndTime(cmpn, nxtc->last);
        PeiCompUpdated(cmpn);
        PeiSetReturn(nxtc->ppei, FALSE);
        PeiIns(nxtc->ppei);

        chats = nxtc;
        nxtc = nxtc->nxt;
        DMemFree(chats);
    }
    
    pthread_mutex_lock(&end_mux);
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&end_mux);
    
    /* free memory */
    DMemFree(bufferc);
    DMemFree(buffers);
    DMemFree(header);

    return NULL;
}


int AnalyseInit(void)
{
    pthread_t pid;
    int ret;
    char wm_dir[256];
    
    prot_id = ProtId("paltalk_exp");

    if (prot_id != -1) {
        /* pei id */
        pei_url_id = ProtPeiComptId(prot_id, "url");
        pei_client_id = ProtPeiComptId(prot_id, "client");
        pei_host_id = ProtPeiComptId(prot_id, "host");
        pei_req_header_id = ProtPeiComptId(prot_id, "req.header");
        pei_req_body_id = ProtPeiComptId(prot_id, "req.body");
        pei_res_header_id = ProtPeiComptId(prot_id, "res.header");
        pei_res_body_id = ProtPeiComptId(prot_id, "res.body");
        /* added */
        pei_user_id = ProtPeiComptId(prot_id, "user");
        pei_chat_id = ProtPeiComptId(prot_id, "chat");
        pei_duration_id = ProtPeiComptId(prot_id, "duration");
    
    }
    list = NULL;
    mend = FALSE;
    pcount = 0;
    chats = NULL;
    
    /* tmp directory */
    sprintf(wm_dir, "%s/%s", ProtTmpDir(), PLTEX_TMP_DIR);
    mkdir(wm_dir, 0x01FF);

    /* mutex */
    pthread_mutex_init(&pei_mux, NULL);
    pthread_mutex_init(&end_mux, NULL);
    pthread_cond_init(&cond, NULL);
    
    /* start main thread */
    pthread_attr_init(&attr);
    ret = pthread_create(&pid, &attr, PaltalkExpMain, NULL);
    if (ret == 0) {
        pthread_detach(pid);
    }
    else {
        LogPrintf(LV_FATAL, "We can not start the job");
        exit(-1);
    }
    
    return 0;
}


int AnalysePei(pei *ppei)
{
    pei_msg *new, *pre, *msg;

    if (ppei == NULL)
        return 0;

    if (ppei->ret == TRUE) {
        ProtStackFrmDisp(ppei->stack, TRUE);
        LogPrintf(LV_WARNING, "Pei with return!");
    }
    new = DMemMalloc(sizeof(pei_msg));
    new->t = time(NULL);
    new->pei = ppei;
    new->nxt = NULL;
    pthread_mutex_lock(&pei_mux);
    if (list == NULL) {
        list = new;
    }
    else {
        msg = list;
        pre = NULL;
        while (msg != NULL && msg->pei->serial < ppei->serial) {
            pre = msg;
            msg = msg->nxt;
        }
        if (msg != NULL) {
            new->nxt = msg;
            if (pre != NULL)
                pre->nxt = new;
            else
                list = new;
        }
        else
            pre->nxt = new;
    }
    pcount++;
    pthread_mutex_unlock(&pei_mux);

    return 0;
}


int AnalyseEnd(void)
{
    pthread_mutex_lock(&end_mux);
    mend = TRUE;
    pthread_cond_wait(&cond, &end_mux);
    pthread_mutex_unlock(&end_mux);
    
    return 0;
}

