/*
 * msn.c
 * msn packet dissector by Daniele Franchetto <daniele.franchetto@gmail.com> 
 *            overviewed Gianluca Costa  <g.costa@iserm.com>
 *
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>
#include <time.h>

#include "etypes.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "msn.h"
#include "pei.h"
#include "genfun.h"


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
static int msn_id;

/* pei id  */
static int pei_from_id;
static int pei_to_id;
static int pei_chat_id;
static int pei_duration_id; /* room time */

#define MSN_TMP_DIR    "msn"


static volatile unsigned int incr;


static int FindToken(char *row, char *tokens[])
{
    unsigned int tok_num = 0;
    char *str, *tok, *saveptr = NULL;
    
    for (str = row; tok_num != MAXTOKEN; str = NULL) {
        tok = strtok_r(str, " ", &saveptr);
        if (tok == NULL)
            break;
        tokens[tok_num] = tok;
        tok_num++;
    }
    
    return tok_num;
}


static int ReadCycle(char **readbuf, int *head, int queue, char *wanted)   /* unload buffer until the row with the wanted word */
{
    int found = -1;
    
    while ((((queue - *head + ROWBUFDIM) % ROWBUFDIM) > 3)) {
        if ((strstr(readbuf[*head], wanted)) != NULL) {
            found = *head;
            break;
        }
        else
            *head = (*head + 1) % ROWBUFDIM;  /* reading buffer is structured as a circular queue */
    }
    
    return found;
}


static int FindDim(char *buf[], int row)
{
    int dim = 0, i = 0;
    char *sdim;

    row = (row + ROWBUFDIM - 2) % ROWBUFDIM;
    while ((((buf[row][i]) != '\n') || ((buf[row][i + 1]) != 0))
           && (i < (MAXROWLEN / 2)))
        i++;
    i -= 2;
    while ((isprint(buf[row][i])) && (i > 0))
        i--;
    i++;
    sdim = &buf[row][i];
    i = strlen(sdim);
    if (i) {
        i--;
        while ((!(isdigit(sdim[i])) && (i > 0)))
            i--;
        if ((isdigit(sdim[i])) && (isdigit(sdim[i - 1]))
            && (isdigit(sdim[i - 2]))) {
            dim =
                (sdim[i] - 48) + (sdim[i - 1] - 48) * 10 +
                (sdim[i - 2] - 48) * 100;
            if (isdigit(sdim[i - 3]))
                dim += (sdim[i - 3] - 48) * 1000;
        }
    }
    
    return dim;
}


static int FindSender(char **b, int row, char *name, char *nickname, msn_chat *chat)
{
    int i, j, flag, len;
    char sender[MAXCHAR * 2], nick[MAXCHAR * 2];
    
    i = j = flag = 0;
    row = (row + ROWBUFDIM - 2) % ROWBUFDIM;
    len = strlen(b[row]);
    while (((b[row][i]) != ' ') && (i < len))
        i++;
    while (((b[row][i]) == ' ') && (i < len))
        i++;                    /* first letter of the sender's name*/
    while (((b[row][i]) != ' ') && (i < len)) {
        sender[j] = b[row][i];
        if (b[row][i] == '@')
            flag = 1;           /*in every received message the sender name contain the @ character*/
        i++;
        j++;
    }
    if (flag == 1) {
        sender[j] = '\0';
        sender[j + 1] = '\0';
        j = 0;
        nick[j] = '(';
        i++;
        j++;
        while ((b[row][i]) != ' ')      /* looking for the nickname field*/
        {
            nick[j] = b[row][i];
            i++;
            j++;
        }
        nick[j] = ')';
        nick[j + 1] = '\0';
        strncpy(name, sender, MAXCHAR);
        strncat(name, nick, MAXCHAR);
        strncat(nickname, nick, MAXCHAR);
    }
    else
        strncpy(name, chat->client, MAXCHAR); /* in the case there's no sender' it will be used the client's name */
    
    return flag;
}


static int Message(char **b, int *head, int queue, int n, char *mes)
{
    int i = 0;
    char c;
    n -= strlen(b[((*head + ROWBUFDIM - 1) % ROWBUFDIM)]) + 2;
    do {
        c = strlen(b[*head]);
        n -= c;
        i++;
        *head = (*head + ROWBUFDIM + 1) % ROWBUFDIM;
    } while ((!(isspace(b[*head][0]))) && (*head != queue));
    strncpy(mes, b[((*head + ROWBUFDIM + 1) % ROWBUFDIM)], n + 2);
    mes[n] = '\n';
    mes[n + 1] = '\0';
    return 1;
}


static int Write(FILE * clear, char *name, char *receiver, char *mes, time_t capt)
{
    int i = 0;
    struct tm tmm;

    gmtime_r(&(capt), &tmm);
    fprintf(clear, "\n[%.2i:%.2i:%.2i] %s\n", tmm.tm_hour+XTimeOffest(), tmm.tm_min, tmm.tm_sec, name);
    fwrite(mes, 1, strlen(mes), clear);
    fwrite("\n", 1, 1,clear);

    return i;
}


static int Analize(char *buf[], int *head, int queue, packet * pkt, msn_chat *chat)
{
    int rowinf, dim, usr, text;
    char *sender, *phrase;
    char *nick;
    pei_component *cmpn;
    
    sender = xmalloc(MAXCHAR * 2);
    phrase = xmalloc(MAXROWLEN*10);
    nick  = xmalloc(MAXROWLEN * 2);
    
    nick[0] = '\0';
    phrase[0] = '\0';
    nick[0] = '\0';
    rowinf = ReadCycle(buf, head, queue, "text/plain"); /* the elaboration starts only when there's the whole string inside the buffer */
    if ((rowinf != -1) && (((queue - *head + ROWBUFDIM) % ROWBUFDIM) > 7)) {
        dim = FindDim(buf, rowinf);
        usr = FindSender(buf, rowinf, sender, nick, chat);
        if ((dim > 0) && (usr >= 0)) {
            *head = rowinf;
            text = Message(buf, head, queue, dim, phrase);
            if (text) {
                if (chat->fp == NULL) {
                    chat->fp = fopen(chat->file_name, "w");
                        
                    if (usr && chat->client[0] != '\0')
                        sprintf(chat->name, "%s -> %s", sender, chat->client);
                    else
                        sprintf(chat->name, "%s -> %s", sender, chat->receiver);
                    /* compose pei */
                    PeiNew(&(chat->ppei), msn_id);
                    PeiCapTime(chat->ppei, pkt->cap_sec);
                    PeiMarker(chat->ppei, pkt->serial);
                    PeiStackFlow(chat->ppei, FlowStack(chat->flow_id));
                    PeiSetReturn(chat->ppei, TRUE);
                    /* sender */
                    PeiNewComponent(&cmpn, pei_from_id);
                    PeiCompCapTime(cmpn, pkt->cap_sec);
                    PeiCompCapEndTime(cmpn, pkt->cap_sec);
                    PeiCompAddStingBuff(cmpn, sender);
                    PeiAddComponent(chat->ppei, cmpn);
                    /* receiver */
                    PeiNewComponent(&cmpn, pei_to_id);
                    PeiCompCapTime(cmpn, pkt->cap_sec);
                    PeiCompCapEndTime(cmpn, pkt->cap_sec);
                    if (usr && chat->client[0] != '\0')
                        PeiCompAddStingBuff(cmpn, chat->client);
                    else
                        PeiCompAddStingBuff(cmpn, chat->receiver);
                    PeiAddComponent(chat->ppei, cmpn);
                    /* messagges */
                    PeiNewComponent(&cmpn, pei_chat_id);
                    PeiCompCapTime(cmpn, pkt->cap_sec);
                    PeiCompAddFile(cmpn, chat->name, chat->file_name, 0);
                    PeiAddComponent(chat->ppei, cmpn);
                    /* insert pei */
                    PeiIns(chat->ppei);
                }
                if (usr && chat->client[0] != '\0')
                    Write(chat->fp, sender, chat->client, phrase, pkt->cap_sec);
                else
                    Write(chat->fp, sender, chat->receiver, phrase, pkt->cap_sec);
            }
        }
        else {
            *head = (*head + 1) % ROWBUFDIM;
        }
    }

    xfree(sender);
    xfree(phrase);
    xfree(nick);
    
    return 1;
}


static packet *MsnDissector(int flow_id)
{
    int rowinf, usr, loop_counter, head, queue, i, j;
    char *phrase, *c;
    char *buf[ROWBUFDIM], *token[MAXTOKEN];
    packet *pkt;
    msn_chat *chat;
    pei_component *cmp;
    time_t last_t, first_t;

    for (j = 0; j < ROWBUFDIM; j++) {
        buf[j] = (char *)xmalloc(MAXROWLEN);
        memset(buf[j], '\0', MAXROWLEN);
    }
    head = queue = i = 0;
    phrase = xmalloc(MAXROWLEN);
    memset(phrase, '\0', MAXROWLEN);
    chat = xmalloc(sizeof(msn_chat));
    memset(chat, '\0', sizeof(msn_chat));
    chat->fp = NULL;
    chat->flow_id = flow_id;
    last_t = first_t = 0;
    
    sprintf(chat->file_name, "%s/%s/chat_%i_%lld_%p.txt", ProtTmpDir(), MSN_TMP_DIR, flow_id, (long long)time(NULL), chat);
    pkt = FlowGetPkt(flow_id);
    while (pkt != NULL) {
        if (first_t == 0)
            first_t = pkt->cap_sec;
        last_t = pkt->cap_sec;
        if ((pkt->len > 0)&&(pkt->data != NULL)) {
            for (loop_counter = 0; loop_counter < pkt->len; loop_counter++) {
                buf[queue][i] = pkt->data[loop_counter];
                i++;
                if ((pkt->data[loop_counter - 1] == '\r')
                    && (pkt->data[loop_counter] == '\n')) {
                    buf[queue][i] = '\0';
                    strncpy(phrase, buf[queue], MAXROWLEN);
                    rowinf = FindToken(phrase, token);
                    if ((rowinf > 2) && (!(strcmp(token[0], "USR")))) {
                        if (!strcmp(token[2], "OK")) {
                            strncpy(chat->client, token[3], MAXCHAR);
                            c = strchr(chat->client, ';');
                            if (c != NULL)
                                *c = '\0';
                            if (rowinf > 3) {
                                strcat(chat->client, "(");
                                strncat(chat->client, token[4], MAXCHAR);
                                usr = strlen(chat->client);
                                chat->client[usr - 2] = ')';
                                chat->client[usr - 1] = '\0';
                            }
                        }
                    }
                    else if ((rowinf > 2) && (!(strcmp(token[0], "JOI")))) {
                        strncpy(chat->receiver, token[1], MAXCHAR);
                        c = strchr(chat->receiver, ';');
                        if (c != NULL)
                            *c = '\0';
                        if (rowinf > 2) {
                            strcat(chat->receiver, "(");
                            strncat(chat->receiver, token[2], MAXCHAR);
                            usr = strlen(chat->receiver);
                            chat->receiver[usr] = ')';
                            chat->receiver[usr + 1] = '\0';
                        }
                    }
                    else if ((rowinf > 4) && (!(strcmp(token[0], "IRO")))) {
                        strncpy(chat->receiver, token[4], MAXCHAR);
                        c = strchr(chat->receiver, ';');
                        if (c != NULL)
                            *c = '\0';
                        if (rowinf > 5) {
                            strcat(chat->receiver, "(");
                            strncat(chat->receiver, token[5], MAXCHAR);
                            usr = strlen(chat->receiver);
                            chat->receiver[usr] = ')';
                            chat->receiver[usr + 1] = '\0';
                        }
                    }
                    queue = (queue + 1) % ROWBUFDIM;
                    i = 0;
                    if (((queue - head + ROWBUFDIM) % ROWBUFDIM) > 5) {
                        Analize(buf, &head, queue, pkt, chat);
                    }
                }
                if (i == MAXROWLEN - 4)
                    i = 0;
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    if (chat->fp != NULL) {
        fclose(chat->fp);
        cmp = PeiCompSearch(chat->ppei, pei_chat_id);
        if (cmp != NULL) {
            PeiCompCapEndTime(cmp, last_t);
            PeiCompUpdated(cmp);
        }
        PeiNewComponent(&cmp, pei_duration_id);
        PeiCompCapTime(cmp, first_t);
        PeiCompCapEndTime(cmp, last_t);
        sprintf(phrase, "%lld", (long long)last_t-first_t);
        PeiCompAddStingBuff(cmp, phrase);
        PeiAddComponent(chat->ppei, cmp);
        PeiSetReturn(chat->ppei, FALSE);
        //LogPrintf(LV_DEBUG, "Msn: %s", chat->file_name);
        PeiIns(chat->ppei);
    }

    /* free */
    for (j = 0; j < ROWBUFDIM; j++)
        xfree(buf[j]);
    xfree(phrase);
    xfree(chat);
    
    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name  */
    ProtName("Microsoft Messeger", "msn");

    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_MSN;
    ProtDep(&dep);

    dep.attr = "tcp.srcport";
    ProtDep(&dep);
    
    /* PEI components */
    peic.abbrev = "from";
    peic.desc = "Caller";
    ProtPeiComponent(&peic);
    peic.abbrev = "to";
    peic.desc = "Called";
    ProtPeiComponent(&peic);
    peic.abbrev = "chat";
    peic.desc = "chat messages";
    ProtPeiComponent(&peic);
    peic.abbrev = "duration";
    peic.desc = "room duration";
    ProtPeiComponent(&peic);

    /* dissectors registration */
    ProtDissectors(NULL, MsnDissector, NULL, NULL);
    
    return 0;
}


int DissectInit(void)
{
    char msn_dir[256];

    /* part of file name  */
    incr = 0;
    
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
    msn_id = ProtId("msn");
    
    /* pei id  */
    pei_from_id = ProtPeiComptId(msn_id, "from");
    pei_to_id = ProtPeiComptId(msn_id, "to");
    pei_chat_id = ProtPeiComptId(msn_id, "chat");
    pei_duration_id = ProtPeiComptId(msn_id, "duration");

    /* tmp directory */
    sprintf(msn_dir, "%s/%s", ProtTmpDir(), MSN_TMP_DIR);
    mkdir(msn_dir, 0x01FF);
    
    return 0;
}
