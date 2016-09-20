/* tcp.c
 * TCP dissector
 *
 * $Id: $
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


#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "ipproto.h"
#include "in_cksum.h"
#include "order.h"
#include "log.h"
#include "embedded.h"
#include "configs.h"

#define TCP_ORD_PRINT           0
#if TCP_ORD_PRINT==0
# define printf(arg...)
#endif

static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
#if SNIFFER_EVASION
static int ip_ttl_id;
static int ip_id_id;
#endif
static int ipv6_src_id;
static int ipv6_dst_id;
#if SNIFFER_EVASION
static int ipv6_hlim_id;
#endif
static int prot_id;
static int src_id;
static int dst_id;
static int clnt_id;
static int lost_id;
static int syn_id;


typedef struct _oflow oflow;
struct _oflow {
    bool ipv4;
    ftval ip_mx;
    unsigned short port_mx;
    ftval ip_mn;
    unsigned short port_mn;
};


static void TcpOrdInit(order *ord, pstack_f *stk)
{   
    memset(ord, 0, sizeof(order));
    ord->src_put = TRUE;
    ord->mono = TRUE;
    ord->stk_s = ProtCopyFrame(stk, TRUE);
#if SNIFFER_EVASION
    ord->first = TRUE;
    ord->hl_s_on = FALSE;
#endif
}


static void TcpOrdFree(order *ord)
{
    if (ord->stk_s != NULL)
        ProtDelFrame(ord->stk_s);
    if (ord->stk_d != NULL)
        ProtDelFrame(ord->stk_d);
    if (ord->ack_s != NULL)
        PktFree(ord->ack_s);
    if (ord->ack_d != NULL)
        PktFree(ord->ack_d);
}


static void TcpOrdPrint(order *ord)
{
#if TCP_ORD_PRINT
    struct seq *put;
    unsigned long num;
    unsigned long nser;

    put = ord->src;
    num = 0;
    nser = ord->seq_s;
    printf("Src(%d): %lu\n", ord->src_put, ord->seq_s);
    while (put != NULL) {
        if (nser != 0 && nser != put->seq)
            printf("***->");
        printf("%lu(%lu-%d-%d-%lu)->", put->seq, put->nxt_seq, put->cng, put->ack, put->pkt->len);
        if (put->seq != 0 && put->nxt_seq - put->seq != 1 && put->nxt_seq - put->seq !=  put->pkt->len){
            printf("\n");
            LogPrintf(LV_OOPS, "TCP internal tcp length error pkt:%lu len:%lu", put->nxt_seq - put->seq, put->pkt->len);
            ProtStackFrmDisp(put->pkt->stk, TRUE);
            exit(-1);
        }
        if (put->pkt->len > put->pkt->raw_len && put->pkt->raw != NULL) {
            LogPrintf(LV_OOPS, "TCP data dimension error raw:%lu data:%lu", put->pkt->raw_len, put->pkt->len);
            ProtStackFrmDisp(put->pkt->stk, TRUE);
            exit(-1);
        }
        nser = put->nxt_seq;
        put = put->next;
        num++;
    }
    printf("\n");
    put = ord->dst;
    nser = ord->seq_d;
    printf("Dst: %lu\n", ord->seq_d);
    while (put != NULL) {
        if (nser != 0 && nser != put->seq)
            printf("***->");
        printf("%lu(%lu-%d-%d-%lu)->", put->seq, put->nxt_seq, put->cng, put->ack, put->pkt->len);
        if (put->seq != 0 && put->nxt_seq - put->seq != 1 && put->nxt_seq - put->seq !=  put->pkt->len){
            printf("\n");
            LogPrintf(LV_OOPS, "TCP internal tcp length error");
            ProtStackFrmDisp(put->pkt->stk, TRUE);
            exit(-1);
        }
        if (put->pkt->len > put->pkt->raw_len && put->pkt->raw != NULL) {
            LogPrintf(LV_OOPS, "TCP data dimension error raw:%lu data:%lu", put->pkt->raw_len, put->pkt->len);
            ProtStackFrmDisp(put->pkt->stk, TRUE);
            exit(-1);
        }
        nser = put->nxt_seq;
        put = put->next;
        num++;
    }
    printf("\n");
    if (num != ord->num) {
        LogPrintf(LV_OOPS, "TCP internal counter error");
        exit(-1);
    }
    
#endif
}


static struct seq* TcpSeq(packet *pkt, unsigned long seq, unsigned long nxt_seq)
{
    struct seq *newp;

    newp = DMemMalloc(sizeof(struct seq));
    if (newp == NULL)
        return NULL;

    newp->pkt = pkt;
    newp->seq = seq;
    newp->nxt_seq = nxt_seq;
    newp->next = NULL;
    newp->cng = FALSE;
    newp->ack = FALSE;

    return newp;
}


static unsigned long TcpContSeq(struct seq *lst)
{
    while (lst->next != NULL && lst->nxt_seq == lst->next->seq)
        lst = lst->next;

    return lst->nxt_seq;
}


static int TcpEmpty(int flow_id, order *ord)
{
    struct seq *nxt, *empt;

    LogPrintf(LV_DEBUG, "Empty TCP");
    ord->seq_s = 0;
    ord->seq_d = 0;
    nxt = ord->src;
    ord->src = NULL;
    while (nxt != NULL) {
        empt = nxt;
        nxt = nxt->next;
        PktFree(empt->pkt);
        DMemFree(empt);
    }
    nxt = ord->dst;
    ord->dst = NULL;
    while (nxt != NULL) {
        empt = nxt;
        nxt = nxt->next;
        PktFree(empt->pkt);
        DMemFree(empt);
    }
    ord->num = 0;
    ord->fin_s = 0;
    ord->fin_d = 0;
    ord->last_src = NULL;
    ord->last_dst = NULL;
    if (ord->ack_d != NULL)
        PktFree(ord->ack_d);
    ord->ack_d = NULL;
    if (ord->ack_s != NULL)
        PktFree(ord->ack_s);
    ord->ack_s = NULL;

    return 0;
}


static int TcpPut(int flow_id, order *ord)
{
    struct seq *put;
    bool cont = TRUE;
    
    do {
        if (ord->src_put) {
#if TCP_SOFT_ACK
            if (ord->src != NULL && ord->seq_s == ord->src->seq) 
#else
            if (ord->src != NULL && ord->seq_s == ord->src->seq && ord->src->ack == TRUE) 
#endif
                {
                put = ord->src;
                ord->src = ord->src->next;
                ord->seq_s = put->nxt_seq;
                if (put->cng == TRUE)
                    ord->src_put = FALSE;
                if (ord->ack_s == put->pkt)
                    ord->ack_s = NULL;
                FlowPutPkt(flow_id, put->pkt);
                DMemFree(put);
                ord->num--;
            }
            else
                cont = FALSE;
        }
        else {
#if TCP_SOFT_ACK
            if (ord->dst != NULL && ord->seq_d == ord->dst->seq)
#else
            if (ord->dst != NULL && ord->seq_d == ord->dst->seq && ord->dst->ack == TRUE)
#endif
                {
                put = ord->dst;
                ord->dst = ord->dst->next;
                ord->seq_d = put->nxt_seq;
                if (put->cng == TRUE)
                    ord->src_put = TRUE;
                if (ord->ack_d == put->pkt)
                    ord->ack_d = NULL;
                FlowPutPkt(flow_id, put->pkt);
                DMemFree(put);
                ord->num--;
            }
            else
                cont = FALSE;
        }
    } while (cont == TRUE);

    if (ord->src == NULL)
        ord->last_src = NULL;
    if (ord->dst == NULL)
        ord->last_dst = NULL;

    printf("%s:\n", __FUNCTION__);
    TcpOrdPrint(ord);

    return 0;
}


static int TcpFlush(int flow_id, order *ord, bool mono)
{
    struct seq *put;
    packet *hole;
    ftval val;
    int cnt;

    printf("%s:\n", __FUNCTION__);
    TcpOrdPrint(ord);

    cnt = 0;
    while ((ord->src != NULL || ord->dst != NULL) &&
           (mono == FALSE || (ord->num > TCP_SUBDIS_MONO_PKT_MARG))) {
        cnt++;
        if (ord->src_put) {
            if (ord->src != NULL && ord->seq_s == ord->src->seq) {
                put = ord->src;
                ord->src = ord->src->next;
                ord->seq_s = put->nxt_seq;
                if (put->cng == TRUE)
                    ord->src_put = FALSE;
                if (ord->ack_s == put->pkt)
                    ord->ack_s = NULL;
                FlowPutPkt(flow_id, put->pkt);
                DMemFree(put);
                ord->num--;
            }
            else {
                if (ord->src != NULL) {
                    /* hole */
                    hole = PktNew();
                    hole->stk = ProtCopyFrame(ord->src->pkt->stk, TRUE);
                    val.uint8 = TRUE;
                    ProtInsAttr(hole->stk, lost_id, &val);
                    if (ord->seq_s != 0) {
                        hole->len = ord->src->seq - ord->seq_s;
                    }
                    else {
                        hole->len = 0;
                    }
                    hole->data = NULL;
                    hole->cap_sec = ord->src->pkt->cap_sec;
                    hole->cap_usec = ord->src->pkt->cap_usec;
                    hole->serial = ord->src->pkt->serial;
                    FlowPutPkt(flow_id, hole);
                    ord->seq_s = ord->src->seq;
                }
            }
        }
        else {
            if (ord->dst != NULL && ord->seq_d == ord->dst->seq) {
                put = ord->dst;
                ord->dst = ord->dst->next;
                ord->seq_d = put->nxt_seq;
                if (put->cng == TRUE)
                    ord->src_put = TRUE;
                if (ord->ack_d == put->pkt)
                    ord->ack_d = NULL;
                FlowPutPkt(flow_id, put->pkt);
                DMemFree(put);
                ord->num--;
            }
            else {
                if (ord->dst != NULL) {
                    /* hole */
                    hole = PktNew();
                    hole->stk = ProtCopyFrame(ord->dst->pkt->stk, TRUE);
                    val.uint8 = TRUE;
                    ProtInsAttr(hole->stk, lost_id, &val);
                    if (ord->seq_d != 0) {
                        hole->len = ord->dst->seq - ord->seq_d;
                    }
                    else {
                        hole->len = 0;
                    }
                    hole->data = NULL;
                    hole->cap_sec = ord->dst->pkt->cap_sec;
                    hole->cap_usec = ord->dst->pkt->cap_usec;
                    hole->serial = ord->dst->pkt->serial;
                    FlowPutPkt(flow_id, hole);
                    ord->seq_d = ord->dst->seq;
                }
            }
        }
        if (ord->src_put == TRUE) {
            if (ord->src == NULL)
                ord->src_put = FALSE;
        }
        else if (ord->dst == NULL)
            ord->src_put = TRUE;
    }

    if (mono == TRUE) {
        /* last ack */
        if (ord->ack_s != NULL) {
            FlowPutPkt(flow_id, ord->ack_s);
            ord->ack_s = NULL;
        }
        
        if (ord->ack_d != NULL) {
            FlowPutPkt(flow_id, ord->ack_d);
            ord->ack_d = NULL;
        }
    }

    return 0;
}


static int TcpOrder(int flow_id, order *ord, packet *pkt, unsigned long seq, unsigned long nxt_seq, bool src)
{
    struct seq **queue, *chk, *pre, **last_sq, *last_rv, *newp, *tmp;
    unsigned long nseq, cnt;
    long delta;
    bool same, cng;

    /* select sequence to analize */
    same = FALSE;
    if (src == TRUE) {
        queue = &ord->src;
        chk = ord->src;
        nseq = ord->seq_s;
        last_sq = &ord->last_src;
        last_rv = ord->last_dst;
        if (ord->lins_src)
            same = TRUE;
    }
    else {
        queue = &ord->dst;
        chk = ord->dst;
        nseq = ord->seq_d;
        last_sq = &ord->last_dst;
        last_rv = ord->last_src;
        if (ord->lins_src == FALSE)
            same = TRUE;
    }
    if (nxt_seq <= nseq) {
        /* retrasmition */
        LogPrintf(LV_DEBUG, "Retrasmition 1");
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return 0;
    }

    /* search position */
    pre = chk;
    while (chk != NULL && chk->nxt_seq <= seq) {
        pre = chk;
        chk = chk->next;
    }
    if (chk == NULL) {
        ord->num++;
        if (pre != NULL) {
            pre->next = TcpSeq(pkt, seq, nxt_seq);
            if (same == FALSE && last_rv != NULL)
                last_rv->cng = TRUE;
            ord->lins_src = src;
            *last_sq = pre->next;
        }
        else {
            /* first packet in the queue */
            if (nseq != 0 && nseq > seq) {
                delta = nseq - seq;
                pkt->data += delta;
                pkt->len -= delta;
                seq = nseq;
            }
            newp = TcpSeq(pkt, seq, nxt_seq);
            *queue = newp;
            /* last */
            *last_sq = newp;
            if (same == FALSE && last_rv != NULL) {
                last_rv->cng = TRUE;
            }
            ord->lins_src = src;
            *last_sq = newp;
        }

        return 0;
    }
    if (pre == chk) { // fist packet in queue
        cnt = TcpContSeq(chk);
        if (chk->seq == nseq || chk->seq <= seq) {
            if (cnt >= nxt_seq) {
                /* retrasmition */
                LogPrintf(LV_DEBUG, "Retrasmition 2");
                //ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                
                return 0;
            }

            pre = chk;
            chk = chk->next;
            while (chk != NULL && pre->nxt_seq == chk->seq) {
                pre = chk;
                chk = chk->next;
            }
            ord->num++;
            if (chk == NULL || nxt_seq <= chk->seq) {
                delta = pre->nxt_seq - seq;
                seq = pre->nxt_seq;
                pkt->data += delta;
                pkt->len -= delta;
                newp = TcpSeq(pkt, seq, nxt_seq);
                newp->next = chk;
                pre->next = newp;
                if (chk == NULL) {
                    if (same == FALSE && last_rv != NULL)
                        last_rv->cng = TRUE;
                    ord->lins_src = src;
                    *last_sq = pre->next;
                }
            }
            else {
                cng = FALSE;
                while (chk != NULL && chk->nxt_seq <= nxt_seq) {
                    tmp = chk;
                    if (chk->cng == TRUE)
                        cng = TRUE;
                    chk = chk->next;
                    PktFree(tmp->pkt);
                    DMemFree(tmp);
                    ord->num--;
                }
                delta = pre->nxt_seq -seq;
                seq = pre->nxt_seq;
                pkt->data += delta;
                pkt->len -= delta;
                if (chk != NULL && nxt_seq > chk->seq) {
                    delta = nxt_seq - chk->seq;
                    nxt_seq = chk->seq;
                    pkt->len -= delta;
                }
                newp = TcpSeq(pkt, seq, nxt_seq);
                newp->next = chk;
                pre->next = newp;
            }
        }
        else {
            ord->num++;
            if (seq < nseq) {
                delta = nseq - seq;
                seq = nseq;
                pkt->data += delta;
                pkt->len -= delta;
            }
            if (nxt_seq <= chk->seq) {
                newp = TcpSeq(pkt, seq, nxt_seq);
                newp->next = chk;
                *queue = newp;
            }
            else {
                if (cnt >= nxt_seq) {
                    delta = nxt_seq - chk->seq;
                    pkt->len -= delta;
                    newp = TcpSeq(pkt, seq, nxt_seq-delta);
                    newp->next = pre;
                    *queue = newp;
                }
                else {
                    cng = FALSE;
                    while (chk != NULL && chk->nxt_seq <= nxt_seq) {
                        tmp = chk;
                        if (chk->cng == TRUE)
                            cng = TRUE;
                        chk = chk->next;
                        PktFree(tmp->pkt);
                        DMemFree(tmp);
                        ord->num--;
                    }
                    if (chk == NULL) {
                        newp = TcpSeq(pkt, seq, nxt_seq);
                        newp->cng = cng;
                        *queue = newp;
                        /* last */
                        *last_sq = newp;
                    }
                    else {
                        if (nxt_seq > chk->seq) {
                            delta = nxt_seq - chk->seq;
                            pkt->len -= delta;
                            nxt_seq -= delta;
                        }
                        newp = TcpSeq(pkt, seq, nxt_seq);
                        newp->cng = cng;
                        newp->next = chk;
                        *queue = newp;
                    }
                }
            }
        }
    }
    else {
        cnt = TcpContSeq(chk);
        if (chk->seq == pre->nxt_seq || chk->seq <= seq) {
            if (cnt >= nxt_seq) {
                /* retrasmition */
                LogPrintf(LV_DEBUG, "Retrasmition 3");
                //ProtStackFrmDisp(pkt->stk, TRUE);
                PktFree(pkt);
                
                return 0;
            }
            pre = chk;
            chk = chk->next;
            while (chk != NULL && pre->nxt_seq == chk->seq) {
                pre = chk;
                chk = chk->next;
            }
            ord->num++;
            if (chk == NULL || nxt_seq <= chk->seq) {
                delta = pre->nxt_seq - seq;
                seq = pre->nxt_seq;
                pkt->data += delta;
                pkt->len -= delta;
                newp = TcpSeq(pkt, seq, nxt_seq);
                newp->next = chk;
                pre->next = newp;
            }
            else {
                cng = FALSE;
                while (chk != NULL && chk->nxt_seq <= nxt_seq) {
                    tmp = chk;
                    if (chk->cng == TRUE)
                        cng = TRUE;
                    chk = chk->next;
                    PktFree(tmp->pkt);
                    DMemFree(tmp);
                    ord->num--;
                }
                delta = pre->nxt_seq - seq;
                seq = pre->nxt_seq;
                pkt->data += delta;
                pkt->len -= delta;
                if (chk != NULL && nxt_seq > chk->seq) {
                    delta = nxt_seq - chk->seq;
                    nxt_seq = chk->seq;
                    pkt->len -= delta;
                }
                newp = TcpSeq(pkt, seq, nxt_seq);
                newp->next = chk;
                pre->next = newp;
            }
            if (same == FALSE && last_rv != NULL)
                last_rv->cng = TRUE;
            ord->lins_src = src;
            *last_sq = pre->next;
        }
        else {
            ord->num++;
            if (seq < pre->nxt_seq) {
                delta = pre->nxt_seq - seq;
                seq = pre->nxt_seq;
                pkt->data += delta;
                pkt->len -= delta;
            }
            if (nxt_seq <= chk->seq) {
                newp = TcpSeq(pkt, seq, nxt_seq);
                newp->next = chk;
                pre->next = newp;
            }
            else {
                if (cnt >= nxt_seq) {
                    delta = nxt_seq - chk->seq;
                    pkt->len -= delta;
                    newp = TcpSeq(pkt, seq, nxt_seq-delta);
                    newp->next = chk;
                    pre->next = newp;
                }
                else {
                    cng = FALSE;
                    while (chk != NULL && chk->nxt_seq <= nxt_seq) {
                        tmp = chk;
                        if (chk->cng == TRUE)
                            cng = TRUE;
                        chk = chk->next;
                        PktFree(tmp->pkt);
                        DMemFree(tmp);
                        ord->num--;
                    }
                    if (chk == NULL) {
                        newp = TcpSeq(pkt, seq, nxt_seq);
                        newp->cng = cng;
                        pre->next = newp;
                        /* last */
                        *last_sq = newp;
                    }
                    else {
                        if (nxt_seq > chk->seq) {
                            delta = nxt_seq - chk->seq;
                            pkt->len -= delta;
                            nxt_seq -= delta;
                        }
                        newp = TcpSeq(pkt, seq, nxt_seq);
                        newp->cng = cng;
                        newp->next = chk;
                        pre->next = newp;
                    }
                }
            }
        }
    }

    printf("%s:\n", __FUNCTION__);
    TcpOrdPrint(ord);
#if TCP_SOFT_ACK
    /* put pkt */
    TcpPut(flow_id, ord);
#endif

    return 0;
}


static bool TcpAck(int flow_id, order *ord, unsigned long ack_seq, bool src)
{
    struct seq **head, *chk, *tmp, *sq_hole;
    unsigned long seq, nxt_seq;
    packet *hole;
    ftval val;
    pstack_f *stk;
    bool ret = FALSE;

    /* select sequence to analize */
    if (src == TRUE) {
        head = &ord->dst;
        chk = ord->dst;
        seq = ord->seq_d;
        stk = ord->stk_d;
    }
    else {
        head = &ord->src;
        chk = ord->src;
        seq = ord->seq_s;
        stk = ord->stk_s;
    }

    if (ack_seq > seq) {
        ret = TRUE;
        if (chk != NULL) {
            /* complete all packet acknowleged */
            nxt_seq = seq;
            tmp = chk;
            while (chk != NULL && chk->seq <= ack_seq) {
                if (nxt_seq != chk->seq) {
                    /* hole */
                    hole = PktNew();
                    hole->stk = ProtCopyFrame(chk->pkt->stk, TRUE);
                    val.uint8 = TRUE;
                    ProtInsAttr(hole->stk, lost_id, &val);
                    if (nxt_seq != 0) {
                        hole->len = chk->seq - nxt_seq;
                    }
                    else {
                        hole->len = 0;
                    }
                    hole->data = NULL;
                    hole->cap_sec = chk->pkt->cap_sec;
                    hole->cap_usec = chk->pkt->cap_usec;
                    hole->serial = chk->pkt->serial;
                    sq_hole = TcpSeq(hole, nxt_seq, chk->seq);
                    sq_hole->next = chk;
                    sq_hole->ack = TRUE;
                    if (tmp == chk) {
                        *head = sq_hole;
                    }
                    else {
                        tmp->next = sq_hole;
                    }
                    ord->num++;
                }
                chk->ack = TRUE;
                tmp = chk;
                nxt_seq = chk->nxt_seq;
                chk = chk->next;
            }
            if (chk == NULL && nxt_seq < ack_seq) {
                /* hole in the queue of stream */
                hole = PktNew();
                hole->stk = ProtCopyFrame(tmp->pkt->stk, TRUE);
                val.uint8 = TRUE;
                ProtInsAttr(hole->stk, lost_id, &val);
                if (nxt_seq != 0) {
                    hole->len = ack_seq - nxt_seq;
                }
                else {
                    hole->len = 0;
                }
                hole->data = NULL;
                hole->cap_sec = tmp->pkt->cap_sec;
                hole->cap_usec = tmp->pkt->cap_usec;
                hole->serial = tmp->pkt->serial;
                sq_hole = TcpSeq(hole, nxt_seq, ack_seq);
                sq_hole->next = chk;
                sq_hole->ack = TRUE;
                if (tmp == chk) {
                    *head = sq_hole;
                }
                else {
                    tmp->next = sq_hole;
                }
                ord->num++;
            }
        }
        else if (seq != 0) {
            /* hole */
            hole = PktNew();
            hole->stk = ProtCopyFrame(stk, TRUE);
            val.uint8 = TRUE;
            ProtInsAttr(hole->stk, lost_id, &val);
            hole->len = ack_seq - seq;
            hole->data = NULL;
            sq_hole = TcpSeq(hole, seq, ack_seq);
            sq_hole->ack = TRUE;
            *head = sq_hole;
            ord->num++;
        }

        if (*head != NULL && seq == (*head)->seq) {
            ord->src_put = !src;
        }

        printf("%s:\n", __FUNCTION__);
        TcpOrdPrint(ord);
        TcpPut(flow_id, ord);
    }
    else if (ack_seq == seq) {
        ret = TRUE;
    }

    return ret;
}


static packet* TcpUrg(packet *pkt, unsigned short urg)
{
#ifdef XPL_CHECK_CODE
    LogPrintf(LV_OOPS, "Urgent data in pkt");
    ProtStackFrmDisp(pkt->stk, TRUE);
#endif

    return pkt;
}


static int TcpSyn(int flow_id, order *ord, packet *pkt, unsigned long seq, unsigned long nxt_seq, bool src)
{
    struct seq *ins;

    /* select sequence to analize */
    if (src == TRUE) {
        ins = ord->src;
        if (ins == NULL) {
            ord->seq_s = seq + 1;
            if (ord->ack_s == pkt)
                ord->ack_s = NULL;
            FlowPutPkt(flow_id, pkt);
            
            return 0;
        }
        else {
            if (ins->seq > seq) {
                ord->seq_s = seq;
                nxt_seq = seq + 1;
            }
            else {
                /* syn replayed */
                TcpEmpty(flow_id, ord);
                LogPrintf(LV_DEBUG, "Multimple syn");
                //ProtStackFrmDisp(pkt->stk, TRUE);
                TcpSyn(flow_id, ord, pkt, seq, nxt_seq, src);

                return 0;
            }
        }
    }
    else {
        ins = ord->dst;
        if (ins == NULL) {
            ord->seq_d = seq + 1;
            if (ord->ack_d == pkt)
                ord->ack_d = NULL;
            FlowPutPkt(flow_id, pkt);

            return 0;
        }
        else {
            if(ins->seq > seq) {
                ord->seq_d = seq;
                nxt_seq = seq + 1;
            }
            else {
                /* syn replayed */
                TcpEmpty(flow_id, ord);
                LogPrintf(LV_DEBUG, "Multimple syn");
                //ProtStackFrmDisp(pkt->stk, TRUE);
                TcpSyn(flow_id, ord, pkt, seq, nxt_seq, src);

                return 0;
            }
        }
    }
    TcpOrder(flow_id, ord, pkt, seq, nxt_seq, src);
    printf("%s:\n", __FUNCTION__);
    TcpOrdPrint(ord);

    return 0;
}


static int TcpFin(int flow_id, order *ord, packet *pkt, unsigned long seq, unsigned long nxt_seq, bool src)
{
    if (src == TRUE)
        ord->fin_s = seq;
    else
        ord->fin_d = seq;
    if (pkt->len == 0)
        nxt_seq++;
    TcpOrder(flow_id, ord, pkt, seq, nxt_seq, src);

    return 0;
}


static int TcpRst(int flow_id, order *ord, packet *pkt, unsigned long seq, unsigned long nxt_seq, bool src)
{
    ord->rst = TRUE;

    return 0;
}


#if TCP_SOFT_ACK
static int TcpOneVers(int flow_id, order *ord, bool src)
{
    if (src == TRUE) {
        if (ord->src != NULL && ord->dst == NULL) {
            if (ord->src->seq == ord->seq_s) {
                ord->src_put = TRUE;
            }
        }
    }
    else {
        if (ord->src == NULL && ord->dst != NULL) {
            if (ord->dst->seq == ord->seq_d) {
                ord->src_put = FALSE;
            }
        }
    }

    /* put pkt */
    TcpPut(flow_id, ord);

    return 0;
}
#endif


static void TcpSubDissector(int flow_id, packet *pkt)
{
    order *ord;
    struct tcphdr *tcp;
    const pstack_f *ip;
    unsigned long seq;
    unsigned long nxt_seq;
    unsigned long ack_seq;
    unsigned short tcphdr_len;
    unsigned long len;
    unsigned short s_port;
    unsigned short d_port;
    unsigned short urg;
    bool src, ack;
    ftval val, ip_s;
#if SNIFFER_EVASION
    ftval ip_ttl, ipv6_hlim;
    ftval ip_ident;
#endif

    ord = FlowNodePrivGet(flow_id);
    if (pkt == NULL) {
#ifdef XPL_CHECK_CODE
        if (ord == NULL) {
            LogPrintf(LV_OOPS, "bug in TCP subdissector");
            exit(-1);
        }
#endif
        /* flush data */
        TcpFlush(flow_id, ord, FALSE);

        TcpOrdFree(ord);
        DMemFree(ord);
        FlowNodePrivPut(flow_id, NULL);

        return;
    }

    ProtGetAttr(pkt->stk, src_id, &val);
    s_port = val.uint16;
    ip = ProtGetNxtFrame(pkt->stk);
    tcp = (struct tcphdr *)pkt->data;
    tcphdr_len = tcp->doff << 2;
    len = pkt->len - tcphdr_len;

    if (ord == NULL) {
        ord = DMemMalloc(sizeof(order));
        TcpOrdInit(ord, pkt->stk);
        if (ProtFrameProtocol(ip) == ip_id) {
            /* IPv4 */
            ProtGetAttr(ip, ip_src_id, &ord->ip);
            ord->ipv6 = FALSE;
        }
        else {
            /* IPv6 */
            ProtGetAttr(ip, ipv6_src_id, &ord->ip);
            ord->ipv6 = TRUE;
        }
        ProtGetAttr(pkt->stk, dst_id, &val);
        d_port = val.uint16;
        
        if (d_port != s_port) {
            ord->port_diff = TRUE;
        }
        else {
            ord->port_diff = FALSE;
        }
        ord->port = s_port;

        FlowNodePrivPut(flow_id, ord);

        /* if first packet is an ack with len zero
           we close the flow. In this way we eliminate
           the last fin-ack that arrive when flow is close
           by subdissector(fin+fin).
           If this packet isn't the last fin-ack is always an
           ack of flow with packet lost and so is inrilevant the
           src/dst information and so we consider as src/dst
           information assosiated with fist not zero tcp packet */
        if (tcp->ack == 1 && len == 0) {
            PktFree(pkt);
            FlowClose(flow_id);
            return;
        }
    }

    /* packet info */
#ifdef XPL_X86
    seq = ntohl(tcp->seq);
    ack_seq = ntohl(tcp->ack_seq);
#else
    seq = Emb32(&tcp->seq);
    ack_seq = Emb32(&tcp->ack_seq);
    ack_seq = ntohl(ack_seq);
#endif
    nxt_seq = seq + len;
    printf("New pkt:%lu----->%lu\n", seq, nxt_seq);
    printf("%s: start\n", __FUNCTION__);
    TcpOrdPrint(ord);

    if (ord->ipv6) {
        ProtGetAttr(ip, ipv6_src_id, &ip_s);
#if SNIFFER_EVASION
        ProtGetAttr(ip, ipv6_hlim_id, &ipv6_hlim);
#endif
    }
    else {
        ProtGetAttr(ip, ip_src_id, &ip_s);
#if SNIFFER_EVASION
        ProtGetAttr(ip, ip_ttl_id, &ip_ttl);
        ProtGetAttr(ip, ip_id_id, &ip_ident);
#endif
    }

    if (ord->port_diff == TRUE) {
        if (ord->port == s_port)
            src = TRUE;
        else {
            src = FALSE;
            ord->mono = FALSE;
        }
    }
    else {
        if (ord->ipv6) {
            if (FTCmp(&ip_s, &ord->ip, FT_IPv6, FT_OP_EQ, NULL) == 0)
                src = TRUE;
            else {
                src = FALSE;
                ord->mono = FALSE;
            }
        }
        else {
            if (FTCmp(&ip_s, &ord->ip, FT_IPv4, FT_OP_EQ, NULL) == 0)
                src = TRUE;
            else {
                src = FALSE;
                ord->mono = FALSE;
            }
        }
    }
    /* insert client attribute */
    val.uint8 = src;
    ProtInsAttr(pkt->stk, clnt_id, &val);

    if (ord->stk_d == NULL && src == FALSE) {
        ord->stk_d = ProtCopyFrame(pkt->stk, TRUE);
    }

    /* pdu */
    pkt->data += tcphdr_len;
    pkt->len = len;

    /* check ack */
    ack = FALSE;
    if (tcp->ack == 1) {
#if TCP_ENABLE_TCP_ACK
        ack = TcpAck(flow_id, ord, ack_seq, src);
#endif
    }

    /* check urg */
    if (tcp->urg == 1) {
        urg = ntohs(tcp->urg_ptr);
        if (urg < len)
            pkt = TcpUrg(pkt, urg);
    }

    /* check syn */
    if (tcp->syn == 1) {
        val.uint8 = TRUE;
        ProtInsAttr(pkt->stk, syn_id, &val);
        TcpSyn(flow_id, ord, pkt, seq, nxt_seq, src);
        pkt = NULL;
    }
    else if (tcp->fin == 1) {
        /* check fin */
        TcpFin(flow_id, ord, pkt, seq, nxt_seq, src);
        pkt = NULL;
    }
    if (pkt != NULL && tcp->rst == 1) {
        /* check rst */
        TcpRst(flow_id, ord, pkt, seq, nxt_seq, src);
    }

    /* insert pkt */
    if (len > 0 && pkt != NULL) {
        TcpOrder(flow_id, ord, pkt, seq, nxt_seq, src);
        pkt = NULL;
#if TCP_SOFT_ACK
        TcpOneVers(flow_id, ord, src);
#endif
    }

    if (pkt != NULL && ack == TRUE && len == 0) {
        /* last ack */
        if (src) {
            if (ord->ack_s != NULL)
                PktFree(ord->ack_s);
            ord->ack_s = pkt;
        }
        else {
           if (ord->ack_d != NULL)
               PktFree(ord->ack_d);
           ord->ack_d = pkt; 
        }
        pkt = NULL;
    }

    if (pkt != NULL)
        PktFree(pkt);

    printf("%s: end\n", __FUNCTION__);
    TcpOrdPrint(ord);

    if (ord->mono == TRUE && ord->num > (TCP_SUBDIS_MONO_PKT_LIMIT + TCP_SUBDIS_MONO_PKT_MARG)) {
        TcpFlush(flow_id, ord, TRUE);
    }
    if ((ord->fin_s != 0 && ord->fin_d != 0) || ord->rst == TRUE) {
        /* close flow */
        TcpFlush(flow_id, ord, FALSE);
        FlowClose(flow_id);
    }
}


static packet* TcpDissector(packet *pkt)
{
    pstack_f *frame;
    ftval val, ipv6_src, ipv6_dst;
    struct tcphdr *tcp;
#if (XPL_DIS_IP_CHECKSUM == 0)
    unsigned int src, dst;
    vec_t cksum_vec[4];
    unsigned int phdr[2];
    unsigned short computed_cksum;
#endif

    /* check lenght packet */
    if (pkt->len < sizeof(struct tcphdr)) {
        LogPrintf(LV_WARNING, "TCP header packet length error (tcp:%i pkt:%i tcp_header:%i)", sizeof(struct tcphdr), pkt->len, sizeof(struct tcphdr));
        ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);

        return NULL;
    }

    tcp = (struct tcphdr *)pkt->data;
    /* check consistence and checksum */
    if (ProtFrameProtocol(pkt->stk) == ip_id) {
#if (XPL_DIS_IP_CHECKSUM == 0)
        /* IPv4 */
        ProtGetAttr(pkt->stk, ip_src_id, &val);
        src = val.uint32;
        ProtGetAttr(pkt->stk, ip_dst_id, &val);
        dst = val.uint32;

        cksum_vec[0].ptr = (const unsigned char *)&src;
        cksum_vec[0].len = 4;
        cksum_vec[1].ptr = (const unsigned char *)&dst;
        cksum_vec[1].len = 4;
        cksum_vec[2].ptr = (const unsigned char *)&phdr;
        phdr[0] = htonl((IP_PROTO_TCP<<16) + pkt->len);
        cksum_vec[2].len = 4;
        cksum_vec[3].ptr = (unsigned char *)pkt->data;
        cksum_vec[3].len = pkt->len;
        computed_cksum = in_cksum(&cksum_vec[0], 4);
        if (computed_cksum != 0) {
            LogPrintf(LV_WARNING, "TCP packet chechsum error 0x%x", computed_cksum);
            //ProtStackFrmDisp(pkt->stk, TRUE);
            PktFree(pkt);

            return NULL;
        }
#endif
    }
    else {
        /* IPv6 */
        ProtGetAttr(pkt->stk, ipv6_src_id, &ipv6_src);
        ProtGetAttr(pkt->stk, ipv6_dst_id, &ipv6_dst);
#if (XPL_DIS_IP_CHECKSUM == 0)
        cksum_vec[0].ptr = (const unsigned char *)&ipv6_src.ipv6;
        cksum_vec[0].len = 16;
        cksum_vec[1].ptr = (const unsigned char *)&ipv6_dst.ipv6;
        cksum_vec[1].len = 16;
        cksum_vec[2].ptr = (const unsigned char *)&phdr;
        phdr[0] = htonl(pkt->len);
        phdr[1] = htonl(IP_PROTO_TCP);
        cksum_vec[2].len = 8;

        cksum_vec[3].ptr = (unsigned char *)pkt->data;
        cksum_vec[3].len = pkt->len;
        computed_cksum = in_cksum(&cksum_vec[0], 4);
        if (computed_cksum != 0) {
            LogPrintf(LV_WARNING, "TCP packet chechsum error 0x%x", computed_cksum);
            //ProtStackFrmDisp(pkt->stk, TRUE);
            PktFree(pkt);

            return NULL;
        }
#endif
    }

#if XPL_DIS_IP_CHECKSUM
    if (pkt->len < sizeof(struct tcphdr)) {
        LogPrintf(LV_WARNING, "TCP leght error");
        //ProtStackFrmDisp(pkt->stk, TRUE);
        PktFree(pkt);
        return NULL;
    }
#endif

    /* new frame */
    frame = ProtCreateFrame(prot_id);
    ProtSetNxtFrame(frame, pkt->stk);
    pkt->stk = frame;

    /* set attribute */
    val.uint16 = ntohs(tcp->source);
    ProtInsAttr(frame, src_id, &val);
    val.uint16 = ntohs(tcp->dest);
    ProtInsAttr(frame, dst_id, &val);
    val.uint8 = TRUE; /* insert default client attribute */
    ProtInsAttr(frame, clnt_id, &val); 
    val.uint8 = FALSE; /* insert default syn attribute */
    ProtInsAttr(pkt->stk, syn_id, &val);

    /* pdu 'extracted' by subdissector */
    
    return pkt;
}


int DissectFlowHash(cmpflow *fd, unsigned long *hashs)
{
    oflow *o;
    ftval tmp;
    const pstack_f *ip;
    int cmpret;
    
    fd->priv = xmalloc(sizeof(oflow));
    memset(fd->priv, 0, sizeof(oflow));
    o = fd->priv;
    
    ip = ProtGetNxtFrame(fd->stack);
    if (ProtFrameProtocol(ip) == ip_id) {
        o->ipv4 = TRUE;
        hashs[0] = 0;
        ProtGetAttr(ip, ip_dst_id, &o->ip_mx);
        ProtGetAttr(ip, ip_src_id, &o->ip_mn);
        ProtGetAttr(fd->stack, dst_id, &tmp);
        o->port_mx = tmp.uint16;
        ProtGetAttr(fd->stack, src_id, &tmp);
        o->port_mn = tmp.uint16;
        hashs[1] = o->ip_mx.uint32 + o->ip_mn.uint32;
        hashs[1] += o->port_mx + o->port_mn;
        if (o->ip_mx.uint32 < o->ip_mn.uint32 || (o->ip_mx.uint32 == o->ip_mn.uint32 && o->port_mx < o->port_mn)) {
            tmp = o->ip_mn;
            o->ip_mn = o->ip_mx;
            o->ip_mx = tmp;
            tmp.uint16 = o->port_mn;
            o->port_mn = o->port_mx;
            o->port_mx = tmp.uint16;
        }
    }
    else {
        o->ipv4 = FALSE;
        hashs[0] = 1;
        ProtGetAttr(ip, ipv6_dst_id, &o->ip_mx);
        ProtGetAttr(ip, ipv6_src_id, &o->ip_mn);
        ProtGetAttr(fd->stack, dst_id, &tmp);
        o->port_mx = tmp.uint16;
        ProtGetAttr(fd->stack, src_id, &tmp);
        o->port_mn = tmp.uint16;
        hashs[1] = FTHash(&o->ip_mx, FT_IPv6);
        hashs[1] += FTHash(&o->ip_mn, FT_IPv6);
        hashs[1] += o->port_mx + o->port_mn;
        cmpret = memcmp(o->ip_mx.ipv6, o->ip_mn.ipv6, 16);
        if (cmpret < 0 || (cmpret == 0 && o->port_mx < o->port_mn)) {
            tmp = o->ip_mn;
            o->ip_mn = o->ip_mx;
            o->ip_mx = tmp;
            tmp.uint16 = o->port_mn;
            o->port_mn = o->port_mx;
            o->port_mx = tmp.uint16;
        }
    }
    
    return 0;
}


int DissectFlowCmpFree(cmpflow *fd)
{
    xfree(fd->priv);
    
    return 0;
}


int DissectFlowCmp(const cmpflow *fd_a, const cmpflow *fd_b)
{
    oflow *fa, *fb;
    
    fa = (oflow *)fd_a->priv;
    fb = (oflow *)fd_b->priv;
    
    if (fa->ipv4) {
        if (fa->ip_mn.uint32 < fb->ip_mn.uint32)
            return -1;
        else {
            if (fa->ip_mn.uint32 > fb->ip_mn.uint32)
                return 1;
        }
        if (fa->port_mn < fb->port_mn)
            return -1;
        else {
            if (fa->port_mn > fb->port_mn)
                return 1;
        }
        if (fa->ip_mx.uint32 < fb->ip_mx.uint32)
            return -1;
        else {
            if (fa->ip_mx.uint32 > fb->ip_mx.uint32)
                return 1;
        }
        if (fa->port_mx < fb->port_mx)
            return -1;
        else {
            if (fa->port_mx > fb->port_mx)
                return 1;
        }
    }
    else {
        if (memcmp(fa->ip_mn.ipv6, fb->ip_mn.ipv6, 16) < 0)
            return -1;
        else {
            if (memcmp(fa->ip_mn.ipv6, fb->ip_mn.ipv6, 16) > 0)
                return 1;
        }
        if (fa->port_mn < fb->port_mn)
            return -1;
        else {
            if (fa->port_mn > fb->port_mn)
                return 1;
        }
        if (memcmp(fa->ip_mx.ipv6, fb->ip_mx.ipv6, 16) < 0)
            return -1;
        else {
            if (memcmp(fa->ip_mx.ipv6, fb->ip_mx.ipv6, 16) > 0)
                return 1;
        }
        if (fa->port_mx < fb->port_mx)
            return -1;
        else {
            if (fa->port_mx > fb->port_mx)
                return 1;
        }
    }

    return 0;
}


int DissecRegist(const char *file_cfg)
{
    proto_info info;
    proto_dep dep;

    memset(&info, 0, sizeof(proto_info));
    memset(&dep, 0, sizeof(proto_dep));

    /* protocol name */
    ProtName("Transmission Control Protocol", "tcp");

    /* info: source */
    info.name = "Source port";
    info.abbrev = "tcp.srcport";
    info.type = FT_UINT16;
    src_id = ProtInfo(&info);

    /* info: destination */
    info.name = "Destination port";
    info.abbrev = "tcp.dstport";
    info.type = FT_UINT16;
    dst_id = ProtInfo(&info);
    
    /* info: lost */
    info.name = "Client packet";
    info.abbrev = "tcp.clnt";
    info.type = FT_UINT8;
    clnt_id = ProtInfo(&info);

    /* info: lost */
    info.name = "Lost packet";
    info.abbrev = "tcp.lost";
    info.type = FT_UINT8;
    lost_id = ProtInfo(&info);

    /* info: syn */
    info.name = "Packet with syn";
    info.abbrev = "tcp.syn";
    info.type = FT_UINT8;
    syn_id = ProtInfo(&info);

    /* dep: IP */
    dep.name = "ip";
    dep.attr = "ip.proto";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_TCP;
    ProtDep(&dep);

    /* dep: IPv6 */
    dep.name = "ipv6";
    dep.attr = "ipv6.nxt";
    dep.type = FT_UINT8;
    dep.val.uint8 = IP_PROTO_TCP;
    ProtDep(&dep);

    /* dissectors registration */
    ProtDissectors(TcpDissector, NULL, NULL, NULL);

    /* subdissectors registration */
    ProtSubDissectors(TcpSubDissector);

    return 0;
}


int DissectInit(void)
{
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    prot_id = ProtId("tcp");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
#if SNIFFER_EVASION
    ip_ttl_id = ProtAttrId(ip_id, "ip.ttl");
    ip_id_id = ProtAttrId(ip_id, "ip.id");
#endif
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
#if SNIFFER_EVASION
    ipv6_hlim_id = ProtAttrId(ip_id, "ipv6.hlim");
#endif
    return 0;
}
