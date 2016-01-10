/* flow.c
 * flow core functions
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <time.h>

#include "configs.h"
#include "flow.h"
#include "proto.h"
#include "log.h"
#include "dmemory.h"
#include "grp_flows.h"
#include "fthread.h"
#include "grp_rule.h"


/** define */
#define FW_TBL_ELEMENT_DELTA   100000
#define FW_TBL_FFREE_LIM        40000

/* avoid deadlock: new code */
#define XP_NEW_CLOSE              1

typedef struct _freel freel;
struct _freel {
    int id;
    freel *nxt;
};

/** external variables */
extern prot_desc *prot_tbl;
extern int prot_tbl_dim;

/** internal variables */
static flow *volatile flow_tbl;   /* table of flows... all flows */
static volatile unsigned long tbl_dim;     /* dimension of table */
static volatile unsigned long flow_num;    /* number of open flows */
static pthread_mutex_t flow_mux;           /* mutex to access atomicly the tbl */
static volatile pthread_t ptrd_lock;       /* ptread that lock access */
static short nesting;                      /* lock nesting */
static time_t gbl_time;                    /* flow global time */
static freel *ffree;
static unsigned long ffree_num;

/** internal functions */
static int FlowElemInit(flow *flw, bool reset)
{
    int i, n;

    flw->elab = FALSE;
    flw->proto_id = -1;
    flw->fthd_id = -1;
    flw->pfid = -1;
    flw->son_num = 0;
    flw->grp_id = -1;
    flw->pgrp_id = -1;
    flw->gref = -1;
    flw->grp_fuse = FALSE;
    flw->sync = FALSE;
    flw->stack = NULL;
    flw->name[0] = '\0';
    flw->time = ULONG_MAX;
    flw->ustime = ULONG_MAX;
    flw->pkt_q = NULL;
    flw->fpkt = NULL;
    flw->cpkt = NULL;
    flw->close = TRUE; /* attention to modify FlowCloseAll */
    flw->get_to = -1;

    if (reset == FALSE) {
        /* allocate mutex and inizialize it */
        flw->mux = xmalloc(sizeof(pthread_mutex_t));
        pthread_mutex_init(flw->mux, NULL);
        flw->cond = xmalloc(sizeof(pthread_cond_t));
        pthread_cond_init(flw->cond, NULL);
        flw->gcond = xmalloc(sizeof(pthread_cond_t));
        pthread_cond_init(flw->gcond, NULL);
    }

    n = ProtNumber();
    flw->pkt_num = 0;
    flw->priv_data_pn = NULL;
    flw->priv_data = NULL;
    if (reset == FALSE) {
        flw->priv_data_sp = xmalloc(sizeof(void *)*n);
        if (flw->priv_data_sp == NULL) {
            LogPrintf(LV_ERROR, "Unable to inizialie flows data tableallocate memory!");
            return -1;
        }
        
        for (i=0; i!=n; i++) {
            flw->priv_data_sp[i] = NULL;
        }
    }
    else {
        for (i=0; i!=n; i++) {
            if (flw->priv_data_sp[i] != NULL) {
                LogPrintf(LV_WARNING, "Bug in the dissector: %s. Memory leakage!", ProtGetName(i));
            }
            flw->priv_data_sp[i] = NULL;
        }
    }

#ifdef XPL_PEDANTIC_STATISTICS
    flw->pkt_tot = 0;
#endif

    return 0;
}


static int FlowTblExtend(void)
{
    unsigned long i, len;
    flow *newft, *tmp;

    len = tbl_dim + FW_TBL_ELEMENT_DELTA;

    /* lock all mutex */
    for (i=0; i!=tbl_dim; i++) {
        pthread_mutex_lock(flow_tbl[i].mux);
    }

    /* extend memory(copy) */
    newft = xmalloc(sizeof(flow)*(len));
    if (newft == NULL)
        return -1;
    memcpy(newft, flow_tbl, sizeof(flow)*(tbl_dim));
    
    /* initialize new elements */
    for (i=tbl_dim; i<len; i++) {
        memset(&newft[i], 0, sizeof(flow));
        if (FlowElemInit(&(newft[i]), FALSE) != 0) {
            /* unlock all mutex */
            for (i=0; i!=tbl_dim; i++) {
                pthread_mutex_unlock(flow_tbl[i].mux);
            }
            xfree(newft);
            return -1;
        }
    }
    tmp = flow_tbl;
    flow_tbl = newft;
    /* unlock all mutex */
    for (i=0; i!=tbl_dim; i++) {
        pthread_mutex_unlock(flow_tbl[i].mux);
    }
    xfree(tmp);
    tbl_dim = len;

    return 0;
}


static inline void FlowTblLock(void)
{
    if (pthread_mutex_trylock(&flow_mux) != 0) {
        if (ptrd_lock != pthread_self()) {
            pthread_mutex_lock(&flow_mux);
        }
    }
    ptrd_lock = pthread_self();
    nesting++;
}


static inline void FlowTblUnlock(void)
{
    nesting--;
    if (nesting == 0) {
        ptrd_lock = 0;
        pthread_mutex_unlock(&flow_mux);
    }
}


int FlowInit(void)
{ 
    flow_tbl = NULL;
    tbl_dim = 0;
    flow_num = 0;
    gbl_time = ULONG_MAX; /* no time */

    /* base flows tbl */
    if (FlowTblExtend() == -1) {
        LogPrintf(LV_ERROR, "Unable to inizialie flows data table");
        return -1;
    }
    pthread_mutex_init(&flow_mux, NULL);
    ptrd_lock = 0;
    nesting = 0;
    ffree = NULL;
    ffree_num = 0;
    
    return 0;
}


const pstack_f *FlowStack(int flow_id)
{
    pstack_f *res;

    FlowTblLock();

    res = flow_tbl[flow_id].stack;

    FlowTblUnlock();

    return res;
}


int FlowCreate(pstack_f *stk)
{
    int i, ret;
    freel *ftmp;
    
    FlowTblLock();

    if (ffree == NULL) {
        /* search free location */
        for (i=0; i!=tbl_dim; i++) {
            if (flow_tbl[i].stack == NULL) {
                break;
            }
        }
        if (i == tbl_dim) {
            ret = FlowTblExtend();
            if (ret == -1) {
                LogPrintf(LV_ERROR, "Unable to extend flows data table");
                FlowTblUnlock();
    
                return -1;
            }
        }
    }
    else {
        i = ffree->id;
        ftmp = ffree;
        ffree = ffree->nxt;
        xfree(ftmp);
        ffree_num--;
    }
    
#ifdef XPL_CHECK_CODE
    if (flow_tbl[i].fpkt != NULL || flow_tbl[i].pkt_num != 0) {
        LogPrintf(LV_OOPS, "flow element free with packet!");
    }
#endif
    FlowElemInit(&flow_tbl[i], TRUE);
    flow_tbl[i].stack = ProtCopyFrame(stk, TRUE);
    flow_tbl[i].close = FALSE;
    flow_tbl[i].stack->flow_id = i;
    flow_tbl[i].proto_id = ProtFrameProtocol(stk);
    flow_tbl[i].pfid = ProtParent(stk);
    if (flow_tbl[i].pfid != -1) {
        flow_tbl[i].pgrp_id = flow_tbl[flow_tbl[i].pfid].grp_id;
        flow_tbl[flow_tbl[i].pfid].son_num++;
    }
    else
        flow_tbl[i].pgrp_id = -1;
    flow_num++;
    
    FlowTblUnlock();

    return i;
}


int FlowClose(int flow_id)
{
#if XP_NEW_CLOSE
    int pid;
#endif
    
    FlowTblLock();

    /* set close */
    if (flow_tbl[flow_id].close == TRUE) {
        FlowTblUnlock();

        return 0;
    }

#if XP_NEW_CLOSE
    pid = flow_tbl[flow_id].stack->pid;
    FlowTblUnlock();
#endif

    /* flush data */
    /* disable sync to avoid dead lock, and also because the flow is terminated */
    FlowSyncr(flow_id, FALSE);
#if XP_NEW_CLOSE
    ProtFlushFlow(pid, flow_id);
#else
    ProtFlushFlow(flow_tbl[flow_id].stack->pid, flow_id);
#endif

#if XP_NEW_CLOSE
    FlowTblLock();
#endif
    flow_tbl[flow_id].close = TRUE;

    /* if this flow isn't in elaboration we search an heuristic dissector */
    if (flow_tbl[flow_id].elab == FALSE && flow_tbl[flow_id].pkt_num != 0) {
        ProtSearchHeuDissec(flow_tbl[flow_id].proto_id, flow_id);
    }
    pthread_mutex_lock(flow_tbl[flow_id].mux);

#ifndef XPL_CHECK_CODE
    if (flow_tbl[flow_id].pkt_num != 0 && flow_tbl[flow_id].fpkt == NULL) {
        LogPrintf(LV_OOPS, "bug in function %s line: %d", __FILE__, __LINE__);
        while (1) {
            sleep(1);
        }
    }
#endif

    /* wakeup flow in wait */
    if (flow_tbl[flow_id].grp_fuse == TRUE && flow_tbl[flow_id].grp_id != -1) {
        GrpFlowClosed(flow_tbl[flow_id].grp_id);
    }
    pthread_cond_signal(flow_tbl[flow_id].cond);
    pthread_mutex_unlock(flow_tbl[flow_id].mux);

    /* if this flow isn't in elaboration delete it */
    if (flow_tbl[flow_id].elab == FALSE) {
#if XP_NEW_CLOSE
        FlowTblUnlock();
#endif
        if (flow_tbl[flow_id].pkt_num != 0)
            LogPrintf(LV_DEBUG, "FlowClose: flow %i no elab... delete it", flow_id);
        FlowDelete(flow_id);
#if XP_NEW_CLOSE
        FlowTblLock();
#endif
    }

    FlowTblUnlock();

    return 0;
}


bool FlowCloseAll(void)
{
    int i, cnt;
    int base;
    bool ret;

    ret = TRUE;
    cnt = 0;

    FlowTblLock();

    base = flow_num;

    for (i=0; i<tbl_dim && cnt<base; i++) {
        ret = FALSE;
        if (flow_tbl[i].stack != NULL && flow_tbl[i].pfid == -1) {
            cnt++;
            FlowTblUnlock(); /* it isn't necessary to FlowClose (beacause close value is always coerent) but it is useful for scheduler thread */
            FlowClose(i);
            FlowTblLock();
        }
    }

    FlowTblUnlock();

    return ret;
}


int FlowDelete(int flow_id)
{
    int ret;
    packet *pkt, *tmp;
    int i, cnt, base;
    int nxt_flw, grp_id;
    freel *ftmp;
    
    FlowTblLock();

    /* check if flow is closed */
    if (flow_tbl[flow_id].close == FALSE) {
        FlowTblUnlock();
        LogPrintf(LV_ERROR, "It is tried to delete an open flow");
        return -1;
    }

    /* close all flows son of this */
    grp_id = flow_tbl[flow_id].grp_id;
    if (grp_id == -1) {
        if (flow_tbl[flow_id].son_num) {
            cnt = 0;
            base = flow_num;
            for (i=0; i<tbl_dim && cnt<base; i++) {
                if (flow_tbl[i].stack != NULL) {
                    cnt++;
                    if (flow_tbl[i].pfid == flow_id) {
                        FlowClose(i);
                        flow_tbl[i].pfid = -1; /* parent terminated */
                    }
                }
            }
        }
    }
    else if (GrpFlowNum(grp_id) == 1) {
        /* last flow of this group (the thread flow is terminated!) */
        cnt = 0;
        base = flow_num;
        for (i=0; i<tbl_dim && cnt<base; i++) {
            if (flow_tbl[i].stack != NULL) {
                cnt++;
                if (flow_tbl[i].pgrp_id == grp_id) {
                    FlowClose(i);
                    flow_tbl[i].pfid = -1; /* parent terminated */
                    flow_tbl[i].pgrp_id = -1; /* parent terminated */
                }
            }
        }
    }

    /* parent son counter */
    if (flow_tbl[flow_id].pfid != -1) {
        flow_tbl[flow_tbl[flow_id].pfid].son_num--;
    }

    /* count the packet from protocol node to protocol dissector */
#ifdef XPL_PEDANTIC_STATISTICS
    if (flow_tbl[flow_id].proto_id != -1 && flow_tbl[flow_id].proto_id != flow_tbl[flow_id].pfid) {
        ProtPktFromNode(flow_tbl[flow_id].proto_id, flow_tbl[flow_id].pkt_tot);
    }
#endif

    /* remove all (grp) rules created by this flow */
    GrpRuleRmAll(flow_id);

    /* check if flow have packet in the queue */
    pthread_mutex_lock(flow_tbl[flow_id].mux);
    if (flow_tbl[flow_id].pkt_num != 0) {
        if (flow_tbl[flow_id].elab == TRUE) {
            LogPrintf(LV_WARNING, "Deleted a flow with %d packet in queue", flow_tbl[flow_id].pkt_num);
            ProtStackFrmDisp(FlowStack(flow_id), TRUE);
        }
        pkt = flow_tbl[flow_id].fpkt;
        
        /* free all packet */
#ifndef XPL_CHECK_CODE
        PktFree(pkt); /* recursive */
        pkt = NULL;
#else
        while (pkt != NULL) {
            tmp = pkt;
            pkt = pkt->next;
            tmp->next = NULL;
            PktFree(tmp);
            flow_tbl[flow_id].pkt_num--;
        }
        if (flow_tbl[flow_id].pkt_num != 0) {
            LogPrintf(LV_OOPS, "bug in pkt flow counter");
        }
#endif
    }

    pthread_mutex_unlock(flow_tbl[flow_id].mux);

    /* thread */
    if (flow_tbl[flow_id].elab == TRUE) {
        if (flow_tbl[flow_id].grp_id == -1) {
            ProtRunFlowDec(flow_tbl[flow_id].proto_id);
            FthreadChFlow(flow_tbl[flow_id].fthd_id, -1);
        }
        else {
            if (FthreadFlow(flow_tbl[flow_id].fthd_id) == flow_id) {
                GrpLock(flow_tbl[flow_id].grp_id);
                do {
                    nxt_flw = GrpNext(flow_tbl[flow_id].grp_id);
                } while (nxt_flw != -1 && nxt_flw == flow_id);
                GrpUnlock(flow_tbl[flow_id].grp_id);
#ifndef PROT_GRP_COUNT
                if (nxt_flw == -1) {
                    ProtRunFlowDec(flow_tbl[flow_id].proto_id);
                }
#else
                ProtRunFlowDec(flow_tbl[flow_id].proto_id);
#endif
                FthreadChFlow(flow_tbl[flow_id].fthd_id, nxt_flw);
            }
            else {
#ifdef PROT_GRP_COUNT
                ProtRunFlowDec(flow_tbl[flow_id].proto_id);
#endif
            }
        }
    }

    /* remove from grp */
    if (flow_tbl[flow_id].grp_id != -1) {
        ret = GrpRm(flow_tbl[flow_id].grp_id, flow_id);
#ifdef XPL_CHECK_CODE
        if (ret == -1) {
            LogPrintf(LV_OOPS, "bug in Grp Add/Rm use");
        }
#endif
    }

    /* stack */
    ProtDelFrame(flow_tbl[flow_id].stack);

    /* reset flow cel */
    FlowElemInit(flow_tbl+flow_id, TRUE);
    if (ffree_num != FW_TBL_FFREE_LIM) {
        ftmp = xmalloc(sizeof(freel));
        ftmp->id = flow_id;
        ftmp->nxt = ffree;
        ffree = ftmp;
        ffree_num++;
    }
    flow_num--;

    FlowTblUnlock();

    return 0;
}


int FlowDettach(int flow_id)
{
    int nxt_flw, ret;
    bool sync;

    sync = FALSE;
    FlowTblLock();

    /* count the packet from protocol node to protocol dissector */
#ifdef XPL_PEDANTIC_STATISTICS
    if (flow_tbl[flow_id].proto_id != -1 && flow_tbl[flow_id].proto_id != flow_tbl[flow_id].pfid) {
        ProtPktFromNode(flow_tbl[flow_id].proto_id, flow_tbl[flow_id].pkt_tot);
        flow_tbl[flow_id].pkt_tot = 0;
    }
#endif

    /* thread */
    if (flow_tbl[flow_id].elab == TRUE) {
        if (flow_tbl[flow_id].grp_id == -1) {
            ProtRunFlowDec(flow_tbl[flow_id].proto_id);
            FthreadChFlow(flow_tbl[flow_id].fthd_id, -1);
        }
        else {
            if (FthreadFlow(flow_tbl[flow_id].fthd_id) == flow_id) {
                GrpLock(flow_tbl[flow_id].grp_id);
                do {
                    nxt_flw = GrpNext(flow_tbl[flow_id].grp_id);
                } while (nxt_flw != -1 && nxt_flw == flow_id);
                GrpUnlock(flow_tbl[flow_id].grp_id);
#ifndef PROT_GRP_COUNT
                if (nxt_flw == -1) {
                    ProtRunFlowDec(flow_tbl[flow_id].proto_id);
                }
#else
                ProtRunFlowDec(flow_tbl[flow_id].proto_id);
#endif
                FthreadChFlow(flow_tbl[flow_id].fthd_id, nxt_flw);
            }
            else {
#ifdef PROT_GRP_COUNT
                ProtRunFlowDec(flow_tbl[flow_id].proto_id);
#endif
            }
        }
        flow_tbl[flow_id].elab = FALSE;
        flow_tbl[flow_id].fthd_id = -1;
        sync = flow_tbl[flow_id].sync; /* there is the possibility thar flow parent is blocket in FlowPutPkt */
    }

    /* dettach from group */
    if (flow_tbl[flow_id].grp_id != -1) {
        ret = GrpRm(flow_tbl[flow_id].grp_id, flow_id);
#ifdef XPL_CHECK_CODE
        if (ret == -1) {
            LogPrintf(LV_OOPS, "bug in Grp Add/Rm use");
        }
#endif
    }
    /* erase name */
    flow_tbl[flow_id].name[0] = '\0';

    /* reset to original the proto_id (NOT pfid!!) */
    flow_tbl[flow_id].proto_id = ProtFrameProtocol(flow_tbl[flow_id].stack);
#ifdef XPL_CHECK_CODE
    if (flow_tbl[flow_id].pfid != -1) {
        LogPrintf(LV_OOPS, "bug in Dettach (%s:%i) {%i}", __FILE__, __LINE__, flow_tbl[flow_id].pfid);
    }
#endif

    /* if closed the flow haven't a parent */
    if (flow_tbl[flow_id].close == TRUE) {
        /* if this flow isn't in elaboration we search an heuristic dissector */
#warning "only heuristic?!"
        if (flow_tbl[flow_id].pkt_num != 0)
            ret = ProtSearchHeuDissec(flow_tbl[flow_id].proto_id, flow_id);
        /* if this flow isn't in elaboration delete it */
        if (flow_tbl[flow_id].elab == FALSE) {
            if (flow_tbl[flow_id].pkt_num != 0)
                LogPrintf(LV_DEBUG, "FlowDettach: flow %i no elab... delete it", flow_id);
            sync = FALSE;
            FlowDelete(flow_id);
        }
    }

    FlowTblUnlock();

    if (sync == TRUE) {
        pthread_mutex_lock(flow_tbl[flow_id].mux);
        pthread_cond_signal(flow_tbl[flow_id].gcond);
        pthread_mutex_unlock(flow_tbl[flow_id].mux);
    }

    return 0;
}


packet *FlowGetPkt(int flow_id)
{
    packet *pkt;
    struct timespec to;
    struct timeval tpkt, tou;
    bool fuse;
    int ret;

    fuse = FALSE;
    /* fuse (syncronyze flows) flows belong at the same group */
    if (flow_tbl[flow_id].grp_fuse == TRUE && flow_tbl[flow_id].grp_id != -1) {
        fuse = TRUE;
        if (GrpWaitPkt(flow_tbl[flow_id].grp_id, flow_tbl[flow_id].gref) == 0) {
            /* there is a packet but isnt' of this flow */
            return NULL;
        }
    }

    pthread_mutex_lock(flow_tbl[flow_id].mux);
    
    while (flow_tbl[flow_id].fpkt == NULL) {
        if (flow_tbl[flow_id].sync) { /* erase this line to optimize code */
            /* last packet consumed */
            pthread_cond_signal(flow_tbl[flow_id].gcond);
        }
        if (flow_tbl[flow_id].close == TRUE)
            break;
        if (flow_tbl[flow_id].get_to > 0) {
#warning "to improve"
            gettimeofday(&tou, 0);
            to.tv_sec = tou.tv_sec + flow_tbl[flow_id].get_to/1000;
            tou.tv_usec += (flow_tbl[flow_id].get_to%1000)*1000;
            to.tv_sec += tou.tv_usec/1000000;
            to.tv_nsec = (tou.tv_usec%1000000)*1000;
            ret = pthread_cond_timedwait(flow_tbl[flow_id].cond, flow_tbl[flow_id].mux, &to);
            ret = ret;
            if (flow_tbl[flow_id].fpkt == NULL)
                break;
        }
        else if (flow_tbl[flow_id].get_to == -1)
            pthread_cond_wait(flow_tbl[flow_id].cond, flow_tbl[flow_id].mux);
        else /* get_to == 0 */
            break;
    }
    if (flow_tbl[flow_id].fpkt == NULL) {
        pthread_mutex_unlock(flow_tbl[flow_id].mux);
        
        return NULL;
    }

    pkt = flow_tbl[flow_id].fpkt;
    flow_tbl[flow_id].fpkt = flow_tbl[flow_id].fpkt->next;
#ifdef XPL_CHECK_CODE
    if (pkt != flow_tbl[flow_id].cpkt) {
        LogPrintf(LV_OOPS, "bug in funcrion %s line: %d", __FILE__, __LINE__);
        exit(-1);
    }
#endif
    flow_tbl[flow_id].cpkt = flow_tbl[flow_id].fpkt;
    if (flow_tbl[flow_id].fpkt == NULL) {
        flow_tbl[flow_id].pkt_q = NULL;
    }
    else if (fuse == TRUE) {
        /* time of next patcket of this flow */
        tpkt.tv_sec = flow_tbl[flow_id].fpkt->cap_sec;
        tpkt.tv_usec = flow_tbl[flow_id].fpkt->cap_usec;
        GrpNewPkt(flow_tbl[flow_id].grp_id, flow_tbl[flow_id].gref, &tpkt);
    }

    flow_tbl[flow_id].time = pkt->cap_sec;
    flow_tbl[flow_id].ustime = pkt->cap_usec;
    flow_tbl[flow_id].pkt_num--;
#ifdef XPL_CHECK_CODE
    if (flow_tbl[flow_id].pkt_num != 0 && flow_tbl[flow_id].fpkt == NULL) {
        LogPrintf(LV_OOPS, "bug in function %s line: %d", __FILE__, __LINE__);
        exit(-1);
    }
#endif
    pthread_mutex_unlock(flow_tbl[flow_id].mux);
    pkt->next = NULL;

    return pkt;
}


packet* FlowGetPktCp(int flow_id)
{
    packet *pkt = NULL;

    pthread_mutex_lock(flow_tbl[flow_id].mux);

    if (flow_tbl[flow_id].cpkt != NULL) {
        pkt = PktCp(flow_tbl[flow_id].cpkt);
        flow_tbl[flow_id].cpkt = flow_tbl[flow_id].cpkt->next;
    }

    pthread_mutex_unlock(flow_tbl[flow_id].mux);

    return pkt;
}


int FlowPktCpReset(int flow_id)
{
    pthread_mutex_lock(flow_tbl[flow_id].mux);

    flow_tbl[flow_id].cpkt = flow_tbl[flow_id].fpkt;

    pthread_mutex_unlock(flow_tbl[flow_id].mux);

    return 0;
}


int FlowSetTimeOut(int flow_id, long ms)
{
    FlowTblLock();

    flow_tbl[flow_id].get_to = ms;

    FlowTblUnlock();

    return 0;
}


int FlowPutPkt(int flow_id, packet *pkt)
{
    struct timeval tpkt;

    pthread_mutex_lock(flow_tbl[flow_id].mux);

    if (flow_tbl[flow_id].pkt_q != NULL) {
        flow_tbl[flow_id].pkt_q->next = pkt;
        flow_tbl[flow_id].pkt_q = pkt;
    }
    else {
        flow_tbl[flow_id].pkt_q = pkt;
        flow_tbl[flow_id].fpkt = pkt;
        flow_tbl[flow_id].cpkt = pkt;
        flow_tbl[flow_id].time = pkt->cap_sec;
        flow_tbl[flow_id].ustime = pkt->cap_usec;
        /* wakeup group in wait */
        if (flow_tbl[flow_id].grp_fuse == TRUE && flow_tbl[flow_id].grp_id != -1) {
            /* time of next patcket of this flow */
            tpkt.tv_sec = pkt->cap_sec;
            tpkt.tv_usec = pkt->cap_usec;
            GrpNewPkt(flow_tbl[flow_id].grp_id, flow_tbl[flow_id].gref, &tpkt);
        }
    }
    flow_tbl[flow_id].ins_time = pkt->cap_sec;
    flow_tbl[flow_id].ins_ustime = pkt->cap_usec;
    flow_tbl[flow_id].pkt_num++;
#ifdef XPL_PEDANTIC_STATISTICS
    flow_tbl[flow_id].pkt_tot++;
#endif

#ifdef XPL_CHECK_CODE
    if (pkt->len > pkt->raw_len && pkt->raw != NULL) {
        LogPrintf(LV_OOPS, "Data dimension error raw:%lu data:%lu", pkt->raw_len, pkt->len);
        ProtStackFrmDisp(pkt->stk, TRUE);
    }
#endif
    /* wakeup flow in wait */
    pthread_cond_signal(flow_tbl[flow_id].cond);
    
    /* if group with syncronization from flows, wait pkt elaboration */
    if (flow_tbl[flow_id].sync && flow_tbl[flow_id].elab == TRUE) {
        /* group of flows */
        pthread_cond_wait(flow_tbl[flow_id].gcond, flow_tbl[flow_id].mux);
    }
    pthread_mutex_unlock(flow_tbl[flow_id].mux);

    return 0;
}


unsigned long FlowPktNum(int flow_id)
{
    unsigned long ret;

    pthread_mutex_lock(flow_tbl[flow_id].mux);

    ret = flow_tbl[flow_id].pkt_num;

    pthread_mutex_unlock(flow_tbl[flow_id].mux);

    return ret;
}


bool FlowIsClose(int flow_id)
{
    bool ret;

    FlowTblLock();

    ret = flow_tbl[flow_id].close;

    FlowTblUnlock();

    return ret;
}


bool FlowGrpIsEmpty(int flow_id)
{
    bool ret;

    FlowTblLock();
    
    /* with or without group */
    if (flow_tbl[flow_id].grp_id != -1) {
        ret = GrpIsEmpty(flow_tbl[flow_id].grp_id);
    }
    else {
        ret = FlowIsEmpty(flow_id);
    }
    
    FlowTblUnlock();

    return ret;
}


bool FlowGrpIsClose(int flow_id)
{
    bool ret;

    FlowTblLock();
    
    /* with or without group */
    if (flow_tbl[flow_id].grp_id != -1) {
        ret = GrpIsClose(flow_tbl[flow_id].grp_id);
    }
    else {
        ret = FlowIsClose(flow_id);
    }
    
    FlowTblUnlock();

    return ret;
}


int FlowAddToGrp(int flow_id, int new_flow)
{
    FlowTblLock();
    
    GrpAdd(flow_tbl[flow_id].grp_id, new_flow);

    FlowTblUnlock();

    return 0;
}


int FlowGrpId(int flow_id)
{
    int id;

    FlowTblLock();

    id = flow_tbl[flow_id].grp_id;

    FlowTblUnlock();
    
    return id;
}


int FlowGrpSet(int flow_id, int gflow_id)
{
    FlowTblLock();

    flow_tbl[flow_id].grp_id = gflow_id;

    FlowTblUnlock();

    return 0;
}


int FlowGrpFuse(int flow_id, bool fuse, int gref)
{
    struct timeval tpkt;

    FlowTblLock();

    flow_tbl[flow_id].grp_fuse = fuse;
    flow_tbl[flow_id].gref = gref;

    FlowTblUnlock();

    if (fuse == TRUE) {
        pthread_mutex_lock(flow_tbl[flow_id].mux);
        if (flow_tbl[flow_id].fpkt != NULL) {
            /* time of next patcket of this flow */
            tpkt.tv_sec = flow_tbl[flow_id].fpkt->cap_sec;
            tpkt.tv_usec = flow_tbl[flow_id].fpkt->cap_usec;
            GrpNewPkt(flow_tbl[flow_id].grp_id, gref, &tpkt); /* to grp_id value see GrpAdd */
        }
        pthread_mutex_unlock(flow_tbl[flow_id].mux);
    }

    return 0;
}


int FlowGrpElab(int flow_id, int fthd_id)
{
    FlowTblLock();

    flow_tbl[flow_id].elab = TRUE;
    flow_tbl[flow_id].fthd_id = fthd_id;

    FlowTblUnlock();

    return 0;
}


int FlowGrpCreate(int flow_id)
{
    int grp_id;
    
    FlowTblLock();

    grp_id = GrpCreate(flow_id);
    if (grp_id == -1) {
        LogPrintf(LV_ERROR, "Unable to create group");
        FlowTblUnlock();
        
        return -1;
    }
    flow_tbl[flow_id].grp_id = grp_id;

    /* by default sync at only for main flow (first flow) */
    flow_tbl[flow_id].sync = TRUE;

    FlowTblUnlock();

    return 0;
}


void FlowCreateSync(int flow_id, pthread_mutex_t *fthd_sync_mux)
{
    /* if the flow is in packet syncronization the we wait the first packet read */
    pthread_mutex_lock(flow_tbl[flow_id].mux);
    pthread_mutex_unlock(fthd_sync_mux);
    if (flow_tbl[flow_id].sync == TRUE) {
#warning "dead lock with FlowClose (delete next line)"
        if (flow_tbl[flow_id].close == FALSE) /* this line avoid the dead lock but it is not correct */
            pthread_cond_wait(flow_tbl[flow_id].gcond, flow_tbl[flow_id].mux);
    }
    pthread_mutex_unlock(flow_tbl[flow_id].mux);
}


pstack_f *FlowGrpStack(int gflow_id)
{
    pstack_f *ret;

    FlowTblLock();
    
    ret = GrpStack(gflow_id);

    FlowTblUnlock();

    return ret;
}


int FlowSyncr(int flow_id, bool sync)
{
    FlowTblLock();

    flow_tbl[flow_id].sync = sync;

    FlowTblUnlock();

    if (sync == FALSE) {
        pthread_mutex_lock(flow_tbl[flow_id].mux);
        pthread_cond_signal(flow_tbl[flow_id].gcond);
        pthread_mutex_unlock(flow_tbl[flow_id].mux);
    }

    return 0;
}


bool FlowIsEmpty(int flow_id)
{
    bool ret;

    FlowTblLock();
    
    if (flow_tbl[flow_id].close == TRUE && flow_tbl[flow_id].fpkt == NULL) {
        ret = TRUE;
    }
    else {
        ret = FALSE;
    }
    
    FlowTblUnlock();

    return ret;
}


int FlowSetElab(int flow_id, int fthd_id)
{
    FlowTblLock();

#ifdef XPL_CHECK_CODE
    if (flow_tbl[flow_id].elab == TRUE) {
        LogPrintf(LV_OOPS, "flow (%s) alrady in elaboration.", flow_tbl[flow_id].name);
        ProtStackFrmDisp(flow_tbl[flow_id].stack, TRUE);
    }
#endif

    /* set to elab all flow of group */
    if (flow_tbl[flow_id].grp_id != -1) {
        GrpElab(flow_tbl[flow_id].grp_id, fthd_id, flow_id);
    }
    else {
        flow_tbl[flow_id].elab = TRUE;
        flow_tbl[flow_id].fthd_id = fthd_id;
    }

    FlowTblUnlock();

    return 0;
}


int FlowThreadId(int flow_id)
{
    int id;

    FlowTblLock();

    id = flow_tbl[flow_id].fthd_id;

    FlowTblUnlock();
    
    return id;
}


bool FlowCallSubDis(int flow_id, bool state)
{
    bool ret;
    
    ret = flow_tbl[flow_id].dis;
    flow_tbl[flow_id].dis = state;
    
    return ret;
}


int FlowSetName(int flow_id, int prot_id)
{
    FlowTblLock();

#ifdef XPL_CHECK_CODE
    if (flow_tbl[flow_id].name[0] != '\0') {
        LogPrintf(LV_OOPS, "flow (%d) have alrady a name (%s).", flow_id, flow_tbl[flow_id].name);
        ProtStackFrmDisp(flow_tbl[flow_id].stack, TRUE);
    }
#endif

    sprintf(flow_tbl[flow_id].name, "%s_%d", prot_tbl[prot_id].name, flow_id);
    flow_tbl[flow_id].proto_id = prot_id;

    FlowTblUnlock();

    return 0;
}

const char* FlowName(int flow_id)
{
    return flow_tbl[flow_id].name;
}



bool FlowInElabor(int flow_id)
{
    bool ret;

    FlowTblLock();

    ret = flow_tbl[flow_id].elab;

    FlowTblUnlock();

    return ret;
}


int FlowSearch(pstack_f *stk)
{
    return ProtStackSearchNode(stk);
}


void* FlowPrivGet(int flow_id)
{    
    return flow_tbl[flow_id].priv_data;
}


int FlowPrivPut(int flow_id, void *data)
{
    flow_tbl[flow_id].priv_data = data;
    return 0;
}


void *FlowNodePrivGet(int flow_id)
{
    return flow_tbl[flow_id].priv_data_pn;
}


int FlowNodePrivPut(int flow_id, void *data)
{
    flow_tbl[flow_id].priv_data_pn = data;
    return 0;
}


int FlowSetGblTime(time_t ftm)
{
    gbl_time = ftm;
    
    return 0;
}


time_t FlowGetGblTime(void)
{
    return gbl_time;
}


time_t FlowTime(int flow_id)
{
    unsigned long ret;

    FlowTblLock();

    ret = flow_tbl[flow_id].time;
    
    FlowTblUnlock();

    return ret;
}


unsigned long FlowTimeQ(int flow_id)
{
    unsigned long ret;

    FlowTblLock();

    ret = flow_tbl[flow_id].ins_time;
    
    FlowTblUnlock();

    return ret;
}


unsigned long FlowNumber(void)
{
    unsigned long ret;
#ifdef XPL_CHECK_CODE
    int i, cnt, base, closed;
#endif

    FlowTblLock();

    ret = flow_num;
#ifdef XPL_CHECK_CODE
    /* it is atomic and so also ProtOpenFlow in this case */
    if (ret != ProtOpenFlow()) {
        cnt = 0;
        base = flow_num;
        closed = 0;
        for (i=0; i<tbl_dim && cnt<base; i++) {
            if (flow_tbl[i].stack != NULL) {
                cnt++;
                if (flow_tbl[i].close)
                    closed++;
            }
        }
        if (flow_num != cnt) {
            LogPrintf(LV_OOPS, "Number of flows (%d) isn't the same of the sum of flows (%d)!", flow_num, cnt);
            printf("Number of flows (%lu) isn't the same of the sum of flows (%d)!\n", flow_num, cnt);
            exit(-1);
        }
        else
            LogPrintf(LV_INFO, "Flows running: %i closed: %i", cnt, closed);
    }
#endif

    FlowTblUnlock();

    return ret;
}


unsigned long FlowTblDim(void)
{
    return tbl_dim;
}


int FlowProt(int flow_id)
{
    int prot;

    FlowTblLock();
    
    prot = flow_tbl[flow_id].proto_id;
    
    FlowTblUnlock();

    return prot;
}


/* these functions should not be used */
void FlowDebOpen(void)
{
    int i;

    for (i=0; i!=tbl_dim; i++) {
        if (flow_tbl[i].stack != NULL) {
            LogPrintf(LV_DEBUG, "open flow: %i", i);
            LogPrintf(LV_DEBUG, "\t name: %s", flow_tbl[i].name);
            LogPrintf(LV_DEBUG, "\t proto: %i", flow_tbl[i].proto_id);
            LogPrintf(LV_DEBUG, "\t elab: %i", flow_tbl[i].elab);
            LogPrintf(LV_DEBUG, "\t sync: %i", flow_tbl[i].sync);
            LogPrintf(LV_DEBUG, "\t fthd: %i", flow_tbl[i].fthd_id);
            LogPrintf(LV_DEBUG, "\t grp: %i", flow_tbl[i].grp_id);
            ProtStackFrmDisp(flow_tbl[i].stack, TRUE);
        }
    }
}


/* these functions should not be used */
const pstack_f *FlowNxtStack(int pre_id, int *flow_id)
{
    pstack_f *res;
    int i;
    
    res = NULL;
    if (pre_id < 0) {
        pre_id = 0;
    }
    else {
        pre_id++;
    }
    for (i=pre_id; i!=tbl_dim; i++) {
        if (flow_tbl[i].stack != NULL) {
            res = flow_tbl[i].stack;
            if (flow_id != NULL)
                *flow_id = i;
            break;
        }
    }

    return res;
}


void FlowLoopLog(void)
{
    int i;

    for (i=0; i!=tbl_dim; i++) {
        if (flow_tbl[i].stack != NULL) {
            LogPrintfStack(LV_ERROR, flow_tbl[i].stack, "Flow n %i in loop", i);
        }
    }
}
