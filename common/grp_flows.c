/* grp_flows.c
 * Group flows core functions
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

#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "flow.h"
#include "grp_flows.h"
#include "log.h"
#include "dmemory.h"
#include "proto.h"


/** internal variables */
static gflow *volatile gflow_tbl;          /* table of group flows... all group flows */
static volatile unsigned long gtbl_dim;    /* dimension of table */
static volatile unsigned long gflow_num;   /* number of open group flows */
static pthread_mutex_t gflow_mux;          /* mutex to access atomicly the tbl */


static int GrpElemInit(gflow *gflw, bool reset)
{
    int i;

    gflw->fuse = FALSE;
    gflw->sync = FALSE;
    gflw->elab = FALSE;
    gflw->fthd_id = -1;
    gflw->flow_ref = -1;
    gflw->fnum = 0;
    gflw->read = -1;
    gflw->last_read = 0;
    for (i=0; i!=GRPFW_GROUP_DIM; i++) {
        gflw->flow_list[i] = -1;
        gflw->flow_new[i] = FALSE;
        gflw->time[i].tv_sec = ULONG_MAX;
        gflw->time[i].tv_usec = 0;
    }
    if (reset == FALSE) {
        /* allocate mutex and inizialize it */
        gflw->mux = xmalloc(sizeof(pthread_mutex_t));
        pthread_mutex_init(gflw->mux, NULL);
        gflw->cond = xmalloc(sizeof(pthread_cond_t));
        pthread_cond_init(gflw->cond, NULL);
    }

    return 0;
}


static int GrpTblExtend(void)
{
    unsigned long i, len;
    gflow *new;

    len = gtbl_dim + GRPFW_TBL_ELEMENT_DELTA;

    /* lock all mutex */
    for (i=0; i<gtbl_dim; i++) {
        pthread_mutex_lock(gflow_tbl[i].mux);
    }

    /* extend memory(copy) */
    new = xrealloc(gflow_tbl, sizeof(gflow)*(len));
    if (new == NULL)
        return -1;
    
    /* initialize new elements */
    for (i=gtbl_dim; i<len; i++) {
        memset(&new[i], 0, sizeof(gflow));
        GrpElemInit(&(new[i]), FALSE);
    }

    gflow_tbl = new;
    /* unlock all mutex */
    for (i=0; i<gtbl_dim; i++) {
        pthread_mutex_unlock(gflow_tbl[i].mux);
    }
    gtbl_dim = len;

    return 0;
}


int GrpInit(void)
{
    gflow_tbl = NULL;
    gtbl_dim = 0;
    gflow_num = 0;

    /* base group flows tbl */
    if (GrpTblExtend() == -1) {
        LogPrintf(LV_ERROR, "Unable to inizialie group flows data table");
        return -1;
    }
    pthread_mutex_init(&gflow_mux, NULL);

    return 0;
}


int GrpCreate(int flow_id)
{
    int i, ret;

    pthread_mutex_lock(&gflow_mux);

    /* search empty descriptor */
    for (i=0; i!=gtbl_dim; i++) {
        if (gflow_tbl[i].fnum == 0) {
            break;
        }
    }
    if (i == gtbl_dim) {
        ret = GrpTblExtend();
        if (ret == -1) {
            LogPrintf(LV_ERROR, "Unable to extend group data table");
            pthread_mutex_unlock(&gflow_mux);
            return -1;
        }
    }
    
    GrpElemInit(&gflow_tbl[i], TRUE);
    gflow_tbl[i].fnum++;
    gflow_tbl[i].flow_list[0] = flow_id;
    gflow_tbl[i].flow_new[0] = TRUE;
    FlowGrpSet(flow_id, i);
    gflow_num++;

    pthread_mutex_unlock(&gflow_mux);

    return i;
}


int GrpAdd(int gflow_id, int flow_id)
{
    int i;

    pthread_mutex_lock(&gflow_mux);
    
    for (i=0; i!=GRPFW_GROUP_DIM; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] == -1) {
            break;
        }
    }

#ifdef XPL_CHECK_CODE
    if (gflow_id == -1) {
        LogPrintf(LV_OOPS, "Bug in a dissector: enable group: ProtGrpEnable (%s:%i)", __FILE__, __LINE__);
        exit(-1);
    }
    if (i == GRPFW_GROUP_DIM) {
        LogPrintf(LV_OOPS, "Increment (max exceeded) flow group list  (%s:%i)", __FILE__, __LINE__);
        exit(-1);
    }
#endif

    gflow_tbl[gflow_id].flow_list[i] = flow_id;
    gflow_tbl[gflow_id].flow_new[i] = TRUE;
    FlowGrpSet(flow_id, gflow_id); /* Must to be before FlowGrpFuse */
    if (gflow_tbl[gflow_id].fuse == TRUE) {
        FlowGrpFuse(flow_id, gflow_tbl[gflow_id].fuse, i);
    }
    /*
    else {
        FlowGrpFuse(flow_id, gflow_tbl[gflow_id].fuse, -1);
    }
    */
    FlowSyncr(flow_id, gflow_tbl[gflow_id].sync);
    if (gflow_tbl[gflow_id].elab == TRUE) {
        FlowGrpElab(flow_id, gflow_tbl[gflow_id].fthd_id);
    }
    gflow_tbl[gflow_id].fnum++;

    pthread_mutex_unlock(&gflow_mux);

    return 0;
}


int GrpFuse(int gflow_id, bool fuse)
{
    int i, j;

    pthread_mutex_lock(&gflow_mux);

    j = 0;
    for (i=0; j!=gflow_tbl[gflow_id].fnum; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            if (fuse == TRUE) {
                FlowGrpFuse(gflow_tbl[gflow_id].flow_list[i], fuse, i);
            }
            else {
                FlowGrpFuse(gflow_tbl[gflow_id].flow_list[i], fuse, -1);
                gflow_tbl[gflow_id].time[i].tv_sec = ULONG_MAX;
            }
            j++;
        }
    }
    gflow_tbl[gflow_id].fuse = fuse;

    pthread_mutex_unlock(&gflow_mux);

    return 0;
}


int GrpSyncr(int gflow_id, bool sync)
{
    int i, j;

    pthread_mutex_lock(&gflow_mux);

    j = 0;
    for (i=0; j!=gflow_tbl[gflow_id].fnum; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            FlowSyncr(gflow_tbl[gflow_id].flow_list[i], sync);
            j++;
        }
    }
    gflow_tbl[gflow_id].sync = sync;

    pthread_mutex_unlock(&gflow_mux);

    return 0;
}


int GrpElab(int gflow_id, int fthd_id, int flow_id)
{
    int i, j;

    pthread_mutex_lock(&gflow_mux);

    j = 0;
    for (i=0; j!=gflow_tbl[gflow_id].fnum; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            if (gflow_tbl[gflow_id].flow_list[i] == flow_id) {
                gflow_tbl[gflow_id].flow_new[i] = FALSE;
            }
            FlowGrpElab(gflow_tbl[gflow_id].flow_list[i], fthd_id);
            j++;
        }
    }
    gflow_tbl[gflow_id].elab = TRUE;
    gflow_tbl[gflow_id].fthd_id = fthd_id;

    pthread_mutex_unlock(&gflow_mux);
    
    return 0;
}


int GrpLink(int gflow_id)
{
    int i, j, fid;
    
    pthread_mutex_lock(&gflow_mux);

    fid = -1;
    j = 0;
    for (i=0; j!=gflow_tbl[gflow_id].fnum; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            if (gflow_tbl[gflow_id].flow_new[i] == TRUE) {
                fid = gflow_tbl[gflow_id].flow_list[i];
                gflow_tbl[gflow_id].flow_new[i] = FALSE;
                break;
            }
            j++;
        }
    }
    
    pthread_mutex_unlock(&gflow_mux);
    
    return fid;
}


int GrpRm(int gflow_id, int flow_id)
{
    int i;

    pthread_mutex_lock(&gflow_mux);

    for (i=0; i!=GRPFW_GROUP_DIM; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] == flow_id) {
            gflow_tbl[gflow_id].flow_list[i] = -1;
            gflow_tbl[gflow_id].fnum--;
            FlowGrpFuse(flow_id, FALSE, -1);
            FlowGrpSet(flow_id , -1);
            break;
        }
    }

#ifdef XPL_CHECK_CODE
    if (i == GRPFW_GROUP_DIM) {
         LogPrintf(LV_OOPS, "Group bug (%s:%i)", __FILE__, __LINE__);
         exit(-1);
    }
#endif

    if (gflow_tbl[gflow_id].fnum == 0) {
        GrpElemInit(&gflow_tbl[gflow_id], TRUE);
        gflow_num--;
    }

    pthread_mutex_unlock(&gflow_mux);

    return 0;
}


void GrpFlowClosed(int gflow_id)
{
    pthread_mutex_lock(gflow_tbl[gflow_id].mux);

    /* wakeup  GrpWaitPkt */
    pthread_cond_signal(gflow_tbl[gflow_id].cond);

    pthread_mutex_unlock(gflow_tbl[gflow_id].mux);
}


int GrpNewPkt(int gflow_id, int gref, const struct timeval *tpkt)
{
#ifdef XPL_CHECK_CODE
    if (gref == -1) {
        LogPrintf(LV_OOPS, "Group bug (%s:%i): id reference error", __FILE__, __LINE__);
        exit(-1);
    }
#endif

    pthread_mutex_lock(gflow_tbl[gflow_id].mux);

#ifdef XPL_CHECK_CODE
    if (gflow_tbl[gflow_id].time[gref].tv_sec != ULONG_MAX) {
        LogPrintf(LV_OOPS, "Group bug (%s:%i): pkt time error", __FILE__, __LINE__);
        exit(-1);
    }
#endif

    gflow_tbl[gflow_id].time[gref].tv_sec = tpkt->tv_sec;
    gflow_tbl[gflow_id].time[gref].tv_usec = tpkt->tv_usec;

    /* wakeup GrpWaitPkt */
    pthread_cond_signal(gflow_tbl[gflow_id].cond);

    pthread_mutex_unlock(gflow_tbl[gflow_id].mux);
    
    return 0;
}


int GrpWaitPkt(int gflow_id, int gref)
{
    int ref, ret;
    int i, j;
    bool end;
    struct timeval tm;

#ifdef XPL_CHECK_CODE
    if (gref == -1) {
        LogPrintf(LV_OOPS, "Group bug (%s:%i)", __FILE__, __LINE__);
        exit(-1);
    }
#endif
    ret = 0;
    end = FALSE;

    pthread_mutex_lock(gflow_tbl[gflow_id].mux);

    ref = gflow_tbl[gflow_id].flow_ref;
    while (ref == -1 && end == FALSE) {
        j = 0;
        end = TRUE;
        tm.tv_sec = ULONG_MAX;
        tm.tv_usec = 0;
        for (i=0; j!=gflow_tbl[gflow_id].fnum; i++) {
            if (gflow_tbl[gflow_id].flow_list[i] != -1) {
                if (gflow_tbl[gflow_id].time[i].tv_sec < tm.tv_sec) {
                    tm.tv_sec = gflow_tbl[gflow_id].time[i].tv_sec;
                    tm.tv_usec = gflow_tbl[gflow_id].time[i].tv_usec;
                    ref = i;
                }
                else if (gflow_tbl[gflow_id].time[i].tv_sec < tm.tv_sec && gflow_tbl[gflow_id].time[i].tv_usec < tm.tv_usec) {
                    tm.tv_sec = gflow_tbl[gflow_id].time[i].tv_sec;
                    tm.tv_usec = gflow_tbl[gflow_id].time[i].tv_usec;
                    ref = i;
                }
                
                if (end == TRUE)
                    end = FlowIsClose(gflow_tbl[gflow_id].flow_list[i]);
                j++;
            }
        }
        if (ref == -1 && end == FALSE) {
            pthread_cond_wait(gflow_tbl[gflow_id].cond, gflow_tbl[gflow_id].mux);
        }
        /* new packet in new reference (-1 it is possible) */
        gflow_tbl[gflow_id].flow_ref = ref;
    }

    if (ref == gref) {
        gflow_tbl[gflow_id].time[ref].tv_sec = ULONG_MAX;
        gflow_tbl[gflow_id].flow_ref = -1;
        ret = 1;
    }
    
    pthread_mutex_unlock(gflow_tbl[gflow_id].mux);

    return ret;
}


bool GrpIsEmpty(int gflow_id)
{
    int i, j;
    bool ret = TRUE;

    pthread_mutex_lock(&gflow_mux);

#ifdef XPL_CHECK_CODE
    if (gflow_tbl[gflow_id].fnum == 0) {
        LogPrintf(LV_OOPS, "Group bug (%s:%i)", __FILE__, __LINE__);
        exit(-1);
    }
#endif

    j = 0;
    for (i=0; (j!=gflow_tbl[gflow_id].fnum && ret == TRUE); i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            ret = FlowIsEmpty(gflow_tbl[gflow_id].flow_list[i]);
            j++;
        }
    }

    pthread_mutex_unlock(&gflow_mux);

    return ret;
}


bool GrpIsClose(int gflow_id)
{
    int i, j;
    bool ret = TRUE;

    pthread_mutex_lock(&gflow_mux);

#ifdef XPL_CHECK_CODE
    if (gflow_tbl[gflow_id].fnum == 0) {
        LogPrintf(LV_OOPS, "Group bug (%s:%i)", __FILE__, __LINE__);
        exit(-1);
    }
#endif

    j = 0;
    for (i=0; (j!=gflow_tbl[gflow_id].fnum && ret == TRUE); i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            ret = FlowIsClose(gflow_tbl[gflow_id].flow_list[i]);
            j++;
        }
    }

    pthread_mutex_unlock(&gflow_mux);

    return ret;
}


int GrpFlowNum(int gflow_id)
{
    int ret;

    pthread_mutex_lock(&gflow_mux);

    ret = gflow_tbl[gflow_id].fnum;
    pthread_mutex_unlock(&gflow_mux);
    
    return ret;
}


int GrpLock(int gflow_id)
{
    pthread_mutex_lock(&gflow_mux);

    gflow_tbl[gflow_id].read = 0;
    gflow_tbl[gflow_id].last_read = gflow_tbl[gflow_id].fnum;

    return 0;
}


int GrpNext(int gflow_id)
{
    int i, ret;

    ret = -1;
    /* this function must be used after GrpLock */
#ifdef XPL_CHECK_CODE
    if (gflow_tbl[gflow_id].read == -1) {
        LogPrintf(LV_OOPS, "Group bug (%s:%i)", __FILE__, __LINE__);
        return ret;
    }
#endif
    
    for (i=gflow_tbl[gflow_id].read; gflow_tbl[gflow_id].last_read != 0; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            gflow_tbl[gflow_id].read = i + 1;
            gflow_tbl[gflow_id].last_read--;
            ret = gflow_tbl[gflow_id].flow_list[i];
            break;
        }
    }

    return ret;
}


int GrpUnlock(int gflow_id)
{
    gflow_tbl[gflow_id].read = -1;
    gflow_tbl[gflow_id].last_read = 0;
    pthread_mutex_unlock(&gflow_mux);

    return 0;
}


pstack_f *GrpStack(int gflow_id)
{
    pstack_f *stack, *nxt;
    int i, j;

    stack = NULL;
    nxt = NULL;
    pthread_mutex_lock(&gflow_mux);

    j = 0;
    for (i=0; j!=gflow_tbl[gflow_id].fnum; i++) {
        if (gflow_tbl[gflow_id].flow_list[i] != -1) {
            j++;
            if (nxt == NULL) {
                nxt = ProtCopyFrame(FlowStack(gflow_tbl[gflow_id].flow_list[i]), TRUE);
                stack = nxt;
                while (nxt->gstack != NULL)
                    nxt = nxt->gstack;
            }
            else {
                nxt->gstack = ProtCopyFrame(FlowStack(gflow_tbl[gflow_id].flow_list[i]), TRUE);
                nxt = nxt->gstack;
                while (nxt->gstack != NULL)
                    nxt = nxt->gstack;
            }
        }
    }

    pthread_mutex_unlock(&gflow_mux);
    
    return stack;
}



int GrpStatus(void)
{
    printf("Groups: %lu/%lu\n", gflow_num, gtbl_dim);

    return 0;
}
