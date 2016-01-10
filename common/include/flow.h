/* flow.h
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


#ifndef __FLOW_H__
#define __FLOW_H__

#include <pthread.h>
#include <time.h>

#include "ftypes.h"
#include "istypes.h"
#include "packet.h"


/* define */
#define FLOW_MAX_GRP_RULES   20
#define FLOW_NAME_SIZE       20
#define FLOW_RULE_PKT        "pkt."

/** flow  */
typedef struct _flow_t flow;
struct _flow_t {
    int proto_id;          /**< protocol id of flow: master protocol/dissector */
    volatile bool elab;    /**< elaboration started */
    volatile int fthd_id;  /**< flow thread id */
    int pfid;              /**< parent flow id (-1 no parent) */
    volatile int son_num;  /**< number of sons */
    int grp_id;            /**< group id (-1 -> none = grp = FALSE) */
    int pgrp_id;           /**< parent group id (-1 -> none) */
    int gref;              /**< id refererence inside group (used in fuse function) */
    bool grp_fuse;         /**< all flows in the group to be compare as the same flow time line */
    bool sync;             /**< packet syncronization from flows of the same group or any*/
    pstack_f *volatile stack;   /**< flow stack */
    char name[FLOW_NAME_SIZE];  /**< flow name */
    time_t time;           /**< flow time sec in elaboration */
    time_t ustime;         /**< flow time usec in elaboration */
    time_t ins_time;       /**< flow time in sec -last packet- */
    time_t ins_ustime;     /**< flow time usec -last packet- */
    packet *volatile pkt_q;  /**< packet queue (fifo) */
    packet *volatile fpkt;   /**< first packet in queue */
    packet *volatile cpkt;   /**< cpy packet in queue for FlowGetPktCp */
    volatile bool close;     /**< input queue closed */
    long get_to;           /**< get timeout in milli-second (-1 -> no timeout) */
    pthread_mutex_t *mux;  /**< mutex to access packet queue */
    pthread_cond_t *cond;  /**< condiction to access packet queue */
    pthread_cond_t *gcond; /**< condiction to syncronization access packet queue inside group */
    volatile unsigned long pkt_num; /**< number of packet in the flow queue */
    void *priv_data_pn;    /**< private data of protocol node that generate a flow */
    void *priv_data;       /**< private data of dissector flow (main/master dissector) */
    void **priv_data_sp;   /**< private data of dissector flow (inside a main flow dissector) */
    bool dis;              /**< dissector or subdissector running for this flow */
#ifdef XPL_PEDANTIC_STATISTICS
    unsigned long pkt_tot; /**< total number of packet */
#endif
};


/** flow descriptor*/
typedef struct _cmpflow_d cmpflow;
struct _cmpflow_d {
    const pstack_f *stack;   /**< flow stack (point in to stack of flow structure) */
    void *priv;              /**< private data */
};

typedef struct _flow_d flow_d;
struct _flow_d {
    int fid;                 /**< flow id in global table flaws (-1 if free) */
    int pid;                 /**< protocol id of flow: master protocol/dissector */
    int pfid;                /**< parent flow id (-1 no parent) */
    cmpflow cmp;             /**< compare flow structure */
};


/** flow functions */
int FlowInit(void);
const pstack_f* FlowStack(int flow_id);
int FlowCreate(pstack_f *stk);
int FlowClose(int flow_id);
bool FlowCloseAll(void);
int FlowDelete(int flow_id);
int FlowDettach(int flow_id);
packet* FlowGetPkt(int flow_id);
packet* FlowGetPktCp(int flow_id);
int FlowPktCpReset(int flow_id);
int FlowSetTimeOut(int flow_id, long ms);
int FlowPutPkt(int flow_id, packet *pkt);
unsigned long FlowPktNum(int flow_id);
bool FlowIsClose(int flow_id);
bool FlowIsEmpty(int flow_id);
bool FlowGrpIsEmpty(int flow_id);
bool FlowGrpIsClose(int flow_id);
int FlowAddToGrp(int flow_id, int new_flow);
int FlowGrpId(int flow_id);
int FlowGrpSet(int flow_id, int gflow_id);
int FlowGrpFuse(int flow_id, bool fuse, int gref);
int FlowGrpElab(int flow_id, int fthd_id);
int FlowGrpCreate(int flow_id);
pstack_f* FlowGrpStack(int gflow_id);
int FlowSyncr(int flow_id, bool sync);
int FlowSetElab(int flow_id, int fthd_id);
int FlowSetName(int flow_id, int prot_id);
const char* FlowName(int flow_id);
bool FlowInElabor(int flow_id);
int FlowSearch(pstack_f *stk);
void *FlowPrivGet(int flow_id);
int FlowPrivPut(int flow_id, void *data);
void *FlowNodePrivGet(int flow_id);
int FlowNodePrivPut(int flow_id, void *data);
int FlowSetGblTime(time_t ftime);
time_t FlowGetGblTime(void);
time_t FlowTime(int flow_id);

/* private functions */
unsigned long FlowNumber(void);
int FlowThreadId(int flow_id);
bool FlowCallSubDis(int flow_id, bool state);
unsigned long FlowTimeQ(int flow_id);
unsigned long FlowTblDim(void);
int FlowProt(int flow_id);
void FlowDebOpen(void);
const pstack_f *FlowNxtStack(int pre_id, int *flow_id);
void FlowCreateSync(int flow_id, pthread_mutex_t *fthd_sync_mux);
void FlowLoopLog(void);

#endif /* __FLOW_H__ */
