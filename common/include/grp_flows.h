/* grp_flows.h
 *
 * $Id: grp_flows.h,v 1.2 2007/06/05 17:57:12 costa Exp $
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


#ifndef __GRP_FLOW_H__
#define __GRP_FLOW_H__

#include <pthread.h>
#include <sys/time.h>

#include "flow.h"
#include "proto.h"


/* define */
#define GRPFW_GROUP_DIM           100
#define GRPFW_TBL_ELEMENT_DELTA   100


/** group flow descriptor */
typedef struct _gflow gflow;
struct _gflow {
    bool fuse;        /**< all flows in the group to be compare as the same flow time line */
    bool sync;        /**< all flows in the group are syncronizated */
    bool elab;        /**< elaboration started */
    int fthd_id;      /**< group/flow thread id */
    int flow_list[GRPFW_GROUP_DIM];       /**< flow list in the group */
    bool flow_new[GRPFW_GROUP_DIM];       /**< flow list: id requested */
    struct timeval time[GRPFW_GROUP_DIM]; /**< time of next packet in the flow */
    int flow_ref;     /**< next packet flow reference */
    int fnum;         /**< number of flow */
    int read;         /**< read list of flow index */
    int last_read;    /**< last to read */
    pthread_mutex_t *mux;  /**< mutex to access fused packet */
    pthread_cond_t *cond;  /**< condiction to access fused packet */
};


/** group flow functions */
int GrpInit(void);
int GrpCreate(int flow_id);
int GrpAdd(int gflow_id, int flow_id);
int GrpFuse(int gflow_id, bool fuse);
int GrpSyncr(int gflow_id, bool sync);
int GrpElab(int gflow_id, int fthd_id, int flow_id);
int GrpLink(int gflow_id);
int GrpRm(int gflow_id, int flow_id);
void GrpFlowClosed(int gflow_id);
int GrpNewPkt(int gflow_id, int gref, const struct timeval *tpkt);
int GrpWaitPkt(int gflow_id, int gref);
bool GrpIsEmpty(int gflow_id);
bool GrpIsClose(int gflow_id);
int GrpFlowNum(int gflow_id);
int GrpLock(int gflow_id);
int GrpNext(int gflow_id);
int GrpUnlock(int gflow_id);
pstack_f* GrpStack(int gflow_id);


#endif /* __GRP_FLOW_H__ */
