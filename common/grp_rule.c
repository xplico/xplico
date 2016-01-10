/* grp_rule.c
 * manager rule to aggregate flow in group
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

#include <string.h>
#include <pthread.h>
#include <stdarg.h>

#include "grp_rule.h"
#include "dmemory.h"
#include "log.h"
#include "proto.h"


/** internal variables */
static rule_mng *volatile grule_tbl;          /* rule table*/
static volatile unsigned long tbl_dim;        /* dimension of table */
static volatile unsigned long tbl_num;        /* number of open group flows */
static pthread_mutex_t grule_mux;             /* mutex to access atomicly the tbl */
static volatile pthread_t rptrd_lock;         /* ptread that lock access */
static short rnesting;                        /* lock nesting */
static int prot_rid[GRP_RULE_PROT][GRP_RULE_PROT+2]; /* used in GrpRuleCmplt */

static int GrpRuleElem(rule_mng *grule, bool reset)
{
    int i, j;

    grule->active = FALSE;
    if (reset == TRUE) {
        for (i=0; i!=grule->rule.num; i++) {
            for (j=0; j!= grule->rule.or[i].num; j++) {
                FTFree(&(grule->rule.or[i].and[j].val), grule->rule.or[i].and[j].type);
            }
            xfree(grule->rule.or[i].and);
        }
        xfree(grule->rule.or);
    }
    grule->rule.or = NULL;
    grule->rule.num = 0;
#ifdef XPL_CHECK_CODE
    if (reset == TRUE && grule->flow_id != -1) {
        LogPrintf(LV_OOPS, "Bug in protocol rule (%s:%i)", __FILE__, __LINE__);
    }
#endif
    grule->flow_id = -1;
    for (i=0; i!=GRP_RULE_PROT; i++) {
        grule->prot[i] = -1;
    }

    return 0;
}


static int GrpTblExtend(void)
{
    unsigned long i, len;
    rule_mng *new;

    len = tbl_dim + GRP_RULE_TBL_ELEMENT_DELTA;

    /* extend memory(copy) */
    new = xrealloc(grule_tbl, sizeof(rule_mng)*(len));
    if (new == NULL)
        return -1;
    
    /* initialize new elements */
    for (i=tbl_dim; i<len; i++) {
        memset(&new[i], 0, sizeof(rule_mng));
        GrpRuleElem(&(new[i]), FALSE);
    }

    grule_tbl = new;

    tbl_dim = len;

    return 0;
}


static inline void GrpTblLock(void)
{
    if (pthread_mutex_trylock(&grule_mux) != 0) {
        if (rptrd_lock != pthread_self()) {
            pthread_mutex_lock(&grule_mux);
        }
    }
    rptrd_lock = pthread_self();
    rnesting++;
}


static inline void GrpTblUnlock(void)
{
    rnesting--;
    if (rnesting == 0) {
        rptrd_lock = 0;
        pthread_mutex_unlock(&grule_mux);
    }
}


int GrpRuleInit(void)
{
    grule_tbl = NULL;
    tbl_dim = 0;
    tbl_num = 0;
    rptrd_lock = 0;
    rnesting = 0;

    /* base rule tbl */
    if (GrpTblExtend() == -1) {
        LogPrintf(LV_ERROR, "Unable to inizialie rules data table");
        return -1;
    }
    pthread_mutex_init(&grule_mux, NULL);

    return 0;
}


int GrpRuleNew(int flow_id)
{
    int i, j;

    GrpTblLock();

    if (tbl_dim == tbl_num) {
        if (GrpTblExtend() != 0) {
            LogPrintf(LV_ERROR, "Unable to extend rules data table");
            GrpTblUnlock();
            
            return -1;
        }
        i = tbl_num;
    }
    else {
        j = 0;
        for (i=0; j!=tbl_num; i++) {
            if (grule_tbl[i].flow_id == -1) {
                break;
            }
            j++; /* inutile come il controllo del for (se non ci sono bug :)) */
        }
    }
    
    grule_tbl[i].flow_id = flow_id;
    tbl_num++;

    GrpTblUnlock();

    return i;
}


int GrpRule(int id, short vnum, cmp_val *val, ...)
{
    va_list argptr;
    and_rule *or;
    short num, i;
    cmp_val *vcp;
    enum ftype type;

    GrpTblLock();
    
    if (grule_tbl[id].active == TRUE) {
        GrpTblUnlock();

        return -1;
    }

    num = grule_tbl[id].rule.num + 1;
    or = xrealloc(grule_tbl[id].rule.or, sizeof(and_rule)*num);
    if (or == NULL) {
        GrpTblUnlock();
        LogPrintf(LV_ERROR, "Memory finished (fun:%s)", __FUNCTION__);

        return -1;
    }
    grule_tbl[id].rule.num = num;
    grule_tbl[id].rule.or = or;

    GrpTblUnlock();

    num--;
    or[num].and = xmalloc(sizeof(cmp_elem)*vnum);
    or[num].num = vnum;

    i = 0;
    or[num].and[i].prot = val->prot;
    or[num].and[i].att = val->att;
    type = ProtAttrType(val->prot, val->att);
    or[num].and[i].type = type;
    or[num].and[i].op = FT_OP_EQ;
    FTCopy(&(or[num].and[i].val), &val->val, type);
    i++;
    va_start(argptr, val);
    for (; i!=vnum; i++) {
        vcp = va_arg(argptr, cmp_val *);
        or[num].and[i].prot = vcp->prot;
        or[num].and[i].att = vcp->att;
        type = ProtAttrType(vcp->prot, vcp->att);
        or[num].and[i].type = type;
        or[num].and[i].op = FT_OP_EQ;
        FTCopy(&(or[num].and[i].val), &vcp->val, type);
    }
    va_end(argptr);

    return 0;
}


int GrpRuleCmplt(int id)
{
    int i, j, k, ret;
    int max_or;
    grp_rule rule;

    /* 
       prot_rid[i][j] : protocol list 
       prot_rid[i][0] => protocol id (if != -1)
       prot_rid[i][1] => number of 'or' element
       prot_rid[i][2] - prot_rid[i][prot_rid[i][1]+1] => 'or' element in rules for this protocol
    */
    ret = -1;

    GrpTblLock();

    for (i=0; i!=GRP_RULE_PROT; i++) {
        prot_rid[i][0] = -1;
    }

    if (grule_tbl[id].flow_id != -1) {
        max_or = 0;
        /* find protocol node and their rule */
        for (i=0; i!=grule_tbl[id].rule.num; i++) {
            for (j=0; j!=grule_tbl[id].rule.or[i].num; j++) {
                if (ProtIsNode(grule_tbl[id].rule.or[i].and[j].prot) == TRUE) {
                    k = 0;
                    while (prot_rid[k][0] != -1 && prot_rid[k][0] != grule_tbl[id].rule.or[i].and[j].prot)
                        k++;
                    if (k == GRP_RULE_PROT-1) {
                         LogPrintf(LV_FATAL, "Increase GRP_RULE_PROT value!");
                         exit(-1);
                    }
                    if (prot_rid[k][0] != -1) {
                        prot_rid[k][prot_rid[k][1]+2] = i;
                        prot_rid[k][1]++;
                        if (max_or < prot_rid[k][1])
                            max_or = prot_rid[k][1];
                    }
                    else {
                        prot_rid[k][0] = grule_tbl[id].rule.or[i].and[j].prot;
                        prot_rid[k][2] = i;
                        prot_rid[k][1] = 1;
                    }
                }
            }
        }
        /* composing protocol rule */
        i = 0;
        rule.or = xmalloc(sizeof(and_rule)*max_or);
        while (prot_rid[i][0] != -1) {
            rule.num = prot_rid[i][1];
            for (j=0; j!=rule.num; j++) {
                rule.or[j].and = grule_tbl[id].rule.or[prot_rid[i][j+2]].and;
                rule.or[j].num = grule_tbl[id].rule.or[prot_rid[i][j+2]].num;
            }
            grule_tbl[id].prot[i] = prot_rid[i][0];
            ProtGrpRuleIns(prot_rid[i][0], id, &rule);
            i++;
        }
        xfree(rule.or);
        grule_tbl[id].active = TRUE;

        ret = 0;
    }

    GrpTblUnlock();

    return ret;
}


int GrpRuleFlowId(int id)
{
    int fid;

    GrpTblLock();

    fid = grule_tbl[id].flow_id;

    GrpTblUnlock();

    return fid;
}


int GrpRuleRm(int id)
{
    int ret, i;

    ret = -1;
    GrpTblLock();

    if (grule_tbl[id].flow_id != -1) {
        i = 0;
        while (grule_tbl[id].prot[i] != -1) {
            ProtGrpRuleRm(grule_tbl[id].prot[i], id);
            i++;
        }
        grule_tbl[id].flow_id = -1; /* equal at delete */
        GrpRuleElem(grule_tbl+id, TRUE); /* memory free after remove rule from protocols */
        tbl_num--;
        ret = 0;
    }

    GrpTblUnlock();

    return ret;
}


int GrpRuleRmAll(int flow_id)
{
    int id, j, fid;
    
    id = j = 0;

    GrpTblLock();
    
    fid = grule_tbl[id].flow_id;
    if (fid != -1)
        j++;
    while (j != tbl_num && fid != flow_id) {
        id++;
        fid = grule_tbl[id].flow_id;
        if (fid != -1)
            j++;
    }
    if (j != tbl_num)
        GrpRuleRm(id);

#ifdef XPL_CHECK_CODE
    if (id >= tbl_dim) {
        LogPrintf(LV_OOPS, "GrpRuleRmAll send us a bug report: %i", tbl_num);
        exit(-1);
    }
#endif

    GrpTblUnlock();

    return 0;
}


bool GrpRuleCheck(const grp_rule *rule, const pstack_f *eval)
{
    int i, j;
    bool ret;
    and_rule *andr;
    cmp_elem *and;
    const pstack_f *frm;
    ftval val;

    ret = FALSE;
/*
    GrpRulePrint(rule);
    ProtStackFrmDisp(eval, TRUE);
*/

    for (i=0; i!=rule->num; i++) {
        ret = TRUE;
        andr = rule->or + i;
        for (j=0; j!=andr->num && ret == TRUE; j++) {
            and = andr->and + j;
            /* To be improved (speed) */
            frm = ProtStackSearchProt(eval, and->prot);
            if (frm != NULL) {
                if (ProtGetAttr(frm, and->att, &val) == 0) {
                    if (FTCmp(&val, &and->val, and->type, and->op, NULL) != 0) {
                        ret = FALSE;
                    }
                }
                else {
                    ret = FALSE;
                }
            }
            else
                ret = FALSE;
            /* To be improved end */
        }
        if (ret == TRUE)
            break;
    }

    return ret;
}


void GrpRulePrint(const grp_rule *rule)
{
    short i, j;
    const and_rule *and;
    const cmp_elem *elem;
    char buff[128];

    LogPrintf(LV_DEBUG, "Or items: %i", rule->num);
    for (i=0; i!=rule->num; i++) {
        LogPrintf(LV_DEBUG, "  or (%i):", i+1);
        and = rule->or + i;
        for (j=0; j!=and->num; j++) {
            elem = and->and + j;
            LogPrintf(LV_DEBUG, "    and: %s -> %s", ProtAttrName(elem->prot, elem->att), FTString(&elem->val, elem->type, buff));
        }
    }
}

