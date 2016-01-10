/* proto.h
 *
 * $Id:$
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


#ifndef __PROTO_H__
#define __PROTO_H__

#include <dlfcn.h>
#include <time.h>
#include <regex.h>
#include <stdio.h>

#include "istypes.h"
#include "ftypes.h"
#include "flow.h"
#include "packet.h"
#include "dis_mod.h"
#include "grp_rule.h"


#define PROT_FLOW_CHECK_FLOW   20  /* sec from next tver (see below) */
#define PROT_FLOW_TREES        512
#define PROT_FLOW_TREES_ROOTS  126

/** protocol check function */
typedef bool (*ProtVerify)(int flow_id);

/** protocol packet dissector funcion  */
typedef packet* (*PktDissector)(packet *pkt);

/** protocol flow dissector funcion  */
typedef packet* (*FlowDissector)(int flow_id);

/** protocol ragroup flow  */
typedef int (*GroupFlow)(int flow_id, int *flow_list, int num);

/** protocol sub dissector, only for protocol node */
typedef void (*FlowSubDissector)(int flow_id, packet *pkt);

/** protocol flow hash, only for protocol node */
typedef int (*FlowCmpFreeFun)(cmpflow *fd);
typedef int (*FlowHashFun)(cmpflow *fd, unsigned long *hashs);

/** protocol flow compare functions, only for protocol node */
typedef int (*FlowCmpFun)(const cmpflow *fd_a, const cmpflow *fd_b);

/** information describing a protocol/flow attribute protocol */
typedef struct _proto_info proto_info;
struct _proto_info {
    char   *name;        /**< full name of this field */
    char   *abbrev;      /**< abbreviated name of this field */
    enum ftype type;     /**< field type, one of FT_ (from ftypes.h) */
};


/** protocol dependecy name and attribute */
typedef struct _proto_dep proto_dep;
struct _proto_dep {
    char   *name;            /**< name protocol, field name from prot_desc */
    char   *attr;            /**< one of attribute defined in to prot_desc.info */
    enum ftype   type;       /**< field type, one of FT_ (from ftypes.h)  (type of prot_info) */
    enum ft_op   op;         /**< type of compare (default is equal) */
    ftval        val;        /**< attribute value */
    regex_t      opd;        /**< regular expression compiled if type is FT_OP_REX */
    ProtVerify   ProtCheck;  /**< function to verify protocol -only for prot_dep with flow- */
    unsigned short pktlim;   /**< number of max packet to try  ProtCheck ; 0 -> no limit*/
};


/** heuristic protocol dependecy */
typedef struct _proto_heury_dep proto_heury_dep;
struct _proto_heury_dep {
    char       *name;      /**< name protocol, field name from prot_desc */
    ProtVerify ProtCheck;  /**< function to try idenficate protocol -only for prot_dep with flow- */
    unsigned short pktlim; /**< number of max packet to try  ProtCheck; 0 -> no limit*/
};


/** next possible protocol */
typedef struct _proto_son proto_son;
struct _proto_son {
    int id;                   /**< protocol identification, identify the sun protocol in the table of protocols */
    /* info relation */
    proto_dep  *dep;          /**< protocol dependency element from dep of id protocol */
    proto_info *info;         /**< protocol info element from info */
    int sfpaid;               /**< stack frame attribute id to compare whit dep */

    /* heuristic relation */
    proto_heury_dep *heu_dep; /**< protocol heuristic dependency element from heu_dep of id protocol */
};


/** Protocol Element Information (PEI) component descriptor */
typedef struct _pei_cmpt  pei_cmpt;
struct _pei_cmpt {
    char *desc;        /**< component name description */
    char *abbrev;      /**< abbreviated name of this component; reference name in dispatcher modules */
};


/** Protocol rules to aggegate flow in group */
typedef struct _prot_rule prot_rule;
struct _prot_rule {
    int id;            /**< rule id in grp_rule */
    bool verified;     /**< rule verified, pending cancellation */
    grp_rule rule;     /**< rule */
    prot_rule *nxt;    /**< next rule */
};


/** protocol descriptor */
typedef struct _proto_desc prot_desc;
struct _proto_desc {
    char           *desc;      /**< protocol name description */
    char           *name;      /**< IANA protocol name */
    bool           flow;       /**< true if this protocol is a node of flows, protocol node */
    bool           grp;        /**< true if this protocol is a protocol flow of group of flows */
    proto_info     *info;      /**< protocol info field */
    int            info_num;   /**< number of info field */
    proto_dep      *dep;       /**< protocol dependence rules */
    int            dep_num;    /**< number of dep field */
    proto_heury_dep *heu_dep;  /**< heuristic protocol dependence rules */
    int            heu_num;    /**< number of heu_dep field */
    unsigned short log_mask;   /**< log mask */
    int            pstack_sz;  /**< real size of protocol stack */
    /* dependency session */
    proto_son      *stbl;      /**< son protocols table */
    int            stbl_dim;   /**< number of son of stbl */
    /* Dissector */
    PktDissector   PktDis;     /**< packet dissector function */
    PktDissector   DflSubDis;  /**< default next packet dissector function */
    FlowDissector  FlowDis;    /**< flow dissector function */
    GroupFlow      GrpFlow;    /**< group function for aggregate stream, before start disserctor */
    volatile int   flow_run;   /**< number of flow/thread of this protocol running */
    volatile unsigned long flow_tot;   /**< number of total flow/thread */

    /* flow generation */
    FlowHashFun  FlowHash;     /**< the hash of flow */
    FlowCmpFun   FlowCmp;      /**< compare two flows */
    FlowCmpFreeFun FlowCmpFree;/**< free data used to compare */
    FlowSubDissector SubDis;   /**< subdissector for elaborate flow stream before insert new packets in the flow */

    /* flow aggregation in group */
    prot_rule *grule;          /**< rule to aggregate flows */
    pthread_mutex_t rl_mux;    /**< mutex for access rules list */
    volatile pthread_t rl_ptrd_lock;   /**< ptread that lock access */
    short rl_nesting;          /**< lock nesting */

    /* flow control for protocol node protocol (flow == TRUE) */
    void           *ftree[PROT_FLOW_TREES_ROOTS][PROT_FLOW_TREES];     /**< flow tree descriptor, all flows of this protocol */
    flow_d         *node_del;                  /**< last node deleted */
    volatile int   flow_num;   /**< number of flow for this protocol node */
    pthread_mutex_t mux;       /**< mutex for access flow table descriptor */
    volatile pthread_t ptrd_lock;      /**< ptread that lock access */
    short          nesting;    /**< lock nesting */
    bool           tver;       /**< verify timeout closure */

    /* module function and handler */
    void *handle;              /**< module handler */
    DisRegist DissecRegist;    /**< dissector function register */
    DisMultiRegist DissecMultiRegist;   /**< dissector function for multiple register */
    DisInit DissectInit;       /**< dissector function inizialization */
    DisLog DissectLog;         /**< dissector function log inizialization */
#ifdef XPL_PEDANTIC_STATISTICS
    pthread_mutex_t cnt_mux;        /**< mutex to access packet counter */
    volatile unsigned long pkt_tot; /**< total number of packet */
#endif

    /* Protocol Element Information (PEI) description of dissector protocol*/
    /*    this session of struct is used only by protocol that generate PEI */
    bool pei;                  /**< true if protocol is an end (leaf) protocol */
    pei_cmpt *peic;            /**< type of components pei of protocol */
    int peic_num;              /**< number of type of components */
};


/* inizialization functions */
int ProtInfo(proto_info *ppinfo); /* it return the id to be use to insert the attibute into the stack (protocol stack-frame) */
int ProtDep(proto_dep *ppdep);
int ProtHeuDep(proto_heury_dep *ppedep);
int ProtName(char *name, char *abbr);
int ProtAddRule(char *rule);
int ProtPeiComponent(pei_cmpt *ppeic);
int ProtGrpEnable(void);
int ProtDissectors(PktDissector p_dis, FlowDissector f_dis, GroupFlow g_flow, PktDissector dflt_subdis);
int ProtSubDissectors(FlowSubDissector p_sdis);

/* runtime functions */
int ProtId(char *name);
int ProtAttrId(int pid, char *attr);
enum ftype ProtAttrType(int pid, int attr_id);
const char *ProtAttrName(int pid, int attr_id);
int ProtInsAttr(pstack_f *frame, int id, ftval *val);
int ProtGetAttr(const pstack_f *frame, int id, ftval *val);
int ProtPeiComptId(int pid, char *abbrev);
const char *ProtTmpDir(void);
int ProtFrameProtocol(const pstack_f *frame);
const pstack_f *ProtGetNxtFrame(const pstack_f *frame);
int ProtSetNxtFrame(pstack_f *frame, pstack_f *nxt);
int ProtStackSearchNode(const pstack_f *stk);
const pstack_f* ProtStackSearchProt(const pstack_f *stk, int pid);
void ProtStackFrmDisp(const pstack_f *frame, bool all);
char *ProtStackFrmXML(const pstack_f *frame);
char *ProtStackFrmFilter(const pstack_f *frame);
int ProtFrameSize(int prot_id);
pstack_f *ProtCreateFrame(int prot_id);
pstack_f *ProtCopyFrame(const pstack_f *stk, bool all);
bool ProtDiffFrame(const pstack_f *stk_a, const pstack_f *stk_b, bool all);
int ProtDelFrame(pstack_f *stk);
PktDissector ProtPktDis(int prot_id);
FlowDissector ProtFlowDis(int prot_id);
PktDissector ProtPktDefaultDis(int prot_id);
int ProtGrpRuleIns(int prot_id, int rule_id, const grp_rule *rule);
int ProtGrpRuleRm(int prot_id, int rule_id);
packet *ProtDissecPkt(int prot_id, packet *pkt);
const char *ProtGetName(int prot_id);

/* core function */
int ProtDissec(int prot_id, packet *pkt);
bool ProtIsNode(int prot_id);
int ProtFlushFlow(int prot_id, int flow_id);
int ProtOpenFlow(void);
int ProtSearchHeuDissec(int prot_id, int flow_id);
int ProtParent(const pstack_f *stk);
int ProtRunFlowInc(int prot_id);
int ProtRunFlowDec(int prot_id);
int ProtRunningFlow(int prot_id);
unsigned long ProtTotFlow(int prot_id);
int ProtStatus(FILE *fp);
unsigned short ProtLogMask(int prot_id);
const char *ProtLogName(int prot_id);
#ifdef XPL_PEDANTIC_STATISTICS
int ProtPktFromNode(int prot_id, unsigned long pkt_tot);
#endif
int ProtInit(const char *file_cfg);
int ProtNumber(void);
int ProtFlowTimeOutForce(int prot_id);

/* core functions */
int ProtNodeLock(void);
int ProtNodeUnlock(void);

#endif /* __PROTO_H__ */
