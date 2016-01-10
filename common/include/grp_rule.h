/* grp_rule.h
 * definition of data and functions that mange group of flows
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __GRP_RULE_H__
#define __GRP_RULE_H__


#include "ftypes.h"
#include "packet.h"


#define GRP_RULE_PROT                20
#define GRP_RULE_TBL_ELEMENT_DELTA   20

/** grp rules */
typedef struct _cmp_elem cmp_elem;
struct _cmp_elem {
    enum ftype type; /**< compare data type */
    enum ft_op op;   /**< compare operand */
    int prot;        /**< protocol ID */
    int att;         /**< attribiut ID */
    ftval val;       /**< value to be compared */
};


typedef struct _and_rule and_rule;
struct _and_rule {
    cmp_elem *and;   /**< 'and' rule */
    short num;       /**< number of 'and' that compose rule */
};


typedef struct _grp_rule grp_rule;
struct _grp_rule {
    and_rule *or;    /**< 'or' rule */
    short num;       /**< number of 'or' that compose rule */
};


typedef struct _rule_mng rule_mng;
struct _rule_mng {
    bool active;      /**< rule active or not */
    grp_rule rule;    /**< rule */
    int flow_id;      /**< flow id of rule */
    int prot[GRP_RULE_PROT]; /**< protocol where does the rule */
};


typedef struct _cmp_val cmp_val;
struct _cmp_val {
    int prot;        /**< protocol ID */
    int att;         /**< attribiut ID */
    ftval val;       /**< value */
};


int GrpRuleInit(void);
int GrpRuleNew(int flow_id);
int GrpRule(int id, short vnum, cmp_val *val, ...);
int GrpRuleCmplt(int id);
int GrpRuleFlowId(int id);
int GrpRuleRm(int id);
int GrpRuleRmAll(int flow_id);
bool GrpRuleCheck(const grp_rule *rule, const pstack_f *eval);
void GrpRulePrint(const grp_rule *rule);


#endif /* __GRP_RULE_H__ */
