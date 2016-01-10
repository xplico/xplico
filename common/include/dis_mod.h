/* dis_mod.h
 * Dissector modules definition
 *
 * $Id: dis_mod.h,v 1.5 2007/11/07 14:28:41 costa Exp $
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


#ifndef __DIS_MOD_H__
#define __DIS_MOD_H__

#define DISMOD_REGIST_FUN        "DissecRegist"
#define DISMOD_MULTI_REGIST_FUN  "DissecMultiRegist"
#define DISMOD_INIT_FUN          "DissectInit"
#define DISMOD_LOG_FUN           "DissectLog"
#define DISMOD_FLOW_HASH         "DissectFlowHash"
#define DISMOD_FLOW_CMP          "DissectFlowCmp"
#define DISMOD_FLOW_CMPFREE      "DissectFlowCmpFree"



/** Dissector register */
typedef int (*DisRegist)(const char *file_cfg);

/** Dissector multiple register */
typedef int (*DisMultiRegist)(const char *file_cfg);

/** Dissector inizialization */
typedef int (*DisInit)(void);

/** Dissector Log */
typedef void (*DisLog)(int);


int DisModLoad(char *file_cfg);
int DisModInit(void);
int DisModClose(void);
void DisModProtGraph(void);
void DisModProtInfo(const char *iana_name);

#endif /* __DIS_MOD_H__ */
