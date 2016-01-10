/* pei.h
 * Protocol Element Information.
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __PEI_H__
#define __PEI_H__

#include <time.h>
#include <stdio.h>

#include "istypes.h"
#include "packet.h"


typedef enum _eerror eerror;
enum _eerror {
    ELMT_ER_NONE = 0,
    ELMT_ER_HOLE,
    ELMT_ER_PARTIAL
};


typedef struct _pei_component pei_component;
struct _pei_component {
    int eid;          /**< identify univocaly a component type internal of PEI of paticular protocol */
    unsigned long id; /**< id (unic and assigned by dispatcer) of PEI component, used in case of PEI return to dissector */
    time_t time_cap;         /**< start capture time */
    time_t time_cap_end;     /**< capture time end   */
    char *strbuf;            /**< buffer string */
    char *name;              /**< file name */
    char *file_path;         /**< file path of component data */
    size_t file_size;        /**< file size */
    bool changed;            /**< true if data in the file is changed */
    eerror err;              /**< error type */
    pei_component *next;     /**< next component */
};


typedef struct _pei pei;
struct _pei {
    int prot_id;                 /**< PEI of protocol with this protocol id */
    unsigned long id;            /**< id (unic and assigned by dispatcer) of this pei */
    unsigned long pid;           /**< id (unic) of the parent pei of this pei */
    bool ret;                    /**< identify a PEI that return to dissector */
    pei_component *components;   /**< components list */
    time_t time_cap;             /**< start capture time */
    time_t time;                 /**< decoding end time -real time- (auto assigned) */
    unsigned long serial;        /**< serial number (unique) used for order a pei (if necesary) */
    pstack_f *stack;             /**< pei protocol stack */
};


int PeiInit(pei *ppei);
int PeiNew(pei **ppei, int prot_id);
int PeiSetReturn(pei *ppei, bool ret);
bool PeiGetReturn(pei *ppei);
int PeiParent(pei *ppei, pei *ppei_parent);
int PeiCapTime(pei *ppei, time_t time_cap);
int PeiDecodeTime(pei *ppei, time_t time_dec);
int PeiStackFlow(pei *ppei, const pstack_f *stack);
int PeiMarker(pei *ppei, unsigned long serial);
int PeiNewComponent(pei_component **comp, int comp_id);
int PeiCompAddFile(pei_component *comp, const char *file_name, const char *file_path, unsigned long file_size);
int PeiCompAddStingBuff(pei_component *comp, const char *strbuf);
int PeiCompCapTime(pei_component *comp, time_t time_cap);
int PeiCompCapEndTime(pei_component *comp, time_t time_cap_end);
int PeiCompError(pei_component *comp, eerror err);
int PeiCompUpdated(pei_component *comp);
pei_component *PeiCompSearch(pei *ppei, int comp_id);
int PeiAddComponent(pei *ppei, pei_component *comp);
int PeiAddStkGrp(pei *ppei, const pstack_f *add);
int PeiIns(pei *ppei);
int PeiFree(pei *ppei);
int PeiDestroy(pei *ppei);
void PeiPrint(const pei *ppei);


#endif /* __PEI_H__ */
