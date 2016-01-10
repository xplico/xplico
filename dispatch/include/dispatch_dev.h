/* dispatch_dev.h
 * Dispatch interface private functions and structures
 *
 * $Id: dispatch_dev.h,v 1.2 2007/11/14 19:02:57 costa Exp $
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


#ifndef __DISPATCH_DEV_H__
#define __DISPATCH_DEV_H__

#include <pthread.h>

#include "pei.h"

#define DISP_D_STR_DIM          256
#define DISP_MANIP_START_PORT   23456


/* pei list, used in thread serial insert */
typedef struct _pei_list {
    pei *ppei;
    pthread_cond_t cond;
    struct _pei_list *nxt;
} pei_list;


/* manipulator connection info */
typedef struct {
    char name[DISP_D_STR_DIM];   /* protocol manipulator */
    char host[DISP_D_STR_DIM];   /* host name or ip address */
    char bin[DISP_D_STR_DIM];    /* binary file */
    unsigned short port;         /* port */
    int pid;                     /* protocol id */
    pthread_mutex_t *mux;        /* mutex to accesses and control connection events */
    int sock;                    /* socket */
    volatile bool wait;          /* wait manipulator restart */
    pei_list * volatile peil;    /* pei list in wait condiction */
    pei_list * volatile peilast; /* last pei in the queue */
} manip_con;


manip_con *DispatManip(int prot_id);
void DispatManipOff(int prot_id);
manip_con *DispatManipOffLine(void);
manip_con *DispatManipWait(void);
const char *DispatManipModulesCfg(void);



#endif /* __DISPATCH_DEV_H__ */
