/* fthread.h
 * flow thread functions and structures
 *
 * $Id: fthread.h,v 1.7 2007/09/08 08:15:56 costa Exp $
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


#ifndef __FTHREAD_H__
#define __FTHREAD_H__

#include <pthread.h>


#define FTHD_TBL_ELEMENT_DELTA   100
#define FTHD_STACK_SIZE          (145*1024)
#define FTHD_STACK_SIZE_PARAM    "THREAD_STACK_SIZE"



typedef void* (*start_routine)(void*);

int FthreadInit(const char *cfg_file);
int FthreadCreate(int flow_id, start_routine fun, void *arg);
void FthreadSync(void);
int FthreadChFlow(int fthd_id, int flow_id);
int FthreadFlow(int fthd_id);
int FthreadSelfFlowId(void);
void FthreadEnd(void);
unsigned long FthreadRunning(void);
unsigned long FthreadTblDim(void);

#endif /* __FTHREAD_H__ */
