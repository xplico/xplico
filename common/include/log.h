/* log.h
 *
 * $Id:  $
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


#ifndef __LOG_H__
#define __LOG_H__

#include "packet.h"

#define LV_OOPS          0x0001
#define LV_FATAL         0x0002
#define LV_ERROR         0x0004
#define LV_WARNING       0x0008
#define LV_INFO          0x0010
#define LV_TRACE         0x0020
#define LV_DEBUG         0x0040
#define LV_START         0x0080
#define LV_STATUS        LV_START
#define LV_ONLY_FILE     0x0100

#define LV_BASE          (LV_OOPS)
#define LV_DEFAULT       (LV_OOPS| LV_FATAL | LV_ERROR| LV_WARNING)

#define LV_LINE_MAX_DIM  40680

/* NOTE: do not use this (LogPrintfPrt)  function!!! */
int LogPrintfPrt(int prot_id, unsigned short level, const pstack_f *stack, const char *format, ...);

#ifndef LOG_COMPONENT
# ifdef LOG_DIS_VAR_NAME
extern int LOG_DIS_VAR_NAME;
# define LogPrintf(level, format, args...)  LogPrintfPrt(LOG_DIS_VAR_NAME, level, NULL, format, ## args)
# define LogPrintfStack(level, stack, format, args...)  LogPrintfPrt(LOG_DIS_VAR_NAME, level, stack, format, ## args)
# define LogPrintfPei(level, pei, format, args...)  LogPrintfPrt(LOG_DIS_VAR_NAME, level, pei->stack, format, ## args)
# else
#  error "you have to include in Makefile of dissector/dispatcher the 'Makefilelog' file"
# endif
#else
# define LogPrintf(level, format, args...)  LogPrintfPrt(LOG_COMPONENT, level, NULL, format, ## args)
# define LogPrintfStack(level, stack, format, args...)  LogPrintfPrt(LOG_COMPONENT, level, stack, format, ## args)
# define LogPrintfPei(level, pei, format, args...)  LogPrintfPrt(LOG_COMPONENT, level, pei->stack, format, ## args)
#endif

int LogSetMask(int component, unsigned short mask);
int LogFault(const char *format, ...);

#endif /* __LOG_H__ */
