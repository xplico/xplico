/* dmemory.h
 *
 * $Id: dmemory.h,v 1.5 2007/06/18 06:14:16 costa Exp $
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


#ifndef __DMEMORY_H__
#define __DMEMORY_H__

#include <stdlib.h>

#include "configs.h"

void *XMalloc(size_t size, const char *function, int line);
void XFree(void *ptr, const char *function, int line);
void *XRealloc(void *ptr, size_t size, const char *function, int line);
void *XMemcpy(void *dest, const void *src, size_t n, const char *function, int line);
char *XStrcpy(char *dest, const char *src, const char *function, int line);

#if XP_MEM_DEBUG
# define xmalloc(size)           XMalloc(size, __FUNCTION__, __LINE__)
# define xcalloc(num, size)      calloc(num, size)
# define xfree(ptr)              XFree(ptr, __FUNCTION__, __LINE__)
# define xrealloc(ptr, size)     XRealloc(ptr, size, __FUNCTION__, __LINE__)
# define xmemcpy(dest, src, n)   XMemcpy(dest, src, n, __FUNCTION__, __LINE__)
# define xstrcpy(dest, src)      XStrcpy(dest, src, __FUNCTION__, __LINE__)
#else
# define xmalloc(size)           malloc(size)
# define xcalloc(num, size)      calloc(num, size)
# define xfree(ptr)              free(ptr)
# define xrealloc(ptr, size)     realloc(ptr, size)
# define xmemcpy(dest, src, n)   memcpy(dest, src, n)
# define xstrcpy(dest, src)      strcpy(dest, src);
#endif


#if XP_MEM_SPEED
int DMemInit(void);
void *DMemMalloc(size_t size);
void DMemFree(void *ptr);
void DMemEmpty(void);
void DMemState(void);
#else
# define DMemInit()   0
# define DMemMalloc(c) xmalloc(c)
# define DMemFree(c)   xfree(c)
# define DMemEmpty()
# define DMemState()
#endif


unsigned long ThreadStackSize(void);

#endif /* __DMEMORY_H__ */
