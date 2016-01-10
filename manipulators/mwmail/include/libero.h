/* libero.h
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2013 Gianluca Costa. Web: www.xplico.org
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


#ifndef __LIBERO_H__
#define __LIBERO_H__

#include "pei.h"

/* webmail service: structures and define */
/*  Libero */
#define LIBERO_STR_SIZE        1024
typedef struct _email_libero_t email_libero;
struct _email_libero_t {
    char pid[LIBERO_STR_SIZE];     /* email pid */
    char header[LIBERO_STR_SIZE];  /* email header file */
    char body[LIBERO_STR_SIZE];    /* email body file */
    pei *ppei;                     /* first pei (but all stacks) */
    email_libero *next;            /* next element */
};

#endif /* __LIBERO_H__ */
