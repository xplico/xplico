/* rossoalice.h
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


#ifndef __ROSSOALICE_H__
#define __ROSSOALICE_H__

#include <time.h>

#define RALICE_STR_SIZE       2048

typedef struct _ra_attach_t ra_attach;
struct _ra_attach_t {
    char attach[RALICE_STR_SIZE];
    ra_attach *nxt;
};

typedef struct _ralice_t ralice;
struct _ralice_t {
    char ref[RALICE_STR_SIZE];
    char uid[RALICE_STR_SIZE];
    char header[RALICE_STR_SIZE];
    char body[RALICE_STR_SIZE];
    pei *ppei;                     /* first pei (but all stacks) */
    ra_attach *attach;
    time_t start;
    ralice *nxt;
};

#endif /* __ROSSOALICE_H__ */
