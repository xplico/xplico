/* pppoe.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __PPPOE_H__
#define __PPPOE_H__

#include <sys/types.h>
#include <sys/time.h>

typedef struct _pppoe_hdr pppoe_hdr;
struct _pppoe_hdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ver:4;
    unsigned char type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned char type:4;
    unsigned char ver:4;
#else
# error "Please fix <bits/endian.h>"
#endif
    unsigned char code;
    unsigned short sess_id;
    unsigned short len;
};


#endif
