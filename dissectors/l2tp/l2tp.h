/* l2tp.h
 *
 * $Id:$
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


#ifndef __L2TP_H__
#define __L2TP_H__

typedef struct {
    unsigned char p:1;   /* Priority */
    unsigned char o:1;   /* Offset */
    unsigned char d2:1;
    unsigned char s:1;   /* Sequence */
    unsigned char d1:1;
    unsigned char d0:1;
    unsigned char l:1;   /* Length */
    unsigned char t:1;   /* Type */

    unsigned char ver:4; /* version */
    unsigned char d6:1;
    unsigned char d5:1;
    unsigned char d4:1;
    unsigned char d3:1;
} l2tphdr;

#endif /* __L2TP_H__ */
