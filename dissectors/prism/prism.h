/* prism.h
 *
 * $Id:$
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __PRISM_H__
#define __PRISM_H__

#define PRISM_DNAMELEN      16

typedef struct {
    unsigned int did;
    unsigned short status;
    unsigned short len;
    unsigned int data;
} __attribute__ ((packed)) prism_val;


typedef struct {
    unsigned int msgcode;
    unsigned int msglen;
    char devname[PRISM_DNAMELEN];
    prism_val hosttime;
    prism_val mactime;
    prism_val channel;
    prism_val rssi;
    prism_val sq;
    prism_val signal;
    prism_val noise;
    prism_val rate;
    prism_val istx;
    prism_val frmlen;
} __attribute__ ((packed)) prism_hdr;


#endif /* __PRISM_H__ */
