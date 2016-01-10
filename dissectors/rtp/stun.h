/* stun.h
 * Dissector of STUN protocol
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#ifndef __STUN_H__
#define __STUN_H__


typedef struct _stun_hdr stun_hdr;
struct _stun_hdr {
    unsigned short type;      /**< message type */
    unsigned short len;       /**< message length */
    unsigned int mc;          /**< magic cookie */
    unsigned char tid[12];    /**< transaction ID */
} __attribute__((__packed__));


/* STUN message type */
#define STUN_MT_BUILD_REQ    0x0001
#define STUN_MT_BUILD_RESP   0x0101
#define STUN_MT_BUILD_ERR    0x0111
#define STUN_MT_SECR_REQ     0x0002
#define STUN_MT_SECR_RESP    0x0102
#define STUN_MT_SECR_ERR     0x0112

#endif /* __STUN_H__ */

