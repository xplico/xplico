/* snoop.h
 * prototype of capture dissector
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

#ifndef __SNOOP_H__
#define __SNOOP_H__

/* information necessary to understand Solaris Snoop output */
struct snoop_file_header {
    char format_name[8];        /* should be "snoop\0\0\0" */
    unsigned int version;       /* current version is "2" */
    unsigned int mac;           /* hardware type */
};

struct snoop_packet_header {
    unsigned int len;
    unsigned int tlen;
    unsigned int blen;
    unsigned int unused3;
    unsigned int secs;
    unsigned int usecs;
};

#endif /* __SNOOP_H__ */
