/* ssl.h
 * Dissector to extract SSL information
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
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


#ifndef __SSL_H__
#define __SSL_H__


/* packets limit for dependency and cfg */
#define TCP_SSL_PKT_LIMIT               4
#define TCP_PORTS_SSL                   {443}

typedef struct _ssl_rcnst ssl_rcnst;
struct _ssl_rcnst {
    unsigned short dim;
    unsigned short len;
    unsigned char *msg;
    ssl_rcnst *nxt;
};



typedef struct _ssl_priv ssl_priv;
struct _ssl_priv {
    bool port_diff;         /* connection with different port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip_s;             /* ip source */
    unsigned short port_s;  /* source port */
    const pstack_f *stack;  /* protocol stack */
};

#endif /* __SSL_H__ */
