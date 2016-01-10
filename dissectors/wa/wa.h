/* wa.h
 * Dissector for WahtsApp
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2014 Gianluca Costa. Web: www.xplico.org
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


#ifndef __WA_H__
#define __WA_H__

/* path & buffer size */
#define WA_FILENAME_PATH_SIZE          512
#define WA_LINE_MAX_SIZE               1024

/* packets limit for dependency and cfg */
#define TCP_WA_PKT_LIMIT               5
#define TCP_PORTS_WA                   {443, 5222}


/* flags mask */
#define WA_FLAG_CRYP                   0x80

#define WA_MSG_LISTS                   0xf8
#define WA_MSG_STR                     0xfc
#define WA_MSG_STR_LG                  0xfd


#define WA_LBL_STREAM                  0x01
#define WA_LBL_ALL                     0x0c
#define WA_LBL_PAUSED                  0x88
#define WA_LBL_PICTURE                 0x89
#define WA_LBL_SOUND                   0xb5


typedef struct _wa_rcnst wa_rcnst;
struct _wa_rcnst {
    unsigned short dim;
    unsigned short len;
    unsigned char *msg;
    wa_rcnst *nxt;
};


typedef struct _wa_data wa_data;
struct _wa_data {
    char *device;
    char *phone;
};


typedef struct _wa_priv wa_priv;
struct _wa_priv {
    bool port_diff;         /* connection with different port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip_s;             /* ip source */
    ftval ip_d;             /* ip destination */
    unsigned short port_s;  /* source port */
    unsigned short port_d;  /* destination port */
    const pstack_f *stack;  /* protocol stack */
    size_t bsent;
    size_t breceiv;
    size_t blost_sent;
    size_t blost_receiv;
    unsigned long pkt_sent;
    unsigned long pkt_receiv;
};

#endif /* __WA_H__ */
