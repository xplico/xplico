/* tcp_analysis.h
 * Dissector to extract TCP informations
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012 Gianluca Costa. Web: www.xplico.org
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

#include <sys/types.h>

#ifndef __TCP_ANALYSIS_H__
#define __TCP_ANALYSIS_H__

#include "pei.h"
#include <ndpi/ndpi_api.h>

/* path & buffer size */
#define TCP_CA_FILENAME_PATH_SIZE      512
#define TCP_CA_LINE_MAX_SIZE           1024

/* threads */
#define TCP_CA_DEFUALT_PARAL_THR       16
#define TCP_CA_CFG_PARAL_THR           "CAPANA_PARALLEL"

/* packets limit for dependency and cfg */
#define TCP_CA_PKT_LIMIT               6


typedef struct _tca_priv tca_priv;
struct _tca_priv {
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
    size_t *tarce_sent;
    size_t *tarce_receiv;
    char img1[TCP_CA_FILENAME_PATH_SIZE];
    char img2[TCP_CA_FILENAME_PATH_SIZE];
};

typedef struct _tca_flow tca_flow;
struct _tca_flow {
    tca_flow *nxt;
    tca_flow *pre;
    int flow_id;
    unsigned long pkt_elb;
    
    tca_priv priv;
    int count;
    pei *ppei;
    size_t flow_size;
    bool first_lost;
    char buff[TCP_CA_LINE_MAX_SIZE];
    char *l7prot_type;
    struct ndpi_flow_struct *l7flow;
    struct ndpi_id_struct *l7src, *l7dst;
    ndpi_protocol l7prot_id;
    unsigned char stage;
    bool syn_clt;
    bool syn_srv;
    time_t cap_sec, end_cap;
};


#endif /* __TCP_ANALYSIS_H__ */
