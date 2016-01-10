/* base.c
 *
 * $Id: captime.c,v 1.1 2007/09/08 07:11:52 costa Exp $
 *
 * Xplico System
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

#include <stdlib.h>
#include <pcap.h>
#include <string.h>

#include "captime.h"
#include "log.h"


static cap_time myctime;


cap_time *CapTime(char *file_name)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap;
    struct pcap_pkthdr *h;
    const u_char *bytes;
    
    if (file_name == NULL)
        return NULL;
    
    memset(&myctime, 0, sizeof(cap_time));

    cap = pcap_open_offline(file_name, errbuf);
    if (cap == NULL) {
        LogPrintf(LV_ERROR, "Pcap error:%s\n", errbuf);
        return NULL;
    }
    
    if (pcap_next_ex(cap, &h, &bytes) == 1) {
        if (h->ts.tv_sec < 0) {
            myctime.start_sec = 0;
            myctime.end_sec = 0;
        }
        else {
            myctime.start_sec = h->ts.tv_sec;
            myctime.end_sec = h->ts.tv_sec;
        }
        myctime.start_usec = h->ts.tv_usec;
        myctime.end_usec = h->ts.tv_usec;
    }
    else {
        return NULL;
    }
    while (pcap_next_ex(cap, &h, &bytes) == 1) {
        if (h->ts.tv_sec > 0) {
            myctime.end_sec = h->ts.tv_sec;
            myctime.end_usec = h->ts.tv_usec;
        }
    }
    pcap_close(cap);

    return &myctime;
}
