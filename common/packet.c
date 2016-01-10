/* packet.c
 * Function to manipulate packet structure
 *
 * $Id: packet.c,v 1.8 2007/05/30 06:03:52 costa Exp $
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

#include <stdlib.h>
#include <string.h>

#include "packet.h"
#include "log.h"
#include "dmemory.h"
#include "proto.h"


void PktFree(packet *pkt)
{
    packet *next;

    do {
        if (pkt == NULL)
            return ;
        
        ProtDelFrame(pkt->stk);
        
        if (pkt->dat_base != NULL) {
            if (pkt->raw != pkt->dat_base) {
                DMemFree(pkt->dat_base);
            }
        }
        else if (pkt->data != NULL) {
            DMemFree(pkt->data);
        }
        if (pkt->raw != NULL) {
            DMemFree(pkt->raw);
        }
        /* list */
        PktFree(pkt->list);

        next = pkt->next;
        DMemFree(pkt);
        pkt = next;
    } while (pkt != NULL);
}


packet* PktNew(void)
{
    packet *pkt;

    pkt = DMemMalloc(sizeof(packet));
    if (pkt != NULL)
        memset(pkt, 0, sizeof(packet));
    
    return pkt;
}


packet* PktCp(const packet *pkt)
{
    packet *new;

    new = PktNew();
    if (new != NULL) {
        new->stk = ProtCopyFrame(pkt->stk, TRUE);
        new->cap_sec = pkt->cap_sec;
        new->cap_usec = pkt->cap_usec;
        new->raw = NULL;
        new->raw_len = 0;
        new->list = NULL;
        new->dat_base = NULL;
        if (pkt->len != 0 && pkt->data != NULL) { /* for protocol with hole (ex:tcp) */
            new->data = DMemMalloc(pkt->len+1);
            memcpy(new->data, pkt->data, pkt->len);
            new->data[pkt->len] = '\0';
        }
        new->len = pkt->len;
        new->next = NULL;
    }

    return new;
}
