/* rltm_pol.h
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


#ifndef __RLTM_POL_DEF_H__
#define __RLTM_POL_DEF_H__

#define RLTM_POL_PATH_DIM          4096
#define RLTM_POL_INIT_SESSION_FILE    "pol_sinit.cfg"
#define RLTM_POL_END_SESSION_FILE     "pol_send.cfg"
#define RLTM_POL_SESSION_ID           "SESSION_ID"
#define RLTM_POL_ID                   "POL_ID"

#include <unistd.h>

struct pcap_ref {
    unsigned int dlt;
    unsigned long cnt;
    size_t offset;
    char *dev;
    unsigned long ses_id;
    unsigned long pol_id;
};

#endif /* __RLTM_POL_DEF_H__ */
