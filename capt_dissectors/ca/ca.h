/* ca.h
 *
 * $Id: $
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


#ifndef __PCAP_DEF_H__
#define __PCAP_DEF_H__

#define PCAP_PATH_DIM           4096
#define CA_END_FILE             "ds_end.cfg"
#define CA_DS_STATUS            "elab_status.log"

#include <unistd.h>

struct cap_ref {
    unsigned int dlt;
    unsigned long cnt;
    size_t offset;
    char *file_name;
    unsigned long file_id;
    unsigned long ds_id;
};

#endif /* __PCAP_DEF_H__ */
