/* pjl.h
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


#ifndef __PJL_H__
#define __PJL_H__

/* path buffer size */
#define PJL_FILENAME_PATH_SIZE        256
#define PJL_CMD_NAME                  20

/* packets limit for PjlVerify, PjlCheck */
#define PJL_PKT_VER_LIMIT              10


typedef enum _pjl_client_dir  pjl_client_dir;
enum _pjl_client_dir {
    PJL_CLT_DIR_NONE,
    PJL_CLT_DIR_OK,
    PJL_CLT_DIR_REVERS
};


typedef struct _pjl_priv pjl_priv;
struct _pjl_priv {
    bool port_diff;         /* connection with different port */
    pjl_client_dir dir;     /* real direction of client */
    unsigned short port;    /* source port */
    bool ipv6;              /* ipv6 or ipv4 */
    ftval ip;               /* ip source */
};


#endif /* __PJL_H__ */
