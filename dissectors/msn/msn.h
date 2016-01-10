/*
 * msn.c
 * msn packet dissector by Daniele Franchetto <daniele.franchetto@gmail.com> 
 *            by Gianluca Costa  <g.costa@iserm.com>
 *
 *
 * $Id: $
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

#ifndef __MSN_H__
#define __MSN_H__

#include <stdio.h>

#include "pei.h"

/* standard port  */
#define TCP_PORT_MSN        1863

/* path buffer size */
#define MAXROWLEN          10240
#define MAXCHAR              300
#define ROWBUFDIM             20
#define MAXTOKEN              10


typedef struct _msn_chat msn_chat;
struct _msn_chat {
    int flow_id;
    char file_name[MAXCHAR];
    char receiver[MAXROWLEN];
    char client[MAXROWLEN];
    char name[MAXROWLEN*2];
    FILE *fp;
    pei *ppei;
};


#endif /* __MSN_H__ */
