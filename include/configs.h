/* config.h
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


#ifndef __CONFIGS_H__
#define __CONFIGS_H__


/* count any group flow with same protocol, the master protocol */
#define PROT_GRP_COUNT            1
/* enable or disable the geo ip localization */
#define XPL_GEO_IP                1
/* timeout at the end, for dissectors in loop */
#define XP_END_TO               600 /* sec */
/* time UTC/GMT or local time in dispatcher modules */
#define XP_CAPTURE_UTC            0
#define XP_DEFAULT_CFG            "config/xplico_cli.cfg"
/* memory debug and speed */
#define XP_MEM_DEBUG              1
#define XP_MEM_SPEED              0
/* tcp ack elaboration */
#define TCP_ENABLE_TCP_ACK        1

#endif /* __CONFIGS_H__ */
