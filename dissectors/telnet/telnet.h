/* telnet.h
 * Dissector of telnet
 *
 * $Id:  $
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


#ifndef __TELNET_H__
#define __TELNET_H__

/* standard port */
#define TCP_PORT_TELNET                   23

/* path & buffer size */
#define TELNET_FILENAME_PATH_SIZE        256
#define TELNET_BUF_SIZE                  256
#define TELNET_LOGIN_SIZE               (1024*512)

/* packets limit for TelnetVerify, TelnetCheck */
#define TELNET_PKT_LIMIT                   10
#define TELNET_PKT_CHECK                   5


#endif /* __TELNET_H__ */
