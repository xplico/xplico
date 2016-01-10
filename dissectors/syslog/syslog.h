/* syslog.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
 *
 */


#ifndef __SYSLOG_H__
#define __SYSLOG_H__


/* standard port */
#define TCP_PORT_UDP_SYSLOG              514

/* path buffer size */
#define SYSLOG_FILENAME_PATH_SIZE        256

/* packets limit for SyslogVerify, SyslogCheck */
#define SYSLOG_PKT_VER_LIMIT             10
#define SYSLOG_PKT_CHECK                 7
#define SYSLOG_PKT_VER                   3
#define SYSLOG_PKT_MIN_LEN               6

#endif /*__SYSLOG_H__ */
