/* captime.h
 *
 * $Id: captime.h,v 1.1 2007/09/08 07:11:52 costa Exp $
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


#ifndef __CAPTIME_H__
#define __CAPTIME_H__


/** capture time data */
typedef struct _cap_time cap_time;
struct _cap_time {
    unsigned long start_sec;
    unsigned long start_usec;
    unsigned long end_sec;
    unsigned long end_usec;
};


cap_time *CapTime(char *file_name);


#endif /* __CAPTIME_H__ */
