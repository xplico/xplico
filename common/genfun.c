/* genfun.c
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <time.h>

#include "genfun.h"

#ifndef XP_CAPTURE_UTC
# error "configs.h error: you must define XP_CAPTURE_UTC as 0 or 1"
#endif


static int hdelta;


#if XP_CAPTURE_UTC == 0
int XTimeOffest(void)
{
    return hdelta;
}
#endif


void genfun_link(void)
{
    time_t now;
    struct tm lcl;;
    struct tm gmt;
    
    now = time(NULL);
    localtime_r(&now, &lcl);
    gmtime_r(&now, &gmt);

    hdelta = lcl.tm_hour - gmt.tm_hour;
}
