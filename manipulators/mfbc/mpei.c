/* mpei.c
 * PEI component definition of manupulator
 *
 * $Id:  $
 *
 * Xplico System
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

#include "log.h"
#include "mpei.h"
#include "proto.h"


int ManipPeiComponent(void)
{
    pei_cmpt peic;

    /* chat friend */
    peic.abbrev = "chat";
    peic.desc = "Chat";
    ProtPeiComponent(&peic);

    /* duration */
    peic.abbrev = "duration";
    peic.desc = "Chat duration";
    ProtPeiComponent(&peic);

    return 0;
}
