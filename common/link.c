/* link.c
 * link all source to be used anywhere
 *
 * $Id: link.c,v 1.1 2007/10/30 13:28:27 costa Exp $
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


extern void strutil_link(void);
extern void embedded_link(void);
extern void f_format_link(void);
extern void genfun_link(void);

void CommonLink(void)
{
    /* neccesary only to link strutils, embedded, fileformat */
    strutil_link();
    embedded_link();
    f_format_link();
    genfun_link();
}
