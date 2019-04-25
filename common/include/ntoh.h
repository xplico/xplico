/* ntoh.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __NTOH_H__
#define __NTOH_H__



#define pntoh24(p)  ((unsigned int)*((const unsigned char *)(p)+0)<<16| \
                     (unsigned int)*((const unsigned char *)(p)+1)<<8|  \
                     (unsigned int)*((const unsigned char *)(p)+2)<<0)


#define kswaps(p)  ((unsigned short)                                   \
                     ((unsigned short)*((const unsigned char *)(p)+1)<<8|  \
                      (unsigned short)*((const unsigned char *)(p)+0)<<0))


#define kswapsl(p)  ((unsigned int)*((const unsigned char *)(p)+3)<<24| \
                     (unsigned int)*((const unsigned char *)(p)+2)<<16| \
                     (unsigned int)*((const unsigned char *)(p)+1)<<8|  \
                     (unsigned int)*((const unsigned char *)(p)+0)<<0)

#define getu16(p, b) (*(unsigned short *)(((unsigned char*)p) + b))
#define getu32(p, b) (*(unsigned int *)(((unsigned char*)p) + b))

#endif /* __NTOH_H__ */
