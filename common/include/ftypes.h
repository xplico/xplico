/* ftypes.h
 * Definitions for field types
 *
 * $Id: ftypes.h,v 1.9 2007/09/08 08:16:13 costa Exp $
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


#ifndef __FTYPES_H__
#define __FTYPES_H__

#include <unistd.h>

#define FT_ETH_LEN     6


/** field types */
enum ftype {
    FT_NONE,
    FT_UINT8,
    FT_UINT16,
    FT_UINT24,
    FT_UINT32,
    FT_UINT64,
    FT_INT8,
    FT_INT16,
    FT_INT24,
    FT_INT32,
    FT_INT64,
    FT_SIZE,
    FT_FLOAT,
    FT_DOUBLE,
    FT_STRING,
    FT_IPv4,
    FT_IPv6,
    FT_ETHER
};


/** field types string operation */
#define FT_SOP_EQ     "=="
#define FT_SOP_DEQ    "!="
#define FT_SOP_MAJ    ">"
#define FT_SOP_MIN    "<"
#define FT_SOP_AND    "AND"
#define FT_SOP_OR     "OR"
#define FT_SOP_CNTD   "<>"    /* contained */
#define FT_SOP_REX    "REX"   /* regular expression, in compare is the first element to be analyzed */

/** field types operation */
enum ft_op {
    FT_OP_EQ = 0, /* default */
    FT_OP_DEQ,
    FT_OP_MAJ,
    FT_OP_MIN,
    FT_OP_AND,
    FT_OP_OR,
    FT_OP_CNTD,
    FT_OP_REX
};


typedef union _ftval ftval;
union _ftval {
    unsigned int uint32;
    unsigned char uint8;
    unsigned short uint16;
    char int8;
    short int16;
    int int32;
    size_t size;
    float flt;
    double dbl;
    char *str;
    unsigned char ipv6[16];
    unsigned char mac[FT_ETH_LEN];
} __attribute__ ((aligned(4)));


int FTCopy(ftval *d, const ftval *s, enum ftype type);
int FTCmp(const ftval *a, const ftval *b, enum ftype type, enum ft_op op, void *opd); /* in regex is 'a' the string compared */
char *FTString(const ftval *val, enum ftype type, char *buff);
int FTFree(ftval *a, enum ftype type);
unsigned long FTHash(ftval *a, enum ftype type);


#endif /* __FTYPES_H__ */
