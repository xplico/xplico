/* dig.h
 * Part of tcp_grbg dissector
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012-2013 Gianluca Costa. Web: www.xplico.org
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option.h) any later version.
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


#ifndef __DIG_H__
#define __DIG_H__

#include "etypes.h"
#include "tcp_garbage.h"
#include "packet.h"


#define TCP_GRB_FILE_EXT_SIZE   10
#define TG_MULTI_END_NUM        10

typedef struct _dig_file_t dig_file;
struct _dig_file_t {
    char ename[TCP_GRB_FILE_EXT_SIZE];  /* file type, its extension */
    unsigned long msize;    /* max size */           
    bool sreg;              /* regular expression */
    char *starttxt;
    char *start;
    unsigned short slen;
    bool ereg;              /* regular expression */
    char *endtxt;
    char *end;
    bool stend;             /* the start condiction can complete the file */
    unsigned short elen;
    short end_id[TG_MULTI_END_NUM];      /* id to find the end -1 => no id */
};


typedef struct _dig_t dig;
struct _dig_t {
    dig_file *ft;        /* file type    */
    unsigned short fs;   /* search fase  */
    bool head;           /* head found   */
    int dig_sync;        /* id match */
    packet *pkt;         /* pkt in srch active fase */
    unsigned int pkt_offset;  /* pkt offset in srch active fase */
    char filename[TCP_GRB_FILENAME_PATH_SIZE];   /* file name */
    FILE *fp;            /* file */
    unsigned long fsize; /* file size */
    unsigned long serial;/* serial number of packet (will be used in PEI) */
    time_t start_cap;    /* first packet */
    time_t end_cap;      /* last packet */
};

#endif  /* __DIG_H__ */



