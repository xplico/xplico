/* mms_decode.h
 *
 * $Id: $
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
 *
 */


#ifndef __MMS_DECODE_H__
#define __MMS_DECODE_H__

#define MMS_VER_STR              10
#define MMS_STR_DIM           10240

typedef struct {
    char *ctype;    /* content type */
    char *name;     /* content name */
    int size;       /* content size */
    char *path;     /* content file path */
} mms_part;

typedef struct {
    char version[MMS_VER_STR];           /* mms version */
    char *msg_type;                      /* message type string */
    char *cont_type;                     /* content type */
    char *from;                          /* from */
    char *to;                            /* to */
    char *cc;                            /* cc */
    char *bcc;                           /* bcc */
    short nparts;                        /* number of part */
    mms_part *part;                      /* parts */
} mms_message;


int MMSInit(mms_message *msg);
int MMSDecode(mms_message *msg, const unsigned char *data, const int len, const char *tmp_path);
int MMSPrint(mms_message *msg);
int MMSFree(mms_message *msg);


#endif /* __MMS_DECODE_H__ */
