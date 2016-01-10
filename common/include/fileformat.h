/* fileformat.h
 * File format functions: uncompress, decode, ...
 *
 * $Id: $
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

#ifndef __FILEFORMAT_H__
#define __FILEFORMAT_H__

/* multipart/form-data; boundary file format */
typedef struct _multipart_f multipart_f;
struct _multipart_f {
    char *name;           /* part name */
    char *value;          /* value */
    unsigned short vlen;  /* value lenght */
    char *file_name;      /* file name of part */
    char *file_path;      /* file path */
    char *content_type;   /* file content_type */
    char *content_range;  /* content range */
    multipart_f *nxt;     /* next part */
};


int FFormatUncompress(const char *encoding, const char *file_in,  const char *file_out);
int FFormatCopy(char *old, char *new);
multipart_f *FFormatMultipart(const char *file_name, const char *boundary);
void FFormatMultipartPrint(multipart_f *mp);
int FFormatMultipartFree(multipart_f *mp);

#endif
