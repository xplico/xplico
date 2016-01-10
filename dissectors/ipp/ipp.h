/* ipp.h
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
 */


#ifndef __IPP_H__
#define __IPP_H__

/* path buffer size */
#define IPP_FILENAME_PATH_SIZE        256
#define IPP_BUFFER_SIZE               1024

/* Operation id */
#define	PRINT_JOB		0x0002
#define	PRINT_URI		0x0003
#define	VALIDATE_JOB		0x0004
#define	CREATE_JOB		0x0005
#define	SEND_DOCUMENT		0x0006
#define	SEND_URI		0x0007
#define	CANCEL_JOB		0x0008
#define	GET_JOB_ATTRIBUTES	0x0009
#define	GET_JOBS		0x000A
#define	GET_PRINTER_ATTRIBUTES	0x000B

/* TAG attribute */
#define	TAG_TYPE(tag)		((tag) & 0xF0)
#define	TAG_TYPE_DELIMITER	0x00
#define	TAG_TYPE_INTEGER	0x20
#define	TAG_TYPE_OCTETSTRING	0x30
#define	TAG_TYPE_CHARSTRING	0x40

#define	TAG_END_OF_ATTRIBUTES	0x03

#define	TAG_INTEGER		0x21
#define	TAG_BOOLEAN		0x22
#define	TAG_ENUM		0x23

#define	TAG_OCTETSTRING		0x30
#define	TAG_DATETIME		0x31
#define	TAG_RESOLUTION		0x32
#define	TAG_RANGEOFINTEGER	0x33
#define	TAG_TEXTWITHLANGUAGE	0x35
#define	TAG_NAMEWITHLANGUAGE	0x36

#define	TAG_TEXTWITHOUTLANGUAGE	0x41
#define	TAG_NAMEWITHOUTLANGUAGE	0x42
#define	TAG_KEYWORD		0x44
#define	TAG_URI			0x45
#define	TAG_URISCHEME		0x46
#define	TAG_CHARSET		0x47
#define	TAG_NATURALLANGUAGE	0x48
#define	TAG_MIMEMEDIATYPE	0x49

typedef enum _ipp_ver ipp_ver;
enum _ipp_ver {
    IPP_1_0 = 0,
    IPP_1_1
};



#endif /* __IPP_H__ */
