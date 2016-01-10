/* strutil.h
 * String utility definitions
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

#ifndef __STRUTIL_H__
#define __STRUTIL_H__


/** @file
 * String handling and conversion utilities.
 */

/** Given a pointer into a data buffer, and to the end of the buffer,
 *  find the end of the (putative) line at that position in the data
 *  buffer.
 *
 * @param data A pointer to the beginning of the data
 * @param dataend A pointer to the end of the data
 * @param eol A pointer that will receive the EOL location
 * @return A pointer to the EOL character(s) in "*eol".
 */
const char *find_line_end(const char *data, const char *dataend, const char **eol);


/** Get the length of the next token in a line, and the beginning of the
 *  next token after that (if any).
 * @param linep A pointer to the beginning of the line
 * @param lineend A pointer to the end of the line
 * @param next_token Receives the location of the next token
 * @return 0 if there is no next token.
 */
int get_token_len(const char *linep, const char *lineend, const char **next_token);

int find_line_end_unquoted(char *tvb, int len, int *next_offset);

int find_chr(const char *line, int len, char c);

#endif /* __STRUTIL_H__ */
