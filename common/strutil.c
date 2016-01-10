/* strutil.c
 * String utility routines
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <stdlib.h>
#include <string.h>

#include "strutil.h"
#include "istypes.h"


/*
 * Line can have end with: '\n', '\r\n' or '\n\r'
 */
const char *find_line_end(const char *data, const char *dataend, const char **eol)
{
    const char *lineend;

    lineend = memchr(data, '\n', dataend - data);
    if (lineend == NULL) {
        lineend = dataend;
        *eol = dataend;
    }
    else {
        if (lineend != data) {
            if (*(lineend - 1) == '\r') {
                *eol = lineend - 1;
            }
            else {
                *eol = lineend;
                if (lineend != (dataend - 1) && *(lineend + 1) == '\r') {
                    lineend++;
                }
            }
        }
        else {
            *eol = lineend;
            if (lineend != (dataend - 1) && *(lineend + 1) == '\r') {
                lineend++;
            }
        }
        lineend++;
    }
    
    return lineend;
}


int get_token_len(const char *linep, const char *lineend, const char **next_token)
{
    const char *tokenp;
    int token_len;

    tokenp = linep;

    while (linep != lineend && *linep != ' ' && *linep != '\r' && *linep != '\n')
        linep++;
    token_len = linep - tokenp;

    while (linep != lineend && *linep == ' ')
        linep++;

    *next_token = linep;

    return token_len;
}



int find_line_end_unquoted(char *line, int len, int *next_offset)
{
    char *token_a, *token_b, *linep;
    char *cr, *lf;
    int linelen;
    bool quote;
    
    linelen = 0;
    quote = FALSE;
    *next_offset = len;
    token_a = memchr(line, '"', len);
    cr = memchr(line, '\r', len);
    lf = memchr(line, '\n', len);
    if (token_a != NULL) {
        if ((cr == NULL || token_a < cr) && (lf == NULL || token_a < lf)) {
            token_a++;
            token_b = memchr(token_a, '"', len - (token_a - line));
            if (token_b != NULL) {
                linep = token_a;
                while (linep != token_b && *linep != '\r' && *linep != '\n')
                    linep++;
                if (linep != token_b) {
                    linelen = token_b - token_a;
                    *next_offset = token_b - line;
                }
            }
        }
    }
    else if (cr != NULL) {
        linelen = cr - line; /* without \r, \n, or ...*/
        if (cr != line + len - 1) {
            if (cr[1] == '\n')
                cr++;
            *next_offset = cr - line + 1;
        }
        else {
            *next_offset = len;
        }
    } 
    else if (lf != NULL) {
        linelen = lf - line; /* without \r, \n, or ...*/
        if (lf != line + len - 1) {
            if (lf[1] == '\n')
                lf++;
            *next_offset = lf - line + 1;
        }
        else {
            *next_offset = len;
        }
    }
    
    
    return linelen;
}


int find_chr(const char *line, int len, char c)
{
    int i;
    
    i = 0;
    
    while (i != len && line[i] != c)
        i++;
    if (i == len)
        return -1;

    return i;
}


void strutil_link(void)
{
    
}
