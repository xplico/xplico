/* analise.h
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __ANALYSE_H__
#define __ANALYSE_H__

#include <stdio.h>

#include "pei.h"
#include "packet.h"
#include "istypes.h"

/* buffer size */
#define HTTPFILE_STR_DIM                10240

/* info file fields */
typedef struct _file_http file_http;
struct _file_http {
    char url[HTTPFILE_STR_DIM]; /* source url */
    char file[HTTPFILE_STR_DIM]; /* file recontruction */
    char file_name[HTTPFILE_STR_DIM]; /* file name */
    char part_list[HTTPFILE_STR_DIM]; /* download list */
    char content_type[HTTPFILE_STR_DIM]; /* content type */
    size_t dim; /* original file size */
    size_t len; /* real file size */
    pei *ppei;  /* pei */
    bool range; /* reconstruct from range */
    unsigned long cnt; /* parts number */
};

typedef struct _file_part file_part;
struct _file_part {
    size_t start; /* offset start */
    size_t end;   /* offset end */
};

int AnalyseInit(void);
int AnalysePei(pei *ppei);
int AnalyseEnd(void);


#endif /* __ANALYSE_H__ */
