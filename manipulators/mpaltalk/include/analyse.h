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

#include <time.h>
#include <stdio.h>

#include "pei.h"
#include "packet.h"

#define PLTEX_WAIT_TIME        10    /* sec */
#define PLTEX_BUFFER_SIZE      (1024*1204)
#define PLTEX_CMD_SIZE         (3*1024)
#define PLTEX_TMP_DIR          "paltalck_exp"

/* strings */
#define PLTEX_STR_START           "<pfont"
#define PLTEX_STR_END             "</pfont>"

/* paltalk express chat: time constrains */
typedef struct _pt_chat pt_chat;
struct _pt_chat {
    char id[PLTEX_CMD_SIZE];   /* chat id and user name */
    char chat[PLTEX_CMD_SIZE]; /* file messages */
    FILE *fp;                  /* file pointer */
    time_t first; /* date of first message */
    time_t last;  /* date of last message */
    pei *ppei;
    pt_chat *nxt;
};


typedef struct _pei_msg pei_msg;
struct _pei_msg {
    time_t t;     /* arrival time */
    pei *pei;     /* pei */
    pei_msg * volatile nxt; /* next */
};

int AnalyseInit(void);
int AnalysePei(pei *ppei);
int AnalyseEnd(void);


#endif /* __ANALYSE_H__ */
