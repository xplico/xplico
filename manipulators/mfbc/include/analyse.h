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

#include "pei.h"
#include "packet.h"

/* facebook chat: time constrains */
#define FBC_MSG_QUEUE           15
#define FBC_ADD_CHAT            10
#define FBC_STR_DIM             1024
#define FBC_MSG_TO              (300) /* sec */


typedef struct _fb_chat_msg fb_chat_msg;
struct _fb_chat_msg {
    time_t mtime;   /* message time */
    char *from;     /* message from ... */
    char *msg;      /* message text */
    int size;       /* message size */
};

typedef struct _fb_chat fb_chat;
struct _fb_chat {
    char *cid;      /* client id */
    char *fid;      /* friend id */
    char *file;     /* file path */
    time_t first;   /* firs message time */
    time_t last;    /* last message time */
    pei *ppei;      /* chat pei */
    int ind;        /* msg index */
    time_t store;   /* last store time */
    fb_chat_msg *msg[FBC_MSG_QUEUE]; /* chat messages */
};


int AnalyseInit(void);
int AnalysePei(pei *ppei);
int AnalyseEnd(void);


#endif /* __ANALYSE_H__ */
