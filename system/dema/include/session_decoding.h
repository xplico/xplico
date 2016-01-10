/* session_decoding.h
 * Session decoding monitoring
 *
 * $Id: session_decoding.h,v 1.1 2007/09/08 07:11:52 costa Exp $
 *
 * Xplico System
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


#ifndef __SESSION_DECODING_H__
#define __SESSION_DECODING_H__

#include "dema.h"
#include "dbinterface.h"

int SeDeInit(char *cert, char *root_dir);
int SeDeFind(char *main_dir, podec *tbl, int dim);
int SeDeStart(dbconf *db_c, char *main_dir, int pol, int session, task *pid, bool rt, char *interf, char *filter);
int SeDeEnd(char *main_dir, int pol, int session, task *pid);
char *SeDeFileNew(char *main_dir, int pol, int session, bool *one);
char *SeDeFileDecode(char *main_dir, int pol, int session);
bool SeDeFileActive(char *filepath);
int SeDeNextSession(char *main_dir, int pol, int session);
int SeDeRun(task *pid, pid_t chld, bool clear);
int SeDeKill(podec *tbl, int id);


#endif /* __SESSION_DECODING_H__ */
