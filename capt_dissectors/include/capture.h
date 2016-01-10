/* capture.h
 * prototype of capture dissector
 *
 * $Id: capture.h,v 1.3 2007/06/05 17:57:14 costa Exp $
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


#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#define CAPT_OPTIONS_FUN        "CaptDisOptions"
#define CAPT_OPTIONS_HELP_FUN   "CaptDisOptionsHelp"
#define CAPT_MAIN_FUN           "CaptDisMain"
#define CAPT_SOURCE_FUN         "CaptDisSource"

int CapInit(const char *file_cfg, const char *cap);
char* CapOptions(void);
void CapOptionsHelp(void);
int CapMain(int argc, char *argv[]);
const char *CapSource(void);


#endif /* __CAPTURE_H__ */
