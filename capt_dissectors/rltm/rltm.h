/* rltm.h
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
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


#ifndef __RLTM_DEF_H__
#define __RLTM_DEF_H__

#define RLTM_PATH_DIM          4096
#define RLTM_DEVICE            "/dev/hda1"
#define RLTM_CHECK_MAC_STR     "c81395ecf03a8a2ca513f245267044ac" /* md5sum "iSerm IP solurions Xplicio num:"
                                                                     alla rovescia
                                                                     "ca440762542f315ac2a8a30fce59318c" */
#define RLTM_PID_FILE          "/var/run/xplico.pid"


struct pcap_ref {
    unsigned int dlt;
    unsigned long cnt;
    char *dev;
};

#endif /* __RLTM_DEF_H__ */
