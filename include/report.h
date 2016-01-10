/* report.h
 * report in a socket connection the xplico status/statistics
 *
 * $Id: report.h,v 1.2 2007/06/05 17:57:08 costa Exp $
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


#ifndef __REPORT_H__
#define __REPORT_H__

/** protocol report */
typedef struct _prot_rep_ prot_rep;
struct _prot_rep_ {
    char           *name;      /**< IANA protocol name */
    int            ftbl_dim;   /**< number of element of flow tbl */
    int            flow_num;   /**< number of flow for protocol */
#ifdef XPL_PEDANTIC_STATISTICS
    unsigned long pkt_tot;     /**< total number of packet */
#endif
};


int ReportInit(void);
int ReportSplash(void);
void ReportFilesDescr(void);

#endif /* __REPORT_H__ */
