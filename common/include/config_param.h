/* config_param.h
 * Parameters of config file
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


#ifndef __CONFIG_PARAM_H__
#define __CONFIG_PARAM_H__

#include "istypes.h"

/* cfg line */
#define CFG_LINE_COMMENT           '#'
#define CFG_LINE_MAX_SIZE          512


/* directory paths */
#define CFG_PAR_TMP_DIR_PATH       "TMP_DIR_PATH"

/* log dir and name template */
#define CFG_PAR_LOG_DIR_PATH       "LOG_DIR_PATH"
#define CFG_PAR_LOG_NAME_TMP       "LOG_BASE_NAME"

/* flow and protocols params */
#define CFG_PAR_FLOW_TIMEOUT       "FLOW_SILENCE_TIMEOUT"

/* modules param */
#define CFG_PAR_MODULES_DIR        "MODULES_DIR"
#define CFG_PAR_MODULE_NAME        "MODULE"
#define CFG_PAR_MODULE_LOG         "LOG"
#define CFG_PAR_MODULE_LOG_LV_1    'F'
#define CFG_PAR_MODULE_LOG_LV_2    'E'
#define CFG_PAR_MODULE_LOG_LV_3    'W'
#define CFG_PAR_MODULE_LOG_LV_4    'I'
#define CFG_PAR_MODULE_LOG_LV_5    'T'
#define CFG_PAR_MODULE_LOG_LV_6    'D'
#define CFG_PAR_MODULE_LOG_LV_7    'S'

/* dispatcher */
#define CFG_PAR_DISPATCH           "DISPATCH"
#define CFG_PAR_DISPATCH_PARAL     "DISPATCH_PARALLEL"
#define CFG_PAR_DISPATCH_MANIP_NAME "MANIP"
#define CFG_PAR_DISPATCH_MANIP_HOST "MPHOST"
#define CFG_PAR_DISPATCH_MANIP_BIN  "MPBIN"
#define CFG_PAR_DISPATCH_MANIP_PORT "MPPORT"

/* geomap */
#define CFG_PAR_GEO_LAT            "DISPATCH_GEPMAP_LAT"
#define CFG_PAR_GEO_LONG           "DISPATCH_GEPMAP_LONG"

/* log mask */
#define CFG_PAR_CORE_LOG           "CORE_LOG"
#define CFG_PAR_CAPTURE_LOG        "CAPTURE_LOG"


bool CfgParIsComment(char *line);
unsigned short CfgParLogMask(char *mask, int line_num);


#endif /* __CONFIG_PARAM_H__ */
