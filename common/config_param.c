/* config_param.c
 * Common function to reade configuration file
 *
 * $Id: config_param.c,v 1.3 2007/06/18 06:14:16 costa Exp $
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "config_param.h"
#include "config_file.h"
#include "istypes.h"
#include "log.h"


bool CfgParIsComment(char *line)
{
    char *cmnt;

    cmnt = strchr(line, CFG_LINE_COMMENT);
    if (cmnt == NULL)
        return FALSE;
    while (*line != CFG_LINE_COMMENT) {
        if (*line != ' ')
            return FALSE;
        line++;
    }

    return TRUE;
}


unsigned short CfgParLogMask(char *mask, int line_num)
{
    unsigned short logm = 0;
    int i;

    /* check mask value */
    for (i=0; i<strlen(mask); i++) {
        switch (mask[i]) {
        case CFG_PAR_MODULE_LOG_LV_1:
            logm |= LV_FATAL;
            break;

        case CFG_PAR_MODULE_LOG_LV_2:
            logm |= LV_ERROR;
            break;

        case CFG_PAR_MODULE_LOG_LV_3:
            logm |= LV_WARNING;
            break;

        case CFG_PAR_MODULE_LOG_LV_4:
            logm |= LV_INFO;
            break;

        case CFG_PAR_MODULE_LOG_LV_5:
            logm |= LV_TRACE;
            break;

        case CFG_PAR_MODULE_LOG_LV_6:
            logm |= LV_DEBUG;
            break;

        case CFG_PAR_MODULE_LOG_LV_7:
            logm |= LV_START;
            break;

        default:
            if (line_num > 0)
                LogPrintf(LV_ERROR, "Config param error in line %d. Unknown log mask '%c'", line_num, mask[i]);
            else
                LogPrintf(LV_ERROR, "Config param error . Unknown log mask '%c'", mask[i]);
            exit(-1);
        }
    }
    
    return logm;
}


bool CfgParamIsComment(char *line)
{
    return CfgParIsComment(line);
}


int CfgParamStr(const char *cfg_file, const char *rparam, char *ret_val, int rsize)
{
    FILE *fp;
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char scans[CFG_LINE_MAX_SIZE];
    char prm[CFG_LINE_MAX_SIZE];
    char *param;
    int res, ret;

    if (cfg_file == NULL)
        return -1;
        
    ret = -1;
    /* configuration file is without errors! */
    fp = fopen(cfg_file, "r");
    sprintf(scans, "%s=%s", rparam, "%s %s");
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = buffer;
            while (param[0] == ' ')
                param++;
            if (param[0] != '\0') {
                res = sscanf(param, scans, prm, bufcpy);
                if (res > 0) {
                    if (strlen(prm) > rsize) {
                        LogPrintf(LV_ERROR, "Config file parameter (%s) too big", rparam);
                    }
                    else {
                        strcpy(ret_val, prm);
                        ret = 0;
                    }
                    break;
                }
            }
        }
    }

    fclose(fp);
    
    return ret;
}


int CfgParamBool(const char *cfg_file, const char *param, bool *rval)
{
    int ret;
    long val; 

    ret = CfgParamInt(cfg_file, param, &val);
    if (ret == 0) {
        if (val == 0)
            *rval = FALSE;
        else
            *rval = TRUE;
    }

    return ret;
}


int CfgParamInt(const char *cfg_file, const char *rparam, long *rval)
{
    FILE *fp;
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char scans[CFG_LINE_MAX_SIZE];
    long prm;
    char *param;
    int res, ret;

    if (cfg_file == NULL)
        return -1;
        
    ret = -1;
    /* configuration file is without errors! */
    fp = fopen(cfg_file, "r");
    sprintf(scans, "%s=%s", rparam, "%li %s");
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = buffer;
            while (param[0] == ' ')
                param++;
            if (param[0] != '\0') {
                if (strstr(param, rparam) != NULL) {
                    res = sscanf(param, scans, &prm, bufcpy);
                    if (res > 0) {
                        *rval = prm;
                        ret = 0;
                        break;
                    }
                    else {
                        LogPrintf(LV_ERROR, "Config param error: %s. See config file \"%s\"", rparam, cfg_file);
                    }
                }
            }
        }
    }

    fclose(fp);
    
    return ret;
}
