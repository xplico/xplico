/* capture.c
 * Capture dissector interface
 *
 * $Id:  $
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

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include "capture.h"
#include "config_param.h"
#include "log.h"


static void *handle;
static char* (*CaptOptions)(void);
static void (*CaptOptionsHelp)(void);
static int (*CaptMain)(int argc, char *argv[]);
static const char *(*CaptSource)(void);

int CapInit(const char *file_cfg, const char *cap)
{
    FILE *fp;
    char module_dir[CFG_LINE_MAX_SIZE];
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char mask[CFG_LINE_MAX_SIZE];
    char module_path[CFG_LINE_MAX_SIZE];
    char *param;
    int res, nl;
    unsigned short logm;

    /* find directory location of module from config file */
    fp = fopen(file_cfg, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }
    module_dir[0] = '\0';
    nl = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        nl++;
        /* check all line */
        if (strlen(buffer)+1 == CFG_LINE_MAX_SIZE) {
            LogPrintf(LV_ERROR, "Config file line more length to %d characters", CFG_LINE_MAX_SIZE);
            return -1;
        }
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            /* modules directory */
            param = strstr(buffer, CFG_PAR_MODULES_DIR);
            if (param != NULL) {
                if (module_dir[0] != '\0') {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_PAR_MODULES_DIR);
                    return -1;
                }
                res = sscanf(param, CFG_PAR_MODULES_DIR"=%s %s", module_dir, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                }
            }
            /* log mask */
            param = strstr(buffer, CFG_PAR_CAPTURE_LOG"=");
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_CAPTURE_LOG"=%s %s", mask, bufcpy);
                logm = LV_BASE;
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                    logm |= CfgParLogMask(mask, nl);
                }
                else {
                    LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, buffer);
                    return -1;
                }
                /* set mask */
                LogSetMask(LOG_COMPONENT, logm);
            }
        }
    }
    fclose(fp);

    /* module path */
    sprintf(module_path, "%s/cap_%s.so", module_dir, cap);

    /* open module */
    handle = dlopen(module_path, RTLD_NOW);
    if (handle == NULL) {
        printf("Can't load capture module %s\n", dlerror());
        return -1;
    }
    
    /* attach funztions */
    CaptOptions = dlsym(handle, CAPT_OPTIONS_FUN);
    if (CapOptions == NULL) {
        printf("Capture module don't contain function %s\n", CAPT_OPTIONS_FUN);
        return -1;
    }

    CaptOptionsHelp = dlsym(handle, CAPT_OPTIONS_HELP_FUN);
    if (CapOptionsHelp == NULL) {
        printf("Capture module don't contain function %s\n", CAPT_OPTIONS_HELP_FUN);
        return -1;
    }

    CaptMain = dlsym(handle, CAPT_MAIN_FUN);
    if (CapMain == NULL) {
        printf("Capture module don't contain function %s\n", CAPT_MAIN_FUN);
        return -1;
    }

    CaptSource = dlsym(handle, CAPT_SOURCE_FUN);
    
    return 0;
}


char* CapOptions(void)
{
    if (CaptOptions != NULL)
        return CaptOptions();
    return "";
}


void CapOptionsHelp(void)
{
    if (CaptOptionsHelp != NULL)
        return CaptOptionsHelp();
}


int CapMain(int argc, char *argv[])
{
    if (CaptMain != NULL)
        return CaptMain(argc, argv);
    return -1;
}


const char *CapSource(void)
{
    if (CaptSource != NULL)
        return CaptSource();
    return "Unknown!";
}

