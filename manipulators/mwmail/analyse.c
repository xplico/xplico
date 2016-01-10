/* analyse.c
 * analyse stack and time to realise pei
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "log.h"
#include "analyse.h"
#include "proto.h"
#include "dmemory.h"
#include "pei.h"
#include "fileformat.h"
#include "libero.h"
#include "rossoalice.h"

/* http id */
static int http_id;
static int http_encoding_id;
/* webamil */
static int prot_id;
static int pei_service_id;
static int pei_url_id;
static int pei_client_id;
static int pei_host_id;
static int pei_req_header_id;
static int pei_req_body_id;
static int pei_res_header_id;
static int pei_res_body_id;
static int pei_serv_id;
static int pei_dir_id;
static int pei_to_id;
static int pei_from_id;
static int pei_cc_id;
static int pei_sent_id;
static int pei_rec_id;
static int pei_messageid_id;
static int pei_subj_id;
static int pei_eml_id;
static int pei_html_id;
static int pei_txt_id;

/* webmail variables */
static volatile unsigned short inc;
static email_libero *libero;
static ralice *alice;
static unsigned int yahoo_m;
static unsigned int aol_m;
static unsigned int gmail_m;
static unsigned int hotmail_m;
static unsigned int yandroid_m;
static unsigned int libero_m;
static unsigned int alice_m;



static pei *WMail2Pei(const char *filename, const pei *mpei, char *dir)
{
    char line[LINE_MAX_SIZE];
    pei *new;
    FILE *fp;
    bool ret;
    int res;
    pei_component *cmpn;

    new = NULL;
    ret = FALSE;
    fp = fopen(filename, "r");
    if (fp != NULL) {
        /* create a PEI */
        PeiNew(&new, prot_id);
        PeiCapTime(new, mpei->time_cap);
        PeiMarker(new, mpei->serial);
        PeiStackFlow(new, mpei->stack);
        /* component */
        //LogPrintf(LV_DEBUG, "Info file: %s", filename);
        while (fgets(line, LINE_MAX_SIZE, fp) != NULL) {
            line[LINE_MAX_SIZE-1] = '\0';
            /* subject */
            res = strncmp(line, WMAIL_FLD_SUBJECT, WMAIL_FLD_SUBJECT_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_subj_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_SUBJECT_DIM);
                PeiAddComponent(new, cmpn);
                ret = TRUE;
                continue;
            }
            res = strncmp(line, WMAIL_FLD_FROM, WMAIL_FLD_FROM_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_from_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_FROM_DIM);
                PeiAddComponent(new, cmpn);
                ret = TRUE;
                continue;
            }
            res = strncmp(line, WMAIL_FLD_TO, WMAIL_FLD_TO_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_to_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_TO_DIM);
                PeiAddComponent(new, cmpn);
                ret = TRUE;
                continue;
            }
            res = strncmp(line, WMAIL_FLD_CC, WMAIL_FLD_CC_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_cc_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_CC_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_MESSAGEID, WMAIL_FLD_MESSAGEID_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_messageid_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_MESSAGEID_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_RECEIVED, WMAIL_FLD_RECEIVED_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_rec_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_RECEIVED_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_SENT, WMAIL_FLD_SENT_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_sent_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddStingBuff(cmpn, line+WMAIL_FLD_SENT_DIM);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_HTML, WMAIL_FLD_HTML_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_html_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddFile(cmpn, "mail.html", strchr(line, ':')+1, 0);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_TXT, WMAIL_FLD_TXT_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_txt_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddFile(cmpn, "mail.txt", strchr(line, ':')+1, 0);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_EML, WMAIL_FLD_EML_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                PeiNewComponent(&cmpn, pei_eml_id);
                PeiCompCapTime(cmpn, mpei->time_cap);
                PeiCompAddFile(cmpn, "mail.eml", line+WMAIL_FLD_EML_DIM, 0);
                PeiAddComponent(new, cmpn);
                continue;
            }
            res = strncmp(line, WMAIL_FLD_FILENAME, WMAIL_FLD_FILENAME_DIM);
            if (res == 0) {
                line[strlen(line)-1] = '\0';
                LogPrintfPei(LV_WARNING, mpei, "Attached filename: %s", line+WMAIL_FLD_FILENAME_DIM);
                continue;
            }
        }
        fclose(fp);
        remove(filename);
    }
    if (ret == FALSE) {
        PeiFree(new);
        new = NULL;
    }
    else {
        /* dir */
        PeiNewComponent(&cmpn, pei_dir_id);
        PeiCompCapTime(cmpn, mpei->time_cap);
        PeiCompAddStingBuff(cmpn, dir);
        PeiAddComponent(new, cmpn);
    }

    return new;
}


static pei *WMYahoo(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;

    resp[0] = '\0';

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_dir_id) {
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (rqb == NULL && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/yahoo_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_yahoo.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_yahoo.pyc %s %s", rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) error: %s", rsb);
        }
    }
    else if (rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/yahoo_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rqb, inc++);
        sprintf(cmd, "./wbm_yahoo.pyc -s %s %s", rqb, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo python (wbm_yahoo.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "Yahoo");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Yahoo python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMYahooV2(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    bool out;
    struct stat finfo;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/yahoo_v2_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_yahoo_v2.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_yahoo_v2.pyc %s %s", rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/yahoo_v2_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rqb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_yahoo_v2.pyc -s %s %s %s", rqb, new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_yahoo_v2.pyc -s %s %s %s", rqb, rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) system error: %s %s", rqb, rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo v2 python (wbm_yahoo_v2.pyc) error: %s %s", rqb, rsb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "Yahoo");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                    yahoo_m++;
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Yahoo v2 python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMYahooAndroid(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb;
    char dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    FILE *fp;

    resp[0] = '\0';

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    dir = 'r';
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
            /* check if sent or not */
            fp = fopen(rqb, "r");
            if (fp != NULL) {
                fread(resp, 1, WMAIL_STR_DIM, fp);
                fclose(fp);
                if (strncmp(resp, "ac=SendMessage&appid=", 21) == 0) {
                    dir = 's';
                }
            }
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (rqb != NULL && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/yahoo_android_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            if (dir == 'r') {
                sprintf(cmd, "./wbm_yahoo_android.pyc %s %s", new_path, resp);
            }
            else {
                sprintf(cmd, "./wbm_yahoo_android.pyc -s %s %s %s", rqb, new_path, resp);
            }
        }
        else {
            /* not compressed */
            if (dir == 'r') {
                sprintf(cmd, "./wbm_yahoo_android.pyc %s %s", rsb, resp);
            }
            else {
                sprintf(cmd, "./wbm_yahoo_android.pyc -s %s %s %s", rqb, rsb, resp);
            }
        }
        LogPrintf(LV_DEBUG, "%s", cmd);
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo Android python (wbm_yahoo_android.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Yahoo Android python (wbm_yahoo_android.pyc) error: %s", rsb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, &dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "Yahoo Android");
                    PeiAddComponent(new_pei, cmpn);
                    //PeiPrint(new_pei);
                    PeiIns(new_pei);
                    yandroid_m++;
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Yahoo Android python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMAol(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }

    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/aol_out_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_aol.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_aol.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/aol_in_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rqb, inc++);
        sprintf(cmd, "./wbm_aol.pyc -s %s %s", rqb, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL python (wbm_aol.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "AOL");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "AOL python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMAolV2(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }

    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/aol_v2_out_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_aol_v2.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_aol_v2.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL && rsb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/aol_v2_in_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rqb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_aol_v2.pyc -s %s %s %s", rqb, new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_aol_v2.pyc -s %s %s %s", rqb, rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "AOL v2 python (wbm_aol_v2.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "AOL");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                    aol_m++;
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "AOL v2 python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}

static pei *WMGmail(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }

    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/gmail_out_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_gmail.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_gmail.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL && rsb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/gmail_in_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rqb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_gmail.pyc -s %s %s %s %s", rqh, rqb, new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_gmail.pyc -s %s %s %s %s", rqh, rqb, rsb, resp);
        }

        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Gmail python (wbm_gmail.pyc) error: %s", rqb);
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "GMail");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                    gmail_m++;
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Gmail python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMHotmail(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/live_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_live.pyc %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_live.pyc %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL) {
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/live_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rqb, inc++);
        sprintf(cmd, "./wbm_live.pyc -s %s %s", rqb, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Live python (wbm_live.pyc) error: %s", rqb);
        }     
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "Live");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_WARNING, ppei, "Live python Decoding failed");
                    LogPrintf(LV_WARNING, "%s", rsb);
                    LogPrintf(LV_WARNING, "%s", rqb);
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


static int WMRossoAliceDU(const char *url, char *user, char *domain)
{
    const char *tmp, *tmp1;

    tmp = strstr(url, "?d=");
    if (tmp == NULL) {
        tmp = strstr(url, "&d=");
    }
    if (tmp != NULL) {
        tmp += 3;
        tmp1 = strstr(tmp, "&");
        if (tmp1 != NULL) {
            strncpy(domain, tmp, tmp1-tmp);
            domain[tmp1-tmp] = '\0';
        }
    }

    tmp = strstr(url, "u=");
    if (tmp != NULL) {
        if (tmp != url && (tmp-1)[0] != '&')
            return -1;
        tmp += 2;
        tmp1 = strstr(tmp, "&");
        if (tmp1 != NULL) {
            strncpy(user, tmp, tmp1-tmp);
            user[tmp1-tmp] = '\0';
        }
    }
    
    return 0;
}

static int WMRossoAliceUID(const char *line, char *uid)
{
    const char *tmp, *tmp1;

    tmp = strstr(line, "&uid=");
    if (tmp != NULL) {
        tmp += 5;
        tmp1 = strstr(tmp, "&");
        if (tmp1 != NULL) {
            strncpy(uid, tmp, tmp1-tmp);
            uid[tmp1-tmp] = '\0';
        }
    }
    
    return 0;
}

    
static pei *WMRossoAlice(pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval enc;
    char usr[RALICE_STR_SIZE];
    char domain[RALICE_STR_SIZE];
    char email[RALICE_STR_SIZE];
    char uid[RALICE_STR_SIZE];
    char line[RALICE_STR_SIZE];
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    bool header;
    int ret, i;
    ralice *aemail, *pre;
    pei *new_pei;
    struct stat finfo;
    FILE *fp;
    
    //PeiPrint(ppei);
    
    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &enc);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    usr[0] = domain[0] = uid[0] = resp[0] = '\0';
    header = FALSE;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            WMRossoAliceDU(url, usr, domain);
            if (strstr(url, "SLEmailHeaders?") != NULL) {
                header = TRUE;
            }
        }
        else if (cmpn->eid == pei_dir_id) {
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
            remove(rqh);
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
            if (uid[0] == '\0') {
                fp = fopen(rqb, "r");
                if (fp != NULL) {
                    if (fread(line, 1, RALICE_STR_SIZE, fp) > 0) {
                        WMRossoAliceUID(line, uid);
                        if (usr[0] == '\0') {
                            WMRossoAliceDU(line, usr, domain);
                        }
                    }
                    fclose(fp);
                }
            }
            //LogPrintf(LV_DEBUG, "-> %s", rqb);
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
            remove(rsh);
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    if (dir[0] == 's') { /* sent */
        if (usr[0] != '\0' &&  domain[0] != '\0' && rqb != NULL) {
            sprintf(email, "%s@%s", usr, domain);
            /* received */
            sprintf(resp, "%s/rossoalice_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rqb, inc++);
            sprintf(cmd, "./wbm_rossoalice.pyc -s %s %s %s", email, rqb, resp);
            /* extract all information:
                from, to, cc, bcc, subject, email */
            ret = system(cmd);
            remove(rqb);
            remove(rsb);
            if (ret == -1) {
                LogPrintfPei(LV_WARNING, aemail->ppei, "Alice TelecomItalia python (wbm_rossoalice.pyc) system error");
                LogPrintf(LV_DEBUG, "Files: %s", rqb);
            }
            else if (WEXITSTATUS(ret) != 0) {
                LogPrintfPei(LV_WARNING, aemail->ppei, "Alice TelecomItalia python (wbm_rossoalice.pyc) error");
                LogPrintf(LV_DEBUG, "Files: %s", rqb);
            }
            alice_m++;
        }
    }
    else if (usr[0] != '\0' &&  domain[0] != '\0' &&  uid[0] != '\0') { /* received */
        remove(rqb);
        sprintf(email, "%s@%s", usr, domain);
        LogPrintf(LV_STATUS, "%s %s", email, uid);
        pre = NULL;
        aemail = alice;
        while (aemail != NULL) {
            if (strcmp(aemail->ref, email) == 0) {
                if (strcmp(aemail->uid, uid) == 0) {
                    break;
                }
            }
            pre = aemail;
            aemail = aemail->nxt;
        }
        if (aemail == NULL) {
            /* new email */
            aemail = xcalloc(1, sizeof(ralice));
            if (aemail == NULL) {
                LogPrintf(LV_ERROR, "Out of memory");
                return NULL;
            }
            strncpy(aemail->ref, email, RALICE_STR_SIZE);
            strncpy(aemail->uid, uid, RALICE_STR_SIZE);
            aemail->ppei = ppei;
            ppei = NULL;
            pre = NULL;
            aemail->nxt = alice;
            alice = aemail;
        }
        if (header) {
            if (enc.str[0] != '\0') {
                /* compressed */
                sprintf(new_path, "%s.dec", rsb);
                FFormatUncompress(enc.str, rsb, new_path);
                remove(rsb);
                strncpy(aemail->header, new_path, RALICE_STR_SIZE);
            }
            else
                strncpy(aemail->header, rsb, RALICE_STR_SIZE);
        }
        else {
            if (enc.str[0] != '\0') {
                /* compressed */
                sprintf(new_path, "%s.dec", rsb);
                FFormatUncompress(enc.str, rsb, new_path);
                remove(rsb);
                strncpy(aemail->body, new_path, RALICE_STR_SIZE);
            }
            else
                strncpy(aemail->body, rsb, RALICE_STR_SIZE);
        }
        if (aemail->body[0] != '\0' && aemail->header != '\0') {
            /* add stack */
            PeiAddStkGrp(aemail->ppei, ppei->stack);
            PeiFree(ppei);
            ppei = NULL;
            /* received */
            sprintf(resp, "%s/rossoalice_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
            sprintf(cmd, "./wbm_rossoalice.pyc %s %s %s %s", aemail->ref, aemail->header, aemail->body, resp);
        
            /* extract all information:
                from, to, cc, bcc, subject, email */
            ret = system(cmd);
            if (ret == -1) {
                LogPrintfPei(LV_WARNING, aemail->ppei, "Alice TelecomItalia python (wbm_rossoalice.pyc) system error");
                LogPrintf(LV_DEBUG, "Files: %s %s", aemail->header, aemail->body);
            }
            else if (WEXITSTATUS(ret) != 0) {
                LogPrintfPei(LV_WARNING, aemail->ppei, "Alice TelecomItalia python (wbm_rossoalice.pyc) error");
                LogPrintf(LV_DEBUG, "Files: %s %s", aemail->header, aemail->body);
            }
            /* remove from list */
            if (pre != NULL && pre->nxt != aemail)
                LogPrintfPei(LV_ERROR, aemail->ppei, "Email Alice TelecomItalia list bug");
            else {
                if (pre == NULL)
                    alice = aemail->nxt;
                else
                    pre->nxt = aemail->nxt;
                remove(aemail->header);
                remove(aemail->body);
                ppei = aemail->ppei;
                aemail->ppei = NULL;
                xfree(aemail);
                aemail = NULL;
            }
            alice_m++;
        }
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "Alice");
                    PeiAddComponent(new_pei, cmpn);
                    //PeiPrint(new_pei);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Alice Telecom Italai python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }
    
    if (ppei != NULL)
        PeiFree(ppei);

    FTFree(&enc, FT_STRING);
    
    return NULL;
}


static pei *WMLiberoOld(const pei *ppei)
{
    return NULL;
}


static pei *WMLibero(pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    char *pid, *pide;
    email_libero *lemail, *pre;
    pei *new_pei;
    struct stat finfo;
    bool lbody;
    
    resp[0] = '\0';

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_dir_id) {
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
            remove(rqh);
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
            remove(rsh);
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }

    /* check and complete the email data */
    if (url == NULL) {
        LogPrintfPei(LV_WARNING, ppei, "Libero WebMail without url!");
        return NULL;
    }
    
    if (strstr(url, "MailMessageBody") != NULL) /* header or body */
        lbody = TRUE;
    else
        lbody = FALSE;
    
    pid = strstr(url, "&pid=");
    if (pid == NULL) {
        printf("%s\n", url);
        PeiPrint(ppei);
        exit(-1);
        LogPrintfPei(LV_WARNING, ppei, "Unable to decode Libero WebMail. Possible new version!");
        return NULL;
    }
    pid += 5;
    pide = strstr(pid, "&");
    if (pide != NULL)
        pide[0] = '\0';
    
    pre = NULL;
    lemail = libero;
    while (lemail != NULL) {
        if (strcmp(lemail->pid, pid) == 0)
            break;
        pre = lemail;
        lemail = lemail->next;
    }
    if (lemail == NULL) {
        /* new email */
        lemail = xcalloc(1, sizeof(email_libero));
        if (lemail == NULL) {
            LogPrintf(LV_ERROR, "Out of memory");
            return NULL;
        }
        strncpy(lemail->pid, pid, LIBERO_STR_SIZE);
        lemail->ppei = ppei;
        ppei = NULL;
        pre = NULL;
        lemail->next = libero;
        libero = lemail;
    }
    if (lbody) {
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            strncpy(lemail->body, new_path, LIBERO_STR_SIZE);
        }
        else
            strncpy(lemail->body, rsb, LIBERO_STR_SIZE);
    }
    else {
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            strncpy(lemail->header, new_path, LIBERO_STR_SIZE);
        }
        else
            strncpy(lemail->header, rsb, LIBERO_STR_SIZE);
    }
    
    /* sent or received */
    if (rqb == NULL && lemail != NULL && lemail->body[0] != '\0' && lemail->header[0] != '\0') {
        /* add stack */
        PeiAddStkGrp(lemail->ppei, ppei->stack);
        PeiFree(ppei);
        ppei = NULL;
        /* received */
        sprintf(resp, "%s/libero_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        sprintf(cmd, "./wbm_libero.pyc %s %s %s", lemail->header, lemail->body, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, lemail->ppei, "Libero python (wbm_libero.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, lemail->ppei, "Libero python (wbm_libero.pyc) error: %s", rsb);
        }
        /* remove from list */
        if (pre != NULL && pre->next != lemail)
            LogPrintfPei(LV_ERROR, lemail->ppei, "Email Libero list bug");
        else {
            if (pre == NULL)
                libero = lemail->next;
            else
                pre->next = lemail->next;
            remove(lemail->header);
            remove(lemail->body);
            ppei = lemail->ppei;
            lemail->ppei = NULL;
            xfree(lemail);
            lemail = NULL;
        }
    }
    else if (rqb != NULL) {
#if 0
        /* sent */
        /* extract all information:
           from, to, cc, bcc, subject, email */
        sprintf(resp, "%s/%s/libero_%lu_%p_%i", ProtTmpDir(), WEBMAIL_TMP_DIR, time(NULL), rqb, inc++);
        sprintf(cmd, "./wbm_libero.pyc -s %s %s", rqb, resp);
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Libero python (wbm_libero.pyc) system error: %s", rqb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Libero python (wbm_libero.pyc) error: %s", rqb);
        }
#endif
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "Libero");
                    PeiAddComponent(new_pei, cmpn);
                    //PeiPrint(new_pei);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_ERROR, ppei, "Libero python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    if (ppei != NULL)
        PeiFree(ppei);

    FTFree(&val, FT_STRING);
    return NULL;
}


static pei *WMLiberoMobi(const pei *ppei)
{
    char *url, *rqh, *rsh, *rqb, *rsb, *dir;
    pei_component *cmpn;
    const pstack_f *frame;
    ftval val;
    char new_path[WMAIL_STR_DIM];
    char resp[WMAIL_STR_DIM];
    char cmd[WMAIL_STR_DIM*2];
    int ret, i;
    pei *new_pei;
    struct stat finfo;
    bool out;

    resp[0] = '\0';
    out = FALSE;

    /* encoding */
    frame = ProtStackSearchProt(ppei->stack, http_id);
    if (frame) {
        ProtGetAttr(frame, http_encoding_id, &val);
    }
    url = rqh = rsh = rqb = rsb = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dir_id) {
            if (strcmp(cmpn->strbuf, "r") == 0)
                out = FALSE;
            else if (strcmp(cmpn->strbuf, "s") == 0)
                out = TRUE;
            dir = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
            url = url;
        }
        else if (cmpn->eid == pei_req_header_id) {
            rqh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_req_body_id) {
            rqb = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_header_id) {
            rsh = cmpn->file_path;
        }
        else if (cmpn->eid == pei_res_body_id) {
            rsb = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    
    /* sent or received */
    if (!out && rsb != NULL) {
        /* received */
        sprintf(resp, "%s/libero_%lld_%p_%i", ProtTmpDir(), (long long)time(NULL), rsb, inc++);
        if (val.str[0] != '\0') {
            /* compressed */
            sprintf(new_path, "%s.dec", rsb);
            FFormatUncompress(val.str, rsb, new_path);
            remove(rsb);
            sprintf(cmd, "./wbm_libero.pyc -m %s %s", new_path, resp);
        }
        else {
            /* not compressed */
            sprintf(cmd, "./wbm_libero.pyc -m %s %s", rsb, resp);
        }
        
        /* extract all information:
           from, to, cc, bcc, subject, email */
        ret = system(cmd);
        if (ret == -1) {
            LogPrintfPei(LV_WARNING, ppei, "Libero python (wbm_libero.pyc) system error: %s", rsb);
        }
        else if (WEXITSTATUS(ret) != 0) {
            LogPrintfPei(LV_WARNING, ppei, "Libero python (wbm_libero.pyc) error: %s", rsb);
        }
    }
    else if (out && rqb != NULL) {
    }

    if (resp[0] != '\0') {
        /* mail decoded */
        i = 0;
        do {
            sprintf(new_path, "%s_%d", resp, i);
            if (stat(new_path, &finfo) == 0) {
                new_pei = WMail2Pei(new_path, ppei, dir);
                if (new_pei != NULL) {
                    /* service type */
                    PeiNewComponent(&cmpn, pei_serv_id);
                    PeiCompCapTime(cmpn, ppei->time_cap);
                    PeiCompAddStingBuff(cmpn, "Libero");
                    PeiAddComponent(new_pei, cmpn);
                    PeiIns(new_pei);
                }
                else {
                    LogPrintfPei(LV_WARNING, ppei, "Live python Decoding failed");
                }
                i++;
            }
            else {
                /* end */
                i = 0;
            }
        } while (i);
    }

    FTFree(&val, FT_STRING);
    return NULL;
}


int AnalyseInit(void)
{    
    /* initialize */
    inc = 0;
    yahoo_m = aol_m = hotmail_m = yandroid_m = gmail_m = 0;
    libero_m = alice_m = 0;
    libero = NULL;
    alice = NULL;
    
    http_id = ProtId("http");
    if (http_id != -1) {
        http_encoding_id = ProtAttrId(http_id, "http.content_encoding");
    }
      
    prot_id = ProtId("webmail");
    if (prot_id != -1) {
        pei_service_id = ProtPeiComptId(prot_id, "service");
        pei_dir_id = ProtPeiComptId(prot_id, "dir");
        pei_url_id = ProtPeiComptId(prot_id, "url");
        pei_client_id = ProtPeiComptId(prot_id, "client");
        pei_host_id = ProtPeiComptId(prot_id, "host");
        pei_req_header_id = ProtPeiComptId(prot_id, "req.header");
        pei_req_body_id = ProtPeiComptId(prot_id, "req.body");
        pei_res_header_id = ProtPeiComptId(prot_id, "res.header");
        pei_res_body_id = ProtPeiComptId(prot_id, "res.body");
        /* components added */
        pei_serv_id = ProtPeiComptId(prot_id, "serv");
        pei_to_id = ProtPeiComptId(prot_id, "to");
        pei_from_id = ProtPeiComptId(prot_id, "from");
        pei_cc_id = ProtPeiComptId(prot_id, "cc");
        pei_sent_id = ProtPeiComptId(prot_id, "sent");
        pei_rec_id = ProtPeiComptId(prot_id, "rec");
        pei_messageid_id = ProtPeiComptId(prot_id, "id");
        pei_subj_id = ProtPeiComptId(prot_id, "subject");
        pei_eml_id = ProtPeiComptId(prot_id, "eml");
        pei_html_id = ProtPeiComptId(prot_id, "html");
        pei_txt_id = ProtPeiComptId(prot_id, "txt");
    }
    
    return 0;
}


int AnalysePei(pei *ppei)
{
    pei_component *cmpn;
    char *unck;
    pei *npei;
    service type;

    if (ppei == NULL)
        return 0;
    
    if (ppei->ret == TRUE) {
        ProtStackFrmDisp(ppei->stack, TRUE);
        LogPrintfPei(LV_WARNING, ppei, "Pei with return!");
    }
    npei = NULL;
    unck = NULL;
    
    /* identify the servce type */
    type = WMS_NONE;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_service_id) {
            unck = cmpn->strbuf;
            if (strcmp(cmpn->strbuf, WMAIL_SERVICE_GMAIL) == 0) {
                type = WMS_GMAIL;
            }
            if (strcmp(cmpn->strbuf, WMAIL_SERVICE_YAHOO) == 0) {
                type = WMS_YAHOO;
            }
            if (strcmp(cmpn->strbuf, WMAIL_SERVICE_YAHOO_V2) == 0) {
                type = WMS_YAHOO_V2;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_YAHOO_ANDRO) == 0) {
                type = WMS_YAHOO_DRIOD;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_AOL) == 0) {
                type = WMS_AOL;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_AOL_V2) == 0) {
                type = WMS_AOL_V2;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_HOTMAIL) == 0) {
                type = WMS_HOTMAIL;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_ROSSOALICE) == 0) {
                type = WMS_ROSSOALICE;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_LIBERO_OLD) == 0) {
                type = WMS_LIBERO_OLD;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_LIBERO_MOBI) == 0) {
                type = WMS_LIBERO_MOBI;
            }
            else if (strcmp(cmpn->strbuf, WMAIL_SERVICE_LIBERO) == 0) {
                type = WMS_LIBERO;
            }
            break;
        }
    }
    /* extract mail */
    switch (type) {
    case WMS_GMAIL:
        npei = WMGmail(ppei);
        PeiDestroy(ppei);
        break;

    case WMS_YAHOO:
        npei = WMYahoo(ppei);

        PeiDestroy(ppei);
        yahoo_m++;
        break;

    case WMS_YAHOO_V2:
        npei = WMYahooV2(ppei);

        PeiDestroy(ppei);
        break;

    case WMS_YAHOO_DRIOD:
        npei = WMYahooAndroid(ppei);

        PeiDestroy(ppei);
        break;

    case WMS_AOL:
        npei = WMAol(ppei);

        PeiDestroy(ppei);
        aol_m++;
        break;

    case WMS_AOL_V2:
        npei = WMAolV2(ppei);

        PeiDestroy(ppei);
        break;

    case WMS_HOTMAIL:
        npei = WMHotmail(ppei);

        PeiDestroy(ppei);
        hotmail_m++;
        break;
        
    case WMS_ROSSOALICE:
        npei = WMRossoAlice(ppei);
        break;

    case WMS_LIBERO_OLD:
        npei = WMLiberoOld(ppei);

        PeiDestroy(ppei);
        libero_m++;
        break;

    case WMS_LIBERO:
        npei = WMLibero(ppei);
        libero_m++;
        break;

    case WMS_LIBERO_MOBI:
        npei = WMLiberoMobi(ppei);

        PeiDestroy(ppei);
        libero_m++;
        break;

    case WMS_NONE:
        LogPrintfPei(LV_WARNING, ppei,"Web mail unknown: %s", unck);
    }
    
    if (npei != NULL) {
        PeiIns(npei);
    }

    return 0;
}


int AnalyseEnd(void)
{
    LogPrintf(LV_STATUS, "-------------------------");
    LogPrintf(LV_STATUS, "Mails statistics:");
    LogPrintf(LV_STATUS, "   Gmail: %d", gmail_m);
    LogPrintf(LV_STATUS, "   Yahoo!: %d", yahoo_m);
    LogPrintf(LV_STATUS, "   AOL: %d", aol_m);
    LogPrintf(LV_STATUS, "   HotMail/Live: %d", hotmail_m);
    LogPrintf(LV_STATUS, "   Yahoo! Android: %d", yandroid_m);
    LogPrintf(LV_STATUS, "   Libero: %d", libero_m);
    LogPrintf(LV_STATUS, "   Alice: %d", alice_m);
    LogPrintf(LV_STATUS, "-------------------------");
    
    return 0;
}

