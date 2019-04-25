/* ftp.c
 * ftp packet dissection
 * RFC 959, RFC 1639, RFC 2428
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on: packet-ftp.c of Wireshark
 *   Copyright 1998 Gerald Combs
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

#include <pcap.h>
#include <stdio.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>
#include <sys/types.h>
#include <fcntl.h>

#include "etypes.h"
#include "proto.h"
#include "dmemory.h"
#include "log.h"
#include "ftp.h"
#include "strutil.h"
#include "pei.h"
#include "grp_flows.h"
#include "dnsdb.h"

#define FTP_TMP_DIR    "ftp"

/* info id */
static int ip_id;
static int ipv6_id;
static int ip_src_id;
static int ip_dst_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int tcp_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int clnt_id;
static int ftp_id;

/* pei id */
static int pei_url_id;
static int pei_user_id;
static int pei_pswd_id;
static int pei_cmd_id;
static int pei_file_in_id;
static int pei_file_out_id;
static int pei_file_offset_id;
static int pei_down_n_id;
static int pei_up_n_id;

static volatile unsigned int incr;

static ftp_rep_code rep_code[] = {
    {110, FTP_REP_110},
    {120, FTP_REP_120},
    {125, FTP_REP_125},
    {150, FTP_REP_150},
    {200, FTP_REP_200},
    {202, FTP_REP_202},
    {211, FTP_REP_211},
    {212, FTP_REP_212},
    {213, FTP_REP_213},
    {214, FTP_REP_214},
    {215, FTP_REP_215},
    {220, FTP_REP_220},
    {221, FTP_REP_221},
    {225, FTP_REP_225},
    {226, FTP_REP_226},
    {227, FTP_REP_227},
    {229, FTP_REP_229},
    {230, FTP_REP_230},
    {250, FTP_REP_250},
    {257, FTP_REP_257},
    {331, FTP_REP_331},
    {332, FTP_REP_332},
    {350, FTP_REP_350},
    {421, FTP_REP_421},
    {425, FTP_REP_425},
    {426, FTP_REP_426},
    {450, FTP_REP_450},
    {451, FTP_REP_451},
    {452, FTP_REP_452},
    {500, FTP_REP_500},
    {501, FTP_REP_501},
    {502, FTP_REP_502},
    {503, FTP_REP_503},
    {504, FTP_REP_504},
    {530, FTP_REP_530},
    {532, FTP_REP_532},
    {550, FTP_REP_550},
    {551, FTP_REP_551},
    {552, FTP_REP_552},
    {553, FTP_REP_553}
};


static void FtpConInit(ftp_con *ftp, ftp_priv *priv)
{
    memset(ftp, 0, sizeof(ftp_con));
    ftp->file_cmd = DMemMalloc(FTP_FILENAME_PATH_SIZE);
    ftp->file_cmd[0] = '\0';
    ftp->user = DMemMalloc(FTP_USER_PWD_DIM);
    ftp->user[0] = '\0';
    ftp->passwd = DMemMalloc(FTP_USER_PWD_DIM);
    ftp->passwd[0] = '\0';
    ftp->data_setup = FALSE;
    ftp->up_n = 0;
    ftp->down_n = 0;
    ftp->rule = -1;
    ftp->cmd_rl = FTP_CMD_NONE;
    if (priv->ipv6) {
        if (priv->dir == FTP_CLT_DIR_OK)
            FTCopy(&(ftp->ip_clnt), &(priv->ip), FT_IPv6);
        else
            FTCopy(&(ftp->ip_clnt), &(priv->ipd), FT_IPv6);
    }
    else{
        if (priv->dir == FTP_CLT_DIR_OK)
            FTCopy(&(ftp->ip_clnt), &(priv->ip), FT_IPv4);
        else
            FTCopy(&(ftp->ip_clnt), &(priv->ipd), FT_IPv4);
    }
}


static void FtpConFree(ftp_con *ftp)
{
    if (ftp->file_cmd != NULL)
        DMemFree(ftp->file_cmd);
    ftp->file_cmd = NULL;
    
    if (ftp->user != NULL)
        DMemFree(ftp->user);
    ftp->user = NULL;

    if (ftp->passwd != NULL)
        DMemFree(ftp->passwd);
    ftp->passwd = NULL;

    if (ftp->rule != -1)
        GrpRuleRm(ftp->rule);
}


static int FtpDataInit(ftp_data *ftpd)
{
    memset(ftpd, 0, sizeof(ftp_data));
    ftpd->fid = -1;
    ftpd->fp = NULL;
    ftpd->cmd = FTP_CMD_NONE;
    ftpd->lost = FALSE;

    return 0;
}


static int FtpDataFree(ftp_data *ftpd)
{
    if (ftpd->fp != NULL) {
        LogPrintf(LV_ERROR, "File (%s) not closed", ftpd->file);
        fclose(ftpd->fp);
        ftpd->fp = NULL;
    }
    if (ftpd->buff != NULL) {
        xfree(ftpd->buff);
        ftpd->buff = NULL;
    }
    if (ftpd->filename != NULL) {
        DMemFree(ftpd->filename);
        ftpd->filename = NULL;
    }
    if (ftpd->file != NULL) {
        DMemFree(ftpd->file);
        ftpd->file = NULL;
    }
    if (ftpd->stack != NULL) {
        ProtDelFrame(ftpd->stack);
        ftpd->stack = NULL;
    }
    if (ftpd->gstack != NULL) {
        ProtDelFrame(ftpd->gstack);
        ftpd->gstack = NULL;
    }

    return 0;
}


static ftp_cmd FtpCommand(const char *line, int linelen)
{
    const char *ptr;
    int	index = 0;

    ptr = (const char *)line;
    /* Look for the space following the command */
    while (index < linelen) {
        if (*ptr == ' ' || *ptr == '\r' || *ptr == '\n')
            break;
        else {
            ptr++;
            index++;
        }
    }

    /* Check the commands that have same length */
    if (index == 3) {
        if (strncasecmp(line, "CWD", index) == 0) {
            return FTP_CMD_CWD;
        }
        else if (strncasecmp(line, "RMD", index) == 0) {
            return FTP_CMD_RMD;
        }
        else if (strncasecmp(line, "MKD", index) == 0) {
            return FTP_CMD_MKD;
        }
        else if (strncasecmp(line, "PWD", index) == 0) {
            return FTP_CMD_PWD;
        }
        else if  (strncasecmp(line, "ENC", index) == 0) {
            return FTP_CMD_ENC;
        }
        else if  (strncasecmp(line, "CCC", index) == 0) {
            return FTP_CMD_CCC;
        }
    }
    else {
        switch (line[0]) {
        case 'A':
        case 'a':
            if (strncasecmp(line, "ACCT", index) == 0) {
                return FTP_CMD_ACCT;
            }
            else if (strncasecmp(line, "APPE", index) == 0) {
                return FTP_CMD_APPE;
            }
            else if (strncasecmp(line, "ALLO", index) == 0) {
                return FTP_CMD_ALLO;
            }
            else if (strncasecmp(line, "ABOR", index) == 0) {
                return FTP_CMD_ABOR;
            }
            else if (strncasecmp(line, "ADAT", index) == 0) {
                return FTP_CMD_ADAT;
            }
            else if (strncasecmp(line, "AUTH", index) == 0) {
                return FTP_CMD_AUTH;
            }
            break;
            
        case 'C':
        case 'c':
            if (strncasecmp(line, "CDUP", index) == 0) {
                return FTP_CMD_CDUP;
            }
            else if (strncasecmp(line, "CONF", index) == 0) {
                return FTP_CMD_CONF;
            }
            else if (strncasecmp(line, "CLNT", index) == 0) {
                return FTP_CMD_CLNT;
            }
            break;

        case 'D':
        case 'd':
            if (strncasecmp(line, "DELE", index) == 0) {
                return FTP_CMD_DELE;
            }
            break;

        case 'E':
        case 'e':
            if (strncasecmp(line, "EPRT", index) == 0) {
                return FTP_CMD_EPRT;
            }
            else if (strncasecmp(line, "EPSV", index) == 0) {
                return FTP_CMD_EPSV;
            }
            break;

        case 'F':
        case 'f':
            if (strncasecmp(line, "FEAT", index) == 0) {
                return FTP_CMD_FEAT;
            }
            break;

        case 'H':
        case 'h':
            if (strncasecmp(line, "HELP", index) == 0) {
                return FTP_CMD_HELP;
            }
            break;

        case 'L':
        case 'l':
            if (strncasecmp(line, "LIST", index) == 0) {
                return FTP_CMD_LIST;
            }
            else if (strncasecmp(line, "LPRT", index) == 0) {
                return FTP_CMD_LPRT;
            }
            else if (strncasecmp(line, "LPSV", index) == 0) {
                return FTP_CMD_LPSV;
            }
            else if (strncasecmp(line, "LANG", index) == 0) {
                return FTP_CMD_LANG;
            }
            break;

        case 'M':
        case 'm':
            if (strncasecmp(line, "MODE", index) == 0) {
                return FTP_CMD_MODE;
            }
            else if (strncasecmp(line, "MDTM", index) == 0) {
                return FTP_CMD_MDTM;
            }
            else if (strncasecmp(line, "MLST", index) == 0) {
                return FTP_CMD_MLST;
            }
            else if (strncasecmp(line, "MLSD", index) == 0) {
                return FTP_CMD_MLSD;
            }
            break;

        case 'N':
        case 'n':
            if (strncasecmp(line, "NLST", index) == 0) {
                return FTP_CMD_NLST;
            }
            else if (strncasecmp(line, "NOOP", index) == 0) {
                return FTP_CMD_NOOP;
            }
            break;

        case 'O':
        case 'o':
            if (strncasecmp(line, "OPTS", index) == 0) {
                return FTP_CMD_OPTS;
            }
            break;

        case 'P':
        case 'p':
            if (strncasecmp(line, "PASS", index) == 0) {
                return FTP_CMD_PASS;
            }
            else if (strncasecmp(line, "PORT", index) == 0) {
                return FTP_CMD_PORT;
            }
            else if (strncasecmp(line, "PASV", index) == 0) {
                return FTP_CMD_PASV;
            }
            else if (strncasecmp(line, "PBSZ", index) == 0) {
                return FTP_CMD_PBSZ;
            }
            else if (strncasecmp(line, "PROT", index) == 0) {
                return FTP_CMD_PROT;
            }
            break;

        case 'Q':
        case 'q':
            if (strncasecmp(line, "QUIT", index) == 0) {
                return FTP_CMD_QUIT;
            }
            break;

        case 'R':
        case 'r':
            if (strncasecmp(line, "REIN", index) == 0) {
                return FTP_CMD_REIN;
            }
            else if (strncasecmp(line, "RETR", index) == 0) {
                return FTP_CMD_RETR;
            }
            else if (strncasecmp(line, "REST", index) == 0) {
                return FTP_CMD_REST;
            }
            else if (strncasecmp(line, "RNFR", index) == 0) {
                return FTP_CMD_RNFR;
            }
            else if (strncasecmp(line, "RNTO", index) == 0) {
                return FTP_CMD_RNTO;
            }
            break;

        case 'S':
        case 's':
            if (strncasecmp(line, "SMNT", index) == 0) {
                return FTP_CMD_SMNT;
            }
            else if (strncasecmp(line, "STRU", index) == 0) {
                return FTP_CMD_STRU;
            }
            else if (strncasecmp(line, "STOR", index) == 0) {
                return FTP_CMD_STOR;
            }
            else if (strncasecmp(line, "STOU", index) == 0) {
                return FTP_CMD_STOU;
            }
            else if (strncasecmp(line, "SITE", index) == 0) {
                return FTP_CMD_SITE;
            }
            else if (strncasecmp(line, "SYST", index) == 0) {
                return FTP_CMD_SYST;
            }
            else if (strncasecmp(line, "STAT", index) == 0) {
                return FTP_CMD_STAT;
            }
            else if (strncasecmp(line, "SIZE", index) == 0) {
                return FTP_CMD_SIZE;
            }
            break;

        case 'T':
        case 't':
            if (strncasecmp(line, "TYPE", index) == 0) {
                return FTP_CMD_TYPE;
            }
            else if (strncasecmp(line, "TVFS", index) == 0) {
                return FTP_CMD_TVFS;
            }
            break;

        case 'U':
        case 'u':
            if (strncasecmp(line, "USER", index) == 0) {
                return FTP_CMD_USER;
            }
            break;

        default:
            break;
        }

    }

    return FTP_CMD_NONE;
}


static ftp_repl FtpReply(const char *line, int len)
{
    const char *ptr;
    int index, val;
    ftp_repl rep = FTP_REP_NONE;
    int i, dim = sizeof(rep_code);

    index = 0;
    val = 0;
    ptr = (const char *)line;
    /* Look for the space pr '-' following the code replay */
    while (index < len) {
        if (*ptr == ' ' || *ptr == '-')
            break;
        else {
            ptr++;
            index++;
        }
    }

    /* The first token is the code reply */
    if (*ptr == ' ') {
        if (sscanf(line, "%i", &val) == 0) {
            return rep;
        }
    }
    else if (*ptr == '-') {
        if (sscanf(line, "%i-", &val) == 0) {
            return rep;
        }
    }
    else {
        return rep;
    }

    /* search enum */
    for (i=0; i!=dim; i++) {
        if (rep_code[i].num == val) {
            rep = rep_code[i].rep;
            break;
        }
    }

    return rep;
}


static bool FtpParsePasv(const char *line, int linelen, ftp_con *ftp)
{
    char *args;
    char *p;
    unsigned char c;
    int i;
    int address[4], port[2];
    bool ret = FALSE;
    
    /*
     * Copy the rest of the line into a null-terminated buffer.
     */
    args = xmalloc(linelen + 1);
    memcpy(args, line, linelen);
    args[linelen] = '\0';
    p = args;

    ftp->ipv_id = ip_id;

    for (;;) {
        /*
         * Look for a digit.
         */
        while ((c = *p) != '\0' && !isdigit(c))
            p++;
        
        if (*p == '\0') {
            /*
             * We ran out of text without finding anything.
             */
            break;
        }
        
        /*
         * See if we have six numbers.
         */
        i = sscanf(p, "%d,%d,%d,%d,%d,%d",
                   &address[0], &address[1], &address[2], &address[3],
		    &port[0], &port[1]);
        if (i == 6) {
            /*
             * We have a winner!
             */
            ftp->port.uint16 = ((port[0] & 0xFF)<<8) | (port[1] & 0xFF);
            ftp->ip.uint32 = htonl((address[0] << 24) | (address[1] <<16) | (address[2] <<8) | address[3]);
            ret = TRUE;
            break;
        }
        
        /*
         * Well, that didn't work.  Skip the first number we found,
         * and keep trying.
         */
        while ((c = *p) != '\0' && isdigit(c))
            p++;
    }
    xfree(args);
    
    return ret;
}


static bool IsRTF2428Delimiter(const int c)
{
    /* RFC2428 sect. 2 states rules for a valid delimiter */
    static const char forbidden[] = {"0123456789abcdef.:"};
    if (c < 33 || c > 126)
        return FALSE;
    else if (strchr(forbidden, tolower(c)))
        return FALSE;
    else
        return TRUE;
}


static bool FtpParseLpasv(const char *line, int linelen, ftp_con *ftp)
{
    int args[40], i, j;
    char c, buff[linelen+1];
    char *n, *p = buff;
    
    strcpy(buff, line);
    buff[linelen] = '\0';
    
    do {
        while ((c = *p) != '\0' && !isdigit(c))
            p++;
        if (*p != '\0' && p[1] == ',')
            break;
        else
            p++;
    } while (*p != '\0');

    if (*p == '\0')
        return FALSE;
    
    i = 0;
    n = strchr(p, ',');
    while (n != NULL) {
        *n = '\0';
        args[i] = atoi(p);
        i++;
        p = n + 1;
        n = strchr(p, ',');
    }
    args[i] = atoi(p);
    i++;

    if (i != 21 && i != 9)
        return FALSE;

    if (args[0] == 6) {
        if (args[1] != 16)
            return FALSE;
        ftp->ipv_id = ipv6_id;
        for (j=0; j!=16; j++) {
            ftp->ip.ipv6[j] = args[2+j];
        }
        ftp->port.uint16 = ((args[19] & 0xFF)<<8) | (args[20] & 0xFF);
    }
    else if (args[0] == 4) {
        if (args[1] != 4)
            return FALSE;
        ftp->ipv_id = ip_id;
        ftp->port.uint16 = ((args[7] & 0xFF)<<8) | (args[8] & 0xFF);
        ftp->ip.uint32 = htonl((args[2] << 24) | (args[3] <<16) | (args[4] <<8) | args[5]);
    }
    else {
        LogPrintf(LV_WARNING, "LPASV and LPRT not supported (not IPv4 and not IPv6)!");
    }
    
    return TRUE;
}


static bool FtpParseEpasv(const char *line, int linelen, ftp_con *ftp, bool req)
{
    char *args, *p, *field;
    char delimiter;
    int n, delimiters_seen, fieldlen, lastn;
    bool ret = TRUE;
    char buff[linelen];
    
    if (line == NULL || linelen < 4)
        return FALSE;
    if (req) {
        args = strchr(line, ' ');
    }
    else {
        args = strchr(line, '(');
    }
    
    if (args == NULL)
        return FALSE;

    args++;
    p = args;
    linelen -= (p - line);
    
    /*
     * RFC2428 sect. 2 states ...
     *
     *     The EPRT command keyword MUST be followed by a single space (ASCII
     *     32). Following the space, a delimiter character (<d>) MUST be
     *     specified.
     *
     * ... the preceding <space> is already stripped so we know that the first
     * character must be the delimiter and has just to be checked to be valid.
     */
    if (!IsRTF2428Delimiter(*p))
        return FALSE;  /* EPRT command does not follow a vaild delimiter;
                        * malformed EPRT command - immediate escape */

    delimiter = *p;
    delimiters_seen = 0;
    /* Validate that the delimiter occurs 4 times in the string */
    for (n = 0; n < linelen; n++) {
        if (*(p+n) == delimiter)
            delimiters_seen++;
    }
    if (delimiters_seen != 4)
        return FALSE; /* delimiter doesn't occur 4 times
                       * probably no EPRT request - immediate escape */
    
    /* we know that the first character is a delimiter... */
    delimiters_seen = 1;
    lastn = 0;
    /* ... so we can start searching from the 2nd onwards */
    for (n=1; n < linelen; n++) {
        if (*(p+n) != delimiter)
            continue;

        /* we found a delimiter */
        delimiters_seen++;

        fieldlen = n - lastn - 1;
        if (fieldlen <= 0 && req)
            return FALSE; /* all fields must have data in them */
        
        field =  p + lastn + 1;

        if (delimiters_seen == 2) {     /* end of address family field */
            strncpy(buff, field, fieldlen);
            buff[fieldlen] = '\0';
            switch (atoi(buff)) {
            case 1:
                ftp->ipv_id = ip_id;
                break;
                
            case 2:
                ftp->ipv_id = ipv6_id;
                break;
            }
        }
        else if (delimiters_seen == 3 && req) {/* end of IP address field */
            strncpy(buff, field, fieldlen);
            buff[fieldlen] = '\0';

            if (ftp->ipv_id == ip_id) {
                if (inet_pton(AF_INET, buff, &ftp->ip.uint32) > 0)
                    ret = TRUE;
                else
                    ret = FALSE;
            }
            else if (ftp->ipv_id == ipv6_id) {
                if (inet_pton(AF_INET6, buff, ftp->ip.ipv6) > 0) {
                    ret = TRUE;
                }
                else
                    ret = FALSE;
            }
            else
                return FALSE; /* invalid/unknown address family */
        }
        else if (delimiters_seen == 4) {/* end of port field */
            strncpy(buff, field, fieldlen);
            buff[fieldlen] = '\0';

            ftp->port.uint16 = atoi(buff);
        }

        lastn = n;
    }

    return ret;
}


static bool FtpClientPkt(ftp_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port);
        if (port.uint16 == priv->port)
            ret = TRUE;
    }
    else {
        if (priv->ipv6 == TRUE) {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ipv6_src_id, &ip);
            type = FT_IPv6;
        }
        else {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ip_src_id, &ip);
            type = FT_IPv4;
        }
        if (FTCmp(&priv->ip, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }

    /* first time, the verify function verify that first pkt is a client pkt */
    if (priv->dir == FTP_CLT_DIR_NONE) {
        if (ret == TRUE)
            priv->dir = FTP_CLT_DIR_OK;
        else {
            priv->dir = FTP_CLT_DIR_REVERS;
            ret = TRUE;
            LogPrintf(LV_WARNING, "Acqusition file have an error!");
            if (pkt != NULL)
                ProtStackFrmDisp(pkt->stk, TRUE);
        }
    }
    else {
        if (priv->dir == FTP_CLT_DIR_REVERS)
            ret = !ret;
    }
    
    return ret;
}


static bool FtpCheckClientPkt(packet *pkt)
{
    bool ret;
    
    ret = FALSE;
    if (FtpReply(pkt->data, pkt->len) == FTP_REP_NONE) {
        if (FtpCommand(pkt->data, pkt->len) == FTP_CMD_NONE) {
            LogPrintf(LV_WARNING, "Unable to identify the client IP");
        }
        else
            ret = TRUE;
    }
    else
        ret = FALSE;

    return ret;
}


static int FtpDataRule(int flow_id, ftp_con *ftp)
{
    cmp_val rip, rport;
    int rid;

    /* delete last rule */
    if (ftp->rule != -1) {
        GrpRuleRm(ftp->rule);
        ftp->rule = -1;
    }
    if (ftp->data_setup == FALSE)
        return -1;

    rid = GrpRuleNew(flow_id);
    LogPrintf(LV_DEBUG, "Rule %i, port:%i", rid, ftp->port.uint16);
    rip.prot = ftp->ipv_id;
    if (rip.prot == ip_id) {
        rip.att = ip_dst_id;
        FTCopy(&(rip.val), &(ftp->ip), FT_IPv4);
    }
    else {
        rip.att = ipv6_dst_id;
        FTCopy(&(rip.val), &(ftp->ip), FT_IPv6);
    }
    rport.prot = tcp_id;
    rport.att = port_dst_id;
    rport.val.uint16 = ftp->port.uint16;
    GrpRule(rid, 2, &rip, &rport);
    if (rip.prot == ip_id) {
        rip.att = ip_src_id;
    }
    else {
        rip.att = ipv6_src_id;
    }
    rport.att = port_src_id;
    GrpRule(rid, 2, &rip, &rport);

    if (ftp->clnt) {
        if (rip.prot == ip_id) {
            rip.att = ip_dst_id;
            FTCopy(&(rip.val), &(ftp->ip_clnt), FT_IPv4);
        }
        else {
            rip.att = ipv6_dst_id;
            FTCopy(&(rip.val), &(ftp->ip_clnt), FT_IPv6);
        }
        rport.prot = tcp_id;
        rport.att = port_dst_id;
        rport.val.uint16 = ftp->port.uint16;
        GrpRule(rid, 2, &rip, &rport);
        if (rip.prot == ip_id) {
            rip.att = ip_src_id;
        }
        else {
            rip.att = ipv6_src_id;
        }
        rport.att = port_src_id;
        GrpRule(rid, 2, &rip, &rport);
    }
    GrpRuleCmplt(rid);

    ftp->rule = rid;
    ftp->data_setup = FALSE;
    ftp->cmd_rl = FTP_CMD_NONE;

    return 0;
}


static int FtpUser(ftp_con *ftp, const char *line, int len)
{
    int i;

    if (ftp->user == NULL)
        return -1;

    /* skeep cmd */
    i = 0;
    while (i != len && line[i] != ' ')
        i++;
    len -= i;
    if (len != 0) {
        i++;
        len -= 3;
    }

    /* user name */
    memcpy(ftp->user, line+i, len);
    ftp->user[len] = '\0';

    return 0;
}


static int FtpPasswd(ftp_con *ftp, const char *line, int len)
{
    int i;
    
    if (ftp->passwd == NULL)
        return -1;
    
    /* skeep cmd */
    i = 0;
    while (i != len && line[i] != ' ')
        i++;
    len -= i;
    if (len != 0) {
        i++;
        len -= 3;
    }

    /* password */
    memcpy(ftp->passwd, line+i, len);
    ftp->passwd[len] = '\0';

    return 0;
}


static int FtpFileName(char *name, const char *line, int len)
{
    int i, j, dim;

    /* skeep cmd */
    i = 0;
    while (i != len && line[i] != ' ')
        i++;
    dim = len - i;
    /* skeep directory */
    j = i+1;
    while (j != len && line[j] != ' ') {
        if (line[j] == '/' || line[j] == '\\') {
            dim -= (j-i);
            i = j;
        }
        j++;
    }
    
    if (dim != 0) {
        i++;
        dim -= 3;
    }
    
    /* filename */
    memcpy(name, line+i, dim);
    name[dim] = '\0';
    
    return 0;
}


static int FtpPeiNum(ftp_con *ftp, pei *ppei)
{
    pei_component *cmpn, *last;
    char *num;

    /* last component */
    last = ppei->components;
    while (last != NULL && last->next != NULL) {
        last = last->next;
    }
    
    /* upload */
    num = DMemMalloc(FTP_CMD_NAME);
    sprintf(num, "%i", ftp->up_n);
    PeiNewComponent(&cmpn, pei_up_n_id); 
    PeiCompCapTime(cmpn, ppei->time_cap);
    cmpn->strbuf = num;
    if (last == NULL)
        ppei->components = cmpn;
    else {
        last->next = cmpn;
        last = cmpn;
    }

    /* download */
    num = DMemMalloc(FTP_CMD_NAME);
    sprintf(num, "%i", ftp->down_n);
    cmpn = DMemMalloc(sizeof(pei_component));
    memset(cmpn, 0, sizeof(pei_component));
    cmpn->eid = pei_down_n_id;
    cmpn->time_cap = ppei->time_cap;
    cmpn->strbuf = num;
    if (last == NULL)
        ppei->components = cmpn;
    else {
        last->next = cmpn;
    }

    return 0;
}


static int FtpPeiCmd(ftp_con *ftp, pei *ppei)
{
    pei_component *cmpn, *last, *tmpn;
    int len;
    char *url;
    const pstack_f *ip;
    ftval val;

    /* last component */
    last = ppei->components;
    while (last != NULL && last->next != NULL) {
        last = last->next;
    }

    cmpn = tmpn = NULL;
    /* url */
    url = DMemMalloc(FTP_FILENAME_PATH_SIZE);
    len = 0;
    sprintf(url, "ftp://");
    len = 6;
    ip = ProtGetNxtFrame(ppei->stack);
    if (ProtFrameProtocol(ip) == ip_id) {
        ProtGetAttr(ip, ip_dst_id, &val);
        if (DnsDbSearch(&val, FT_IPv4, url+len, FTP_FILENAME_PATH_SIZE - len) != 0) {
            FTString(&val, FT_IPv4, url+len);
        }
    }
    else {
        ProtGetAttr(ip, ipv6_dst_id, &val);
        if (DnsDbSearch(&val, FT_IPv6, url+len, FTP_FILENAME_PATH_SIZE - len) != 0) {
            FTString(&val, FT_IPv6, url+len);
        }
    }
    len = strlen(url);
    url[len] = ':';
    len++;
    ProtGetAttr(ppei->stack, port_dst_id, &val);
    FTString(&val, FT_UINT16, url+len);
    PeiNewComponent(&cmpn, pei_url_id);
    PeiCompCapTime(cmpn, ppei->time_cap);
    cmpn->strbuf = url;
    url = NULL;

    /* user */
    if (ftp->user[0] != '\0') {
        PeiNewComponent(&tmpn, pei_user_id);
        PeiCompCapTime(tmpn, ppei->time_cap);
        PeiCompCapEndTime(tmpn, ppei->time_cap);
        tmpn->strbuf = ftp->user;
        ftp->user = NULL;
        if (cmpn != NULL)
            cmpn->next = tmpn;
        else
            cmpn = tmpn;
    }
    /* password */
    if (ftp->passwd[0] != '\0') {
        PeiNewComponent(&tmpn, pei_pswd_id);
        PeiCompCapTime(tmpn, ppei->time_cap);
        PeiCompCapEndTime(tmpn, ppei->time_cap);
        tmpn->strbuf = ftp->passwd;
        ftp->passwd = NULL;
        if (cmpn != NULL)
            if (cmpn->next == NULL)
                cmpn->next = tmpn;
            else
                cmpn->next->next = tmpn;
        else
            cmpn = tmpn;
    }
    /* cmd */
    if (tmpn != NULL) {
        PeiNewComponent(&tmpn->next, pei_cmd_id);
        tmpn = tmpn->next;
    }
    else {
        PeiNewComponent(&tmpn, pei_cmd_id);
        if (cmpn != NULL)
            cmpn->next = tmpn;
        else
            cmpn = tmpn;
    }
    tmpn->time_cap = ppei->time_cap;
    tmpn->name = DMemMalloc(FTP_CMD_NAME);
    strcpy(tmpn->name, "cmd.txt");
    tmpn->file_path = ftp->file_cmd;
    ftp->file_cmd = NULL;

    /* insert */
    if (last == NULL)
        ppei->components = cmpn;
    else
        last->next = cmpn;

    return 0;
}


static int FtpPeiData(ftp_data *ftpd, pei *ppei)
{
    pei_component *cmpn;
    char offset_str[100];

    cmpn = NULL;

    /* main info */
    PeiCapTime(ppei, ftpd->cap_start);
    PeiMarker(ppei, ftpd->serial);
    PeiStackFlow(ppei, ftpd->gstack);

    if (ftpd->offset != 0) {
        PeiNewComponent(&cmpn, pei_file_offset_id);
        PeiCompCapTime(cmpn, ftpd->cap_start);
        PeiCompCapEndTime(cmpn, ftpd->cap_end);
        sprintf(offset_str, "%lu", ftpd->offset);
        PeiCompAddStingBuff(cmpn, offset_str);
        PeiAddComponent(ppei, cmpn);
    }
    if (ftpd->file != NULL) {
        if (ftpd->cmd == FTP_CMD_RETR)
            PeiNewComponent(&cmpn, pei_file_in_id);
         else
            PeiNewComponent(&cmpn, pei_file_out_id);
        PeiCompCapTime(cmpn, ftpd->cap_start);
        PeiCompCapEndTime(cmpn, ftpd->cap_end);
        PeiCompAddFile(cmpn, ftpd->filename, ftpd->file, 0);
        if (ftpd->lost == TRUE)
            PeiCompError(cmpn, ELMT_ER_HOLE);
        PeiAddComponent(ppei, cmpn);
    }

    return 0;
}


static int FtpConnec(int flow_id, ftp_priv *priv)
{
    packet *pkt;
    ftval lost;
    pei *mpei, *dpei;
    int ret,len;
    FILE *fp_cmd;
    unsigned long serial, cap_end;
    ftp_con ftp;
    bool clnt, buff_clnt, first, data_first, real_clnt;
    char *buff, *empty, *filename, *aux;
    const char *eol, *lineend, *lend, *end;
    ftp_cmd cmd;
    ftp_repl repl;
    int gid, data_id;
    ftp_data *ftp_dt, *ftpd, *ftpd_to;
    bool toe, tod, ftpd_free;
    ftp_data *ftprm;

    /* init */
    ret = 0;
    mpei = dpei = NULL;
    gid = FlowGrpId(flow_id);
    data_id = -1;
    ftp_dt = NULL;
    first = TRUE;
    cmd = FTP_CMD_NONE;
    filename = NULL;

    /* first tcp packet */
    pkt = FlowGetPkt(flow_id);
    clnt = FtpClientPkt(priv, pkt);
    FtpConInit(&ftp, priv);

    /* check client and server IPs */
    ProtGetAttr(pkt->stk, lost_id, &lost);
    if (lost.uint8 == TRUE) {
        real_clnt = TRUE;
    }
    else {
        real_clnt = FALSE;
    }

    /* cmd file path and name */
    sprintf(ftp.file_cmd, "%s/%s/ftp_%lld_%p_%i.txt", ProtTmpDir(), FTP_TMP_DIR, (long long)time(NULL), &ftp, incr);
    incr++;
    /* open file */
    fp_cmd = fopen(ftp.file_cmd, "w");
    if (fp_cmd == NULL) {
        /* free */
        LogPrintf(LV_ERROR, "Unable to open file %s", ftp.file_cmd);
        FtpConFree(&ftp);
        PktFree(pkt);
        return -1;
    }

    /* create master pei */
    PeiNew(&mpei, ftp_id);
    PeiCapTime(mpei, pkt->cap_sec);
    PeiMarker(mpei, pkt->serial);
    PeiStackFlow(mpei, FlowStack(flow_id));
    PeiSetReturn(mpei, TRUE); /* neccesary */

    /* main loop */
    buff = xmalloc(FTP_DATA_BUFFER);
    buff[0] = '\0';
    len = 0;
    lineend = buff;
    buff_clnt = FALSE;
    do {
        serial = pkt->serial;
        cap_end = pkt->cap_sec;
        clnt = FtpClientPkt(priv, pkt);
        /* check if there are packet lost */
        ProtGetAttr(pkt->stk, lost_id, &lost);
        //ProtStackFrmDisp(pkt->stk, TRUE);
        if (lost.uint8 == TRUE) {
            /* packet lost */
            ftp.lost = TRUE;
            if (clnt == ftp.clnt)
                ftp.data_setup = FALSE; /* setup not safe */
            if (clnt)
                fwrite("------------Xplico: Client packet lost---------\n", 1, 47, fp_cmd);
            else
                fwrite("------------Xplico: Server packet lost---------\n", 1, 47, fp_cmd);
        }
        else if (pkt->len != 0) {
            if (real_clnt) {
                real_clnt = FtpCheckClientPkt(pkt);
                if (real_clnt != clnt) {
                    priv->dir = FTP_CLT_DIR_REVERS;
                    clnt = !clnt;
                }
                real_clnt = FALSE;
            }
            if (clnt) {
                /* client */
                ftp.clnt = TRUE;
                if (!buff_clnt) {
                    buff[0] = '\0';
                    len = 0;
                    lineend = buff;
                    buff_clnt = TRUE;
                }
                memcpy(buff+len, pkt->data, pkt->len);
                len += pkt->len;
                buff[len] = '\0';
                end = buff+len;
                do {
                    lend = find_line_end(lineend, end, &eol);
                    if (*eol == '\r' || *eol == '\n') {
                        cmd = FtpCommand(lineend, lend-lineend);
                        switch (cmd) {
                        case FTP_CMD_USER:
                            FtpUser(&ftp, lineend, lend-lineend);
                            break;

                        case FTP_CMD_PASS:
                            FtpPasswd(&ftp, lineend, lend-lineend);
                            break;
            
                        case FTP_CMD_TYPE:
                            break;

                        case FTP_CMD_REST:
                            break;

                        case FTP_CMD_RETR:
                        case FTP_CMD_STOR:
                            if (filename == NULL) {
                                filename = DMemMalloc(FTP_USER_PWD_DIM);
                                filename[0] = '\0';
                            }
                            FtpFileName(filename, lineend, lend-lineend);
                            LogPrintf(LV_DEBUG, "File name: %s", filename);
                            break;

                        case FTP_CMD_PORT:
                            ftp.data_setup = FtpParsePasv(lineend, lend-lineend, &ftp);
                            FtpDataRule(flow_id, &ftp); /* it guarantees  the connection of flow with TCP with ack verification */
                            break;
                            
                        case FTP_CMD_LPRT:
                            ftp.data_setup = FtpParseLpasv(lineend, lend-lineend, &ftp);
                            FtpDataRule(flow_id, &ftp); /* it guarantees  the connection of flow with TCP with ack verification */
                            break;

                        case FTP_CMD_EPRT:
                            ftp.data_setup = FtpParseEpasv(lineend, lend-lineend, &ftp, TRUE);
                            FtpDataRule(flow_id, &ftp); /* it guarantees  the connection of flow with TCP with ack verification */
                            break;

                        case FTP_CMD_NONE:
                            aux = xmalloc(lend-lineend + 1);
                            if (aux != NULL) {
                                memcpy(aux, lineend, lend-lineend);
                                aux[lend-lineend] = '\0';
                                LogPrintf(LV_WARNING, "Ftp command don't managed -->%s.", aux);
                                xfree(aux);
                            }
                            else {
                                LogPrintf(LV_WARNING, "Ftp command don't managed");
                            }
                            break;

                        default:
                            break;
                        }
                        
                        lineend = lend;
                    }
                } while (lend < end);
            }
            else {
                /* server */
                ftp.clnt = FALSE;
                if (buff_clnt) {
                    buff[0] = '\0';
                    len = 0;
                    lineend = buff;
                    buff_clnt = FALSE;
                }
                memcpy(buff+len, pkt->data, pkt->len);
                len += pkt->len;
                buff[len] = '\0';
                end = buff+len;
                do {
                    lend = find_line_end(lineend, end, &eol);
                    if (*eol == '\r' || *eol == '\n') {
                        repl = FtpReply(lineend, lend-lineend);
                        switch (repl) {
                        case FTP_REP_227:
                            ftp.data_setup = FtpParsePasv(lineend, lend-lineend, &ftp);
                            FtpDataRule(flow_id, &ftp); /* it guarantees  the connection of flow with TCP with ack verification */
                            break;

                        case FTP_REP_228:
                            ftp.data_setup = FtpParseLpasv(lineend, lend-lineend, &ftp);
                            FtpDataRule(flow_id, &ftp); /* it guarantees  the connection of flow with TCP with ack verification */
                            break;

                        case FTP_REP_229:
                            ftp.data_setup = FtpParseEpasv(lineend, lend-lineend, &ftp, FALSE);
                            if (priv->ipv6)
                                ftp.ipv_id = ipv6_id;
                            else
                                ftp.ipv_id = ip_id;
                            if (priv->dir == FTP_CLT_DIR_OK) {
                                if (priv->ipv6)
                                    FTCopy(&ftp.ip, &priv->ipd, FT_IPv6);
                                else
                                    FTCopy(&ftp.ip, &priv->ipd, FT_IPv4);
                            }
                            else {
                                if (priv->ipv6)
                                    FTCopy(&ftp.ip, &priv->ip, FT_IPv6);
                                else
                                    FTCopy(&ftp.ip, &priv->ip, FT_IPv4);
                            }
                            FtpDataRule(flow_id, &ftp); /* it guarantees  the connection of flow with TCP with ack verification */
                            break;

                        default:
                            break;
                        }
                        lineend = lend;
                    }
                } while (lend < end);
            }

            /* write cmd-response */
            fwrite(pkt->data, 1, pkt->len, fp_cmd);
        }
        /* free packet */
        PktFree(pkt);
        pkt = NULL;

        /* coupling ftp-data */
        data_id = GrpLink(gid);
        if (data_id != -1) {
            /* insert master pei */
            if (first) {
                FtpPeiCmd(&ftp, mpei);
                PeiIns(mpei);
                first = FALSE;
            }
            /* create ftp data */
            ftpd = DMemMalloc(sizeof(ftp_data));
            FtpDataInit(ftpd);
            ftpd->fid = data_id;
            ftpd->stack = ProtCopyFrame(FlowStack(data_id), TRUE);
            ftpd->gstack = ProtCopyFrame(FlowGrpStack(FlowGrpId(data_id)), TRUE);
            ftpd->nxt = ftp_dt;
            ftp_dt = ftpd;
            /* setup timeout */
            FlowSetTimeOut(data_id, 0);
            /* main flow without timeout */
            FlowSetTimeOut(flow_id, 0);

            if (ftp.cmd_rl != FTP_CMD_NONE) {
                cmd = ftp.cmd_rl;           /* old command */
                ftp.cmd_rl = FTP_CMD_NONE;
            }
        }

        /* command of ftp data (it can be a old command... see above)*/
        switch (cmd) {
        case FTP_CMD_LIST:
        case FTP_CMD_NLST:
        case FTP_CMD_MLST:
        case FTP_CMD_MLSD:
            if (ftp_dt != NULL) {
                if (ftp_dt->cmd == FTP_CMD_NONE) {
                    ftp_dt->cmd = FTP_CMD_LIST;
                    if (ftp_dt->dim != 0) {
                        /* write cmd-response */
                        fwrite(ftp_dt->buff, 1, ftp_dt->dim, fp_cmd);
                        ftp_dt->dim = 0;
                        /* check flow status */
                        if (ftp_dt->fid == -1) {
                            /* remove and free struct */
                            ftpd = ftp_dt;
                            ftp_dt = ftp_dt->nxt;
                            FtpDataFree(ftpd);
                        }
                    }
                }
            }
            else {
                if (ftp.lost == FALSE && ftp.rule == -1)
                    LogPrintf(LV_WARNING, "LIST/xLST cmd without ftp data stream");
                else if (ftp.rule != -1)
                    ftp.cmd_rl = cmd;
            }
            break;
            
        case FTP_CMD_RETR:
        case FTP_CMD_STOR:
            if (ftp_dt != NULL) {
                if (ftp_dt->cmd == FTP_CMD_NONE) {
                    ftp_dt->cmd = cmd;
                    /* filename */
                    ftp_dt->filename = filename;
                    filename = NULL;
                    if (ftp_dt->fp == NULL) {
                        /* create file */
                        ftp_dt->file = DMemMalloc(FTP_FILENAME_PATH_SIZE);
                        sprintf(ftp_dt->file, "%s/%s/ftp_%lld_%p_%i.bin", ProtTmpDir(), FTP_TMP_DIR, (long long)time(NULL), ftp_dt, incr);
                        incr++;
                        /* open file */
                        ftp_dt->fp = fopen(ftp_dt->file, "w");
                        if (ftp_dt->fp == NULL) {
                            LogPrintf(LV_ERROR, "Unable to open file %s", ftp_dt->file);
                        }

                        /* write data in the file */
                        fwrite(ftp_dt->buff, 1, ftp_dt->dim, ftp_dt->fp);
                        ftp_dt->dim = 0;
                    }
                    /* check flow status */
                    if (ftp_dt->fid == -1) {
                        if (ftp_dt->fp != NULL) {
                            fclose(ftp_dt->fp);
                            ftp_dt->fp = NULL;
                        }
                        PeiNew(&dpei, ftp_id);
                        FtpPeiData(ftp_dt, dpei);
                        PeiParent(dpei, mpei);
                        PeiIns(dpei);
                        dpei = NULL;
                        /* file conter */
                        if (ftp_dt->cmd == FTP_CMD_RETR)
                            ftp.down_n++;
                        else
                            ftp.up_n++;
                        /* remove and free struct */
                        ftpd = ftp_dt;
                        ftp_dt = ftp_dt->nxt;
                        FtpDataFree(ftpd);
                    }
                }
            }
            else {
                if (ftp.lost == FALSE && ftp.rule == -1)
                    LogPrintf(LV_WARNING, "RETR/STOR cmd without ftp data stream");
                else if (ftp.rule != -1)
                    ftp.cmd_rl = cmd;
            }
            break;

        default:
            break;
        }
        cmd = FTP_CMD_NONE;

        /* new packet from main flow */
        pkt = FlowGetPkt(flow_id);

        /* ftp-data stream */
        data_first = FALSE;
        ftpd_to = NULL;
        tod = TRUE; /* timeout data flow to enable */
        while (pkt == NULL && ftp_dt != NULL && data_first == FALSE) {
            ftpd = ftp_dt;
            ftprm = ftpd;
            toe = TRUE; /* timeout main flow to enable */
            data_first = TRUE;
            ftpd_free = FALSE;
            while (ftpd != NULL) {
                if (ftpd->fid != -1) {
                    pkt = FlowGetPkt(ftpd->fid);
                    FlowSetTimeOut(ftpd->fid, 0);
                    while (pkt != NULL) {
                        tod = FALSE;
                        /* info */
                        if (ftpd->serial == 0) {
                            ftpd->cap_start = pkt->cap_sec;
                            ftpd->serial = pkt->serial;
                        }
                        ftpd->cap_end = pkt->cap_sec;

                        /* check if there are packet lost */
                        ProtGetAttr(pkt->stk, lost_id, &lost);
                        if (lost.uint8 == TRUE) {
                            LogPrintf(LV_WARNING, "Packets lost");
                            /* data lost */
                            ftpd->lost = TRUE;
                            if (ftpd->cmd == FTP_CMD_NONE) {
                                if (ftpd->fp == NULL) {
                                    ftpd->buff = xrealloc(ftpd->buff, ftpd->dim+pkt->len+1);
                                    memset(ftpd->buff+ftpd->dim, '*', pkt->len);
                                    ftpd->dim += pkt->len;
                                    ftpd->buff[ftpd->dim] = '\0';
                                    /* check buffer size */
                                    if (ftpd->dim > FTP_DATA_BUFFER*100) {
                                        /* create file */
                                        ftpd->file = DMemMalloc(FTP_FILENAME_PATH_SIZE);
                                        sprintf(ftpd->file, "%s/%s/ftp_%lld_%p_%i.txt", ProtTmpDir(), FTP_TMP_DIR, (long long)time(NULL), ftpd, incr);
                                        incr++;
                                        /* open file */
                                        ftpd->fp = fopen(ftpd->file, "w");
                                        if (ftpd->fp == NULL) {
                                            LogPrintf(LV_ERROR, "Unable to open file %s", ftpd->file);
                                        }

                                        /* write data in the file */
                                        fwrite(ftpd->buff, 1, ftpd->dim, ftpd->fp);
                                        ftpd->dim = 0;
                                    }
                                }
                                else {
                                    /* write to data file */
                                    empty = xmalloc(pkt->len);
                                    memset(empty, '*', pkt->len);
                                    fwrite(empty, 1, pkt->len, ftpd->fp);
                                    xfree(empty);
                                }
                            }
                            else if (ftpd->cmd == FTP_CMD_LIST) {
                                empty = xmalloc(pkt->len);
                                memset(empty, '*', pkt->len);
                                /* write cmd-response */
                                fwrite(empty, 1, pkt->len, fp_cmd);
                                xfree(empty);
                            }
                            else {
                                empty = xmalloc(pkt->len);
                                memset(empty, '*', pkt->len);
                                /* write to data file */
                                fwrite(empty, 1, pkt->len, ftpd->fp);
                                xfree(empty);
                            }
                        }
                        else {
                            if (ftpd->cmd == FTP_CMD_NONE) {
                                if (ftpd->fp == NULL) {
                                    ftpd->buff = xrealloc(ftpd->buff, ftpd->dim+pkt->len+1);
                                    memcpy(ftpd->buff+ftpd->dim, pkt->data, pkt->len);
                                    ftpd->dim += pkt->len;
                                    ftpd->buff[ftpd->dim] = '\0';
                                    /* check buffer size */
                                    if (ftpd->dim > FTP_DATA_BUFFER*100) {
                                        /* create file */
                                        ftpd->file = DMemMalloc(FTP_FILENAME_PATH_SIZE);
                                        sprintf(ftpd->file, "%s/%s/ftp_%lld_%p_%i.txt", ProtTmpDir(), FTP_TMP_DIR, (long long)time(NULL), ftpd, incr);
                                        incr++;
                                        /* open file */
                                        ftpd->fp = fopen(ftpd->file, "w");
                                        if (ftpd->fp == NULL) {
                                            LogPrintf(LV_ERROR, "Unable to open file %s", ftpd->file);
                                        }

                                        /* write data in the file */
                                        fwrite(ftpd->buff, 1, ftpd->dim, ftpd->fp);
                                        ftpd->dim = 0;
                                    }
                                }
                                else {
                                    /* write to data file */
                                    fwrite(pkt->data, 1, pkt->len, ftpd->fp);
                                }
                            }
                            else if (ftpd->cmd == FTP_CMD_LIST) {
                                /* write cmd-response */
                                fwrite(pkt->data, 1, pkt->len, fp_cmd);
                            }
                            else {
                                /* write to data file */
                                fwrite(pkt->data, 1, pkt->len, ftpd->fp);
                            }
                        }
                        PktFree(pkt);
                        pkt = FlowGetPkt(ftpd->fid);
                    }
                    /* check flow status */
                    if (FlowIsEmpty(ftpd->fid)) {
                        if (ftpd->fp != NULL) {
                            fclose(ftpd->fp);
                            ftpd->fp = NULL;
                        }
                        FlowDelete(ftpd->fid);
                        ftpd->fid = -1;
                        
                        /* compose and insert pei */
                        if (ftpd->cmd != FTP_CMD_NONE) {
                            if (ftpd->cmd != FTP_CMD_LIST) {
                                PeiNew(&dpei, ftp_id);
                                FtpPeiData(ftpd, dpei);
                                PeiParent(dpei, mpei);
                                PeiIns(dpei);
                                dpei = NULL;
                                /* file counter */
                                if (ftpd->cmd == FTP_CMD_RETR)
                                    ftp.down_n++;
                                else
                                    ftp.up_n++;
                            }
                            /* remove data struct */
                            if (ftprm != ftpd) {
                                ftprm->nxt = ftpd->nxt;
                                ftprm = ftprm->nxt;
                            }
                            else {
                                ftp_dt = ftpd->nxt;
                                ftprm = ftp_dt;
                            }
                            ftpd_free = TRUE;
                        }

                        if (data_first == TRUE) {
                            /* suppose only master flow */
                            FlowSetTimeOut(flow_id, -1);
                            toe = FALSE;
                        }
                    }
                    else {
                        if (data_first == TRUE) {
                            ftpd_to = ftpd; /* first data flow */
                            if (toe == FALSE) {
                                /* master without timeout */
                                FlowSetTimeOut(flow_id, 0);
                            }
                        }
                        data_first = FALSE;
                    }
                }
                /* next ftp data */
                if (ftpd_free == TRUE) {
                    FtpDataFree(ftpd);
                    ftpd_free = FALSE;
                    if (ftprm == NULL) {
                        ftpd = NULL;
                    }
                    else {
                        ftpd = ftprm->nxt;
                    }
                }
                else {
                    ftprm = ftpd;
                    ftpd = ftprm->nxt;
                }
            }
            /* ftp cmd, main flow */
            pkt = FlowGetPkt(flow_id);   
            if (pkt == NULL) {
                if (tod == TRUE && ftpd_to != NULL) {
                    FlowSetTimeOut(ftpd_to->fid, FTP_PKT_TIMEOUT);
                }
            }
            else {
                /* suppose only master flow and the more, data flow without data */
                FlowSetTimeOut(flow_id, -1);
            }
        }
    } while (pkt != NULL);

    /* close file */
    fclose(fp_cmd);

    /* create pei info */
    if (first == TRUE) {
        FtpPeiCmd(&ftp, mpei);
        PeiIns(mpei);
        first = FALSE;
    }

    /* free */
    FtpConFree(&ftp);
    xfree(buff);

    /* insert all ftp data without command */
    if (ftp_dt != NULL && ftp_dt->cmd == FTP_CMD_NONE) {
        LogPrintf(LV_WARNING, "Data without command or command lost");
    }
    while (ftp_dt != NULL) {
        ftpd = ftp_dt->nxt;
#warning "to find if upload or dowload..."
        if (ftp_dt->dim != 0) {
            ftp_dt->filename = DMemMalloc(FTP_USER_PWD_DIM);
            sprintf(ftp_dt->filename, "FILENAME_LOST.bin");
            /* create file */
            ftp_dt->file = DMemMalloc(FTP_FILENAME_PATH_SIZE);
            sprintf(ftp_dt->file, "%s/%s/ftp_%lld_%p_%i.bin", ProtTmpDir(), FTP_TMP_DIR, (long long)time(NULL), ftp_dt, incr);
            incr++;
            /* open file */
            ftp_dt->fp = fopen(ftp_dt->file, "w");
            if (ftp_dt->fp == NULL) {
                LogPrintf(LV_ERROR, "Unable to open file %s", ftp_dt->file);
            }
            /* write data in the file */
            fwrite(ftp_dt->buff, 1, ftp_dt->dim, ftp_dt->fp);
            ftp_dt->dim = 0;
            fclose(ftp_dt->fp);
            ftp_dt->fp = NULL;
        }
        
        PeiNew(&dpei, ftp_id);
        FtpPeiData(ftp_dt, dpei);
        PeiParent(dpei, mpei);
        PeiIns(dpei);
        dpei = NULL;
        /* file conter */
        if (ftp_dt->cmd == FTP_CMD_RETR) {
#warning "to find if upload or dowload..."
            ftp.down_n++;
        }
        else if (ftp_dt->cmd == FTP_CMD_STOR) {
            ftp.up_n++;
        }
        /* remove and free struct */
        FtpDataFree(ftp_dt);
        
        /* next */
        ftp_dt = ftpd;
    }

    /* new insert of master PEI */
    FtpPeiNum(&ftp, mpei);
    PeiSetReturn(mpei, FALSE);
#warning "to complete: insert cap end time in cmd file"
    PeiIns(mpei);
    mpei = NULL;
    
    return ret;
}


static packet* FtpDissector(int flow_id)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, ip_dst;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    ftp_priv *priv;
    packet *pkt;

    LogPrintf(LV_DEBUG, "FTP id: %d", flow_id);
    priv = DMemMalloc(sizeof(ftp_priv));
    memset(priv, 0, sizeof(ftp_priv));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv->port = port_src.uint16;
    priv->dir = FTP_CLT_DIR_NONE;
    if (priv->port != port_dst.uint16)
        priv->port_diff = TRUE;
    priv->ipv6 = TRUE;
    if (ProtFrameProtocol(ip) == ip_id)
        priv->ipv6 = FALSE;
    
    if (priv->ipv6 == FALSE) {
        ProtGetAttr(ip, ip_src_id, &priv->ip);
        ProtGetAttr(ip, ip_dst_id, &priv->ipd);
        ProtGetAttr(ip, ip_dst_id, &ip_dst);
        ip_addr.s_addr = priv->ip.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = ip_dst.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv->ip);
        ProtGetAttr(ip, ipv6_dst_id, &priv->ipd);
        ProtGetAttr(ip, ipv6_dst_id, &ip_dst);
        memcpy(ipv6_addr.s6_addr, priv->ip.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, ip_dst.ipv6, sizeof(priv->ip.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: %s:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: %s:%d", ipd_str, port_dst.uint16);

    if (FtpConnec(flow_id, priv) != 0) {
        /* raw ftp file */
        pkt = FlowGetPkt(flow_id);
        while (pkt != NULL) {
#warning "to complete"
            PktFree(pkt);
            pkt = FlowGetPkt(flow_id);
        }
    }

    /* free memory */
    DMemFree(priv);

    LogPrintf(LV_DEBUG, "FTP... bye bye  fid:%d", flow_id);

    return NULL;
}


static bool FtpVerifyCheck(int flow_id, bool check)
{
    const pstack_f *ip;
    packet *pkt;
    bool ipv4, client, vers_unk;
    ftval lost, ips, ip_s;
    ftval port_a, port_b;
    bool ret, fr_data;
    char *data, *new;
    short verify_step; /* 0: none; 1: server presentation ok; 2: command client ok */
    int cmp;
    unsigned long len;
    const char *eol, *lineend;
    ftp_cmd cmd;

    ipv4 = FALSE;
    client = TRUE; /* first packet without lost packet is a client packet */
    ret = FALSE;
    fr_data = FALSE;
    verify_step = 0;
    vers_unk = FALSE;
    pkt = FlowGetPktCp(flow_id);

    if (pkt != NULL) {
        /* check ip */
        ip = ProtGetNxtFrame(pkt->stk);
        if (ProtFrameProtocol(ip) == ip_id)
            ipv4 = TRUE;
        if (ipv4 == TRUE)
            ProtGetAttr(ip, ip_src_id, &ips);
        else
            ProtGetAttr(ip, ipv6_src_id, &ips);

        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == TRUE)
            vers_unk = TRUE;
        while (lost.uint8 == FALSE && pkt->len == 0) {
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt == NULL)
                break;
            ProtGetAttr(pkt->stk, lost_id, &lost);
        }
    }

    while (pkt != NULL && (lost.uint8 == TRUE || pkt->len == 0)) {
        check = TRUE;
        PktFree(pkt);
        pkt = FlowGetPktCp(flow_id);
        if (pkt == NULL)
            break;
        ProtGetAttr(pkt->stk, lost_id, &lost);
    }
    
    if (pkt != NULL && vers_unk == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port_a);
        ProtGetAttr(pkt->stk, port_dst_id, &port_b);
        if (port_a.uint16 == TCP_PORT_FTP) {
            client = FALSE;
            ip = ProtGetNxtFrame(pkt->stk);
            if (ipv4 == TRUE)
                ProtGetAttr(ip, ip_dst_id, &ips);
            else
                ProtGetAttr(ip, ipv6_dst_id, &ips);
        }
        else if (port_b.uint16 == TCP_PORT_FTP) {
            client = TRUE;
        }
        else {
            PktFree(pkt);
            pkt = NULL;
        }
    }

    if (pkt != NULL  && lost.uint8 == FALSE) {
        if (vers_unk == FALSE) {
            ip = ProtGetNxtFrame(pkt->stk);
            if (ipv4 == TRUE) {
                ProtGetAttr(ip, ip_src_id, &ip_s);
                cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
            }
            else {
                ProtGetAttr(ip, ipv6_src_id, &ip_s);
                cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
            }
            if (cmp != 0) {
                /* first packet (with data) is server packet */
                client = FALSE;
            }
        }
        data = (char *)pkt->data;
        len = pkt->len;
        do {
            lineend = find_line_end(data, data+len, &eol);
            if (*eol == '\r' || *eol == '\n') {
                if (verify_step == 0 && client == FALSE) {
                    /* first step is verify server presentation */
                    if (FtpReply(data, lineend-data) != FTP_REP_NONE) {
                        if (check == FALSE) {
                            ret = TRUE;
                            break;
                        }
                        verify_step = 1;
                    }
                    else {
                        break;
                    }
                }
                else if (client == TRUE) {
                    if (verify_step == 1) {
                        /* second step is verify command from client */
                        cmd = FtpCommand(data, lineend-data);
                        if (cmd != FTP_CMD_NONE) {
                            if (cmd == FTP_CMD_USER || cmd == FTP_CMD_PASS || cmd == FTP_CMD_AUTH) {
                                ret = TRUE;
                                break;
                            }
                            else if (vers_unk == TRUE) {
                                ret = TRUE;
                                break;
                            }
                        }
                        else {
                            break;
                        }
                    }
                    else {
                        cmd = FtpCommand(data, lineend-data);
                        if (cmd == FTP_CMD_NONE) {
                            break;
                        }
                    }
                }
            }
            if (fr_data == FALSE) {
                data = xmalloc(len+1);
                if (data == NULL) {
                    LogPrintf(LV_WARNING, "Memmory unavailable");
                    break;
                }
                fr_data = TRUE;
                memcpy(data, pkt->data, len);
                data[len] = '\0';
            }
            PktFree(pkt);
            pkt = FlowGetPktCp(flow_id);
            if (pkt != NULL) {
                ip = ProtGetNxtFrame(pkt->stk);
                if (ipv4 == TRUE) {
                    ProtGetAttr(ip, ip_src_id, &ip_s);
                    cmp = FTCmp(&ips, &ip_s, FT_IPv4, FT_OP_EQ, NULL);
                }
                else {
                    ProtGetAttr(ip, ipv6_src_id, &ip_s);
                    cmp = FTCmp(&ips, &ip_s, FT_IPv6, FT_OP_EQ, NULL);
                }
                if (cmp == 0) {
                    /* client to server */
                    if (client == FALSE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                    if (lost.uint8 == FALSE) {
                        new = xrealloc(data, len+pkt->len+1);
                        if (new == NULL) {
                            LogPrintf(LV_WARNING, "Memmory unavailable");
                            break;
                        }
                        data = new;
                        memcpy(data+len, pkt->data, pkt->len);
                        len += pkt->len;
                        data[len] = '\0';
                    }
                    else {
                        if (vers_unk == TRUE) {
                            data = xrealloc(data, len+1);
                            data[len] = '\0';
                        }
                        else {
                            PktFree(pkt);
                            pkt = NULL;
                        }
                    }
                    client = TRUE;
                }
                else {
                    /* server to client */
                    if (client == TRUE) {
                        xfree(data);
                        data = NULL;
                        len = 0;
                    }
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                    if (lost.uint8 == FALSE) {
                        new = xrealloc(data, len+pkt->len+1);
                        if (new == NULL) {
                            LogPrintf(LV_WARNING, "Memmory unavailable");
                            break;
                        }
                        data = new;
                        memcpy(data+len, pkt->data, pkt->len);
                        len += pkt->len;
                        data[len] = '\0';
                    }
                    else {
                        if (vers_unk == TRUE) {
                            data = xrealloc(data, len+1);
                            data[len] = '\0';
                        }
                        else {
                            PktFree(pkt);
                            pkt = NULL;
                        }
                    }
                    client = FALSE;
                }
            }
        } while (pkt != NULL && len < 1024); /* 1k: max ftp server presentation/helo length */

        /* free memory */
        if (data != NULL && fr_data == TRUE) {
            xfree(data);
        }
    }
    
    if (pkt != NULL)
        PktFree(pkt);

    return ret;
}


static bool FtpVerify(int flow_id)
{
    return FtpVerifyCheck(flow_id, FALSE);
}


static bool FtpCheck(int flow_id)
{
    return FtpVerifyCheck(flow_id, TRUE);
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("File Transfer Protocol", "ftp");
    
    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.val.uint16 = TCP_PORT_FTP;
    dep.ProtCheck = FtpVerify;
    dep.pktlim = FTP_PKT_VER_LIMIT;
    ProtDep(&dep);

    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = FtpCheck;
    hdep.pktlim = FTP_PKT_VER_LIMIT;
    ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "user";
    peic.desc = "User name";
    ProtPeiComponent(&peic);

    peic.abbrev = "password";
    peic.desc = "Password";
    ProtPeiComponent(&peic);

    peic.abbrev = "cmd";
    peic.desc = "File with all user commands";
    ProtPeiComponent(&peic);

    peic.abbrev = "file_in";
    peic.desc = "Received file";
    ProtPeiComponent(&peic);

    peic.abbrev = "file_out";
    peic.desc = "Transmited file";
    ProtPeiComponent(&peic);

    peic.abbrev = "offset";
    peic.desc = "File offset";
    ProtPeiComponent(&peic);

    peic.abbrev = "down_n";
    peic.desc = "Number of file downloaded";
    ProtPeiComponent(&peic);

    peic.abbrev = "up_n";
    peic.desc = "Number of file uploaded";
    ProtPeiComponent(&peic);

    /* group protocol (master flow) */
    ProtGrpEnable();
    
    /* dissectors registration */
    ProtDissectors(NULL, FtpDissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char ftp_dir[256];

    /* part of file name */
    incr = 0;
    
    /* protocols and attributes */
    ip_id = ProtId("ip");
    ip_dst_id = ProtAttrId(ip_id, "ip.dst");
    ip_src_id = ProtAttrId(ip_id, "ip.src");
    ipv6_id = ProtId("ipv6");
    ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
    ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    tcp_id = ProtId("tcp");
    port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
    port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
    lost_id = ProtAttrId(tcp_id, "tcp.lost");
    clnt_id = ProtAttrId(tcp_id, "tcp.clnt");
    ftp_id = ProtId("ftp");

    /* pei id */
    pei_url_id = ProtPeiComptId(ftp_id, "url");
    pei_user_id = ProtPeiComptId(ftp_id, "user");
    pei_pswd_id = ProtPeiComptId(ftp_id, "password");
    pei_cmd_id = ProtPeiComptId(ftp_id, "cmd");
    pei_file_in_id = ProtPeiComptId(ftp_id, "file_in");
    pei_file_out_id = ProtPeiComptId(ftp_id, "file_out");
    pei_file_offset_id = ProtPeiComptId(ftp_id, "offset");
    pei_down_n_id = ProtPeiComptId(ftp_id, "down_n");
    pei_up_n_id = ProtPeiComptId(ftp_id, "up_n");

    /* ftp tmp directory */
    sprintf(ftp_dir, "%s/%s", ProtTmpDir(), FTP_TMP_DIR);
    mkdir(ftp_dir, 0x01FF);

    return 0;
}
