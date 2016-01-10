/* rltm_pol.c
 * main function for dissect a realtime acquisition in pol (XI)
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "log.h"
#include "packet.h"
#include "dmemory.h"
#include "proto.h"
#include "flow.h"
#include "rltm_pol.h"
#include "report.h"
#include "config_param.h"
#include "dispatch.h"
#include "pcap_gfile.h"

#define DISP_PEI_MAX_QUEUE    3000

/* external crash info */
extern unsigned long crash_pkt_cnt; 
extern char *crash_ref_name;

static int pol_prot_id;
static char savepcap;
static unsigned long pkt_serial = 0;
static char pcap_deb[RLTM_POL_PATH_DIM];
static FILE *fp_pcap;

static int RltmPolParam(int argc, char *argv[], char *intf, char *filter, char *dir)
{
    int c;
    short n;
    extern char *optarg;
    extern int optind, optopt;

    n = 0;
    while ((c = getopt(argc, argv, "i:f:d:r")) != -1) {
        switch(c) {
        case 'i':
            strcpy(intf, optarg);
            n++;
            break;

        case 'f':
            strcpy(filter, optarg);
            break;

        case 'd':
            strcpy(dir, optarg);
            n++;
            break;

        case 'r':
            savepcap = 1;
            break;

        case '?':
            printf("Error: unrecognized option: -%c\n", optopt);
            return -1;
        }
    }

    if (n != 2)
        return -1;

    return 0;
}


static void RltmPolDissector(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct pcap_ref *ref = (struct pcap_ref *)user;
    packet *pkt;
    static time_t tm = 0;
    int offset;
    struct timespec to;
    struct pcappkt_hdr pckt_header;
    size_t nwrt, wcnt;

    pkt = PktNew();

    ref->cnt++;
    pkt->raw = DMemMalloc(h->caplen+sizeof(unsigned long)*2+sizeof(char *)+sizeof(unsigned long)*2+sizeof(size_t));
    memcpy(pkt->raw, bytes, h->caplen);
    pkt->raw_len = h->caplen;
    offset = 0;
    *((unsigned long *)&(pkt->raw[pkt->raw_len])) = ref->dlt;
    offset += sizeof(unsigned long);
    *((unsigned long *)&(pkt->raw[pkt->raw_len+offset])) = ref->cnt;
    offset += sizeof(unsigned long);
    if (savepcap)
        *((char **)&(pkt->raw[pkt->raw_len+offset])) = pcap_deb;
    else
        *((char **)&(pkt->raw[pkt->raw_len+offset])) = "Real Time";
    offset += sizeof(char *);
    *((unsigned long *)&(pkt->raw[pkt->raw_len+offset])) = ref->ses_id;
    offset += sizeof(unsigned long);
    *((unsigned long *)&(pkt->raw[pkt->raw_len+offset])) = ref->pol_id;
    offset += sizeof(unsigned long);
    *((size_t *)&(pkt->raw[pkt->raw_len+offset])) = 0;
    pkt->cap_sec = h->ts.tv_sec;
    pkt->cap_usec = h->ts.tv_usec;
    pkt->serial = pkt_serial;

    /* crash info */
    crash_pkt_cnt = ref->cnt;
    
    /* decode */
    /* save packet */
    if (fp_pcap != NULL) {
        pckt_header.caplen = pkt->raw_len;
        pckt_header.len = pkt->raw_len;
        pckt_header.tv_sec = pkt->cap_sec;
        pckt_header.tv_usec = pkt->cap_usec;
        wcnt = 0;
        do {
            nwrt = fwrite(((char *)&pckt_header)+wcnt, 1, sizeof(struct pcappkt_hdr)-wcnt, fp_pcap);
            if (nwrt != -1)
                wcnt += nwrt;
            else
                break;
        } while (wcnt != sizeof(struct pcappkt_hdr));
        
        wcnt = 0;
        do {
            nwrt = fwrite(((char *)pkt->raw)+wcnt, 1, pkt->raw_len-wcnt, fp_pcap);
            if (nwrt != -1)
                wcnt += nwrt;
            else
                break;
        } while (wcnt != pkt->raw_len);
    }

    ProtDissec(pol_prot_id, pkt);

    FlowSetGblTime(h->ts.tv_sec);

    /* next serial number */
    pkt_serial++;

    if (time(NULL) > tm) {
        tm = time(NULL) + 5;
        ReportSplash();
        while (DispatchPeiPending() > DISP_PEI_MAX_QUEUE) {
            to.tv_sec = 2;
            to.tv_nsec = 1;
            /* wait some time */
            while (nanosleep(&to, &to) != 0)
                ;
            LogPrintf(LV_WARNING, "Possible data loss!");
            ReportSplash();
        }
    }
}



char* CaptDisOptions(void)
{
    return "-i <interface> [-f <filter>] [-r] -d <pol_dir_path>";
    
}


void CaptDisOptionsHelp(void)
{
    printf("\t-i interface: eth0, eth1, ...\n");
    printf("\t-f filter\n");
    printf("\t-r save raw data intput\n");
    printf("\t-d directory of the session\n");
    printf("\tNOTE: this capture module run ONLY with DEMA\n");
}


int CaptDisMain(int argc, char *argv[])
{
    char ifile[RLTM_POL_PATH_DIM];
    char dirpath[RLTM_POL_PATH_DIM];
    char tmp[RLTM_POL_PATH_DIM];
    char errbuf[PCAP_ERRBUF_SIZE];
    char intrf[RLTM_POL_PATH_DIM], filter_app[RLTM_POL_PATH_DIM];
    struct bpf_program filter;     /* The compiled filter */
    pcap_t *cap = NULL;
    char *param;
    int ret;
    struct pcap_ref ref;
    FILE *fp;
    bool end, ses_id, pol_id;
    struct pcappkt_hdr *pkt_header;
    const u_char *pkt_data;
    static time_t tm = 0;
    struct pcap_file_header fh;

    end = FALSE;
    ses_id = FALSE;
    pol_id = FALSE;
    savepcap = 0;

    /* pcapfile  protocol id */
    pol_prot_id = ProtId("pol");
    if (pol_prot_id == -1) {
        return -1;
    }

    /* serial number of packet */
    pkt_serial = 1;

    /* interace & filter % pol dir name*/
    intrf[0] = '\0';
    filter_app[0] = '\0';
    dirpath[0] = '\0';
    ret = RltmPolParam(argc, argv, intrf, filter_app, dirpath);
    if (ret != 0) {
        return -1;
    }
    
    /* check name dir */
    if (dirpath[0] == '\0') {
        return -1;
    }

    /* read pol info */
    sprintf(ifile, "%s/%s", dirpath, RLTM_POL_INIT_SESSION_FILE);
    fp = fopen(ifile, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Pol info file (%s) not present!", ifile);

        return -1;
    }
    while (fgets(tmp, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(tmp)) {
            param = strstr(tmp, RLTM_POL_SESSION_ID);
            if (param != NULL) {
                ret = sscanf(param, RLTM_POL_SESSION_ID"=%lu", &ref.ses_id);
                if (ret == 1) {
                    ses_id = TRUE;
                }
            }
            param = strstr(tmp, RLTM_POL_ID);
            if (param != NULL) {
                ret = sscanf(param, RLTM_POL_ID"=%lu", &ref.pol_id);
                if (ret == 1) {
                    pol_id = TRUE;
                }
            }
        }
    }
    fclose(fp);
    remove(ifile);

    if (ses_id == FALSE || pol_id == FALSE) {
        LogPrintf(LV_ERROR, "Pol info file (%s) incomplete!", tmp);

        return -1;
    }

    errbuf[sizeof(errbuf) - 1] = '\0';
    errbuf[0] = '\0';
    
    /* open device in promiscuous mode */
#ifdef HAVE_PCAP_CREATE
    cap = pcap_create(intrf, errbuf);
#else
    cap = pcap_open_live(intrf, 102400, 1, 0, errbuf);
#endif
    if (cap == NULL) {
        printf("Error: %s\n", errbuf);
        return -1;
    }
    else {
#ifdef HAVE_PCAP_CREATE
        ret = pcap_set_snaplen(cap, 102400);
        if (ret != 0) {
            printf("You have an old version of libpcap\n");
            return -1;
        }
        ret = pcap_set_promisc(cap, 1);
        if (ret != 0) {
            printf("You have an old version of libpcap\n");
            return -1;
        }
        ret = pcap_set_timeout(cap, 0);
        if (ret != 0) {
            printf("You have an old version of libpcap\n");
            return -1;
        }
        /* set capture buffer size to 16 MB */
        ret = pcap_set_buffer_size(cap, (1<<24));
        if (ret != 0) {
            printf("You have an old version of libpcap\n");
            return -1;
        }
        ret = pcap_activate(cap);
        if (ret != 0) {
            printf("pcap_activate failed '%s'\n", pcap_geterr(cap));
            return -1;
        }
#endif
        /* compile and apply the filter */
        if (pcap_compile(cap, &filter, filter_app, 1, 0) < 0) {
            printf("Bad filter %s\n", filter_app);
            pcap_perror(cap, "Filter");
            return -1;
        }
        
        pcap_setfilter(cap, &filter);
        pcap_freecode(&filter);

        /* interface */
        ref.dev = intrf;
        
        /* data link type */
        ref.dlt = pcap_datalink(cap);
        
        /* packet counter */
        ref.cnt = 0;

        /* end filename */
        sprintf(ifile, "%s/%s", dirpath, RLTM_POL_END_SESSION_FILE);

        if (savepcap) {
            /* pcap file for debug */
            sprintf(pcap_deb, "/opt/xplico/pol_%li/sol_%li/raw/interface_%s_%lu.pcap", ref.pol_id, ref.ses_id, intrf, time(NULL));
            fp_pcap = fopen(pcap_deb, "w");
            crash_ref_name = pcap_deb;
            memset(&fh, 0, sizeof(struct pcap_file_header));
            fh.magic = 0xA1B2C3D4;
            fh.version_major = PCAP_VERSION_MAJOR;
            fh.version_minor = PCAP_VERSION_MINOR;
            fh.snaplen = 65535;
            fh.linktype = ref.dlt;
            if (fp_pcap != NULL) {
                fwrite((char *)&fh, 1, sizeof(struct pcap_file_header), fp_pcap);
            }
            else {
                LogPrintf(LV_ERROR, "Debug raw file failed: %s", pcap_deb);
                sprintf(pcap_deb, "Real Time");
            }
        }
        else {
            fp_pcap = NULL;
        }

        do {
            /* read data */
            if (pcap_next_ex(cap, &pkt_header, &pkt_data) == -1) {
                /* exit */
                break;
            }
            else {
                /* decode data */
                RltmPolDissector((u_char *)&ref, pkt_header, pkt_data);
            }
            /* check the end */
            if (time(NULL) > tm) {
                tm = time(NULL) + 1;
                fp = fopen(ifile, "r");
                if (fp != NULL) {
                    end = TRUE;
                    fclose(fp);
                }
            }
        } while (end == FALSE);

        pcap_close(cap);

        /* remove file */
        remove(ifile);
    }

    if (fp_pcap != NULL)
        fclose(fp_pcap);

    return 0;
}


const char *CaptDisSource(void)
{
    return "Live Network Capture";
}
