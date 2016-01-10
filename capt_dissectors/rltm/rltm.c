/* rltm.c
 * main function for dissect a realtime acquisition
 *
 * $Id: $
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
#include "rltm.h"
#include "report.h"

/* external crash info */
extern unsigned long crash_pkt_cnt; 
extern char *crash_ref_name;

static int pcap_prot_id;
static unsigned long pkt_serial = 0;


static int RltmParam(int argc, char *argv[], char *intf, char *filter)
{
    int c;
    short n;
    extern char *optarg;
    extern int optind, optopt;

    n = 0;
    while ((c = getopt(argc, argv, "i:f:")) != -1) {
        switch(c) {
        case 'i':
            strcpy(intf, optarg);
            n++;
            break;

        case 'f':
            strcpy(filter, optarg);
            break;

        case '?':
            printf("Error: unrecognized option: -%c\n", optopt);
            return -1;
        }
    }

    if (n != 1)
        return -1;

    return 0;
}


static void RltmDissector(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct pcap_ref *ref = (struct pcap_ref *)user;
    packet *pkt;
    static time_t tm = 0;
    unsigned long len;

    pkt = PktNew();

    ref->cnt++;
    pkt->raw = DMemMalloc(h->caplen+sizeof(unsigned long)*2+sizeof(char *)+4);
    memcpy(pkt->raw, bytes, h->caplen);
    pkt->raw_len = h->caplen;
    /* align 4b */
    len = pkt->raw_len;
    len = len + 4 - (len%4);
    *((unsigned long *)&(pkt->raw[len])) = ref->dlt;
    *((unsigned long *)&(pkt->raw[len+sizeof(unsigned long)])) = ref->cnt;
    *((char **)(&(pkt->raw[len+sizeof(unsigned long)*2]))) = ref->dev;
    pkt->cap_sec = h->ts.tv_sec;
    pkt->cap_usec = h->ts.tv_usec;
    pkt->serial = pkt_serial;
    FlowSetGblTime(h->ts.tv_sec);
        
    /* crash info */
    crash_pkt_cnt = ref->cnt;
    
    /* decode */
    ProtDissec(pcap_prot_id, pkt);

    /* next serial number */
    pkt_serial++;

    if (time(NULL) > tm) {
        tm = time(NULL) + 30;
        ReportSplash();
    }
}

#ifdef XPL_CHECK_HW
#define BUFF_DIM   102400
#define BUFF2_DIM  1024
static int RltmCheckMac(void)
{
    struct ifreq ifr;
    unsigned char *pmac;
    int s, fd, ret, rd, i, j, offset, nxt, k;
    unsigned char buf[BUFF_DIM];
    char mac[BUFF2_DIM];
    unsigned char pattern[] = RLTM_CHECK_MAC_STR;
    int len;
    bool end;

    ret = -1;
    pmac = NULL;

    /* extract mac */
    s = socket(AF_INET,SOCK_DGRAM,0);
    if (s != -1) {
        strcpy(ifr.ifr_name, "eth0");
        /* get mac address of the interface */
        if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
            printf("ioctl SIOCGIFHWADDR non riuscita\n");
        }
        else {
            pmac = (unsigned char *)&ifr.ifr_ifru.ifru_hwaddr.sa_data[0];
            sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
                   *pmac, *(pmac + 1), *(pmac + 2), *(pmac + 3),
                   *(pmac + 4), *(pmac + 5) );
        }
        close(s);
        
        /* find pattern in HD */
        fd = open(RLTM_DEVICE, O_RDONLY);
        if (fd != -1) {
            len = sizeof(pattern) - 2;
            offset = 0;
            end = FALSE;
            while (end != TRUE) {
                rd = read(fd, buf+offset, BUFF_DIM/2);
                if (rd <= 0) {
                    end = TRUE;
                    break;
                }
                rd += offset;
                offset = 0;
                j = len;
                nxt = -1;
                for (i=0; i<rd; i++) {
                    if (buf[i] == pattern[j]) {
                        if (j == len) {
                            nxt = i;
                            if (i + 50 > rd) {
                                offset = rd-i;
                                memcpy(buf, buf+i, offset);
                                break;
                            }
                        }
                        j--;
                        if (j == -1) {
                            /* check MAC */
                            k = 0;
                            while (mac[k] != '\0') {
                                if (mac[k] != buf[i+k+1])
                                    break;
                                k++;
                            }
                            if (mac[k] == '\0') {
                                ret = 0;
                                end = TRUE;
                            }
                            else {
                                j = len;
                                i = nxt;
                            }
                        }
                    }
                    else {
                        j = len;
                        if (nxt != -1)
                            i = nxt;
                        nxt = -1;
                    }
                }
            }
        }
    }

    return ret;
}
#endif


char* CaptDisOptions(void)
{
    return "{-i <interface>  [-f <filter>]}";
}


void CaptDisOptionsHelp(void)
{
    printf("\t-i interface: eth0, eth1, ...\n");
    printf("\t-f filter\n");
}



int CaptDisMain(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char intrf[RLTM_PATH_DIM], filter_app[RLTM_PATH_DIM];
    struct bpf_program filter;     /* The compiled filter */
    pcap_t *cap = NULL;
    int ret;
    struct pcap_ref ref;
    FILE *run;

#ifdef XPL_CHECK_HW
    /* check eth0 MAC */
    if (RltmCheckMac() != 0) {
        printf("Fallito\n");
        return -1;
    }
#endif
    
    /* pcapfile  protocol id */
    pcap_prot_id = ProtId("pcapf");
    if (pcap_prot_id == -1) {
        return -1;
    }
    
    run = fopen(RLTM_PID_FILE, "w+");
    if (run != NULL) {
        fprintf(run, "%i\n", getpid());
        fclose(run);
    }

    /* serial number of packet */
    pkt_serial = 1;

    /* interace & filter */
    intrf[0] = '\0';
    filter_app[0] = '\0';
    ret = RltmParam(argc, argv, intrf, filter_app);
    if (ret != 0) {
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
        
        /* let pcap loop over the input, passing data to the decryptor */
        pcap_loop(cap, -1, (pcap_handler)&RltmDissector, (u_char*)&ref);
        
        pcap_close(cap);
    }

    return 0;
}

const char *CaptDisSource(void)
{
    return "Live Network Capture";
}
