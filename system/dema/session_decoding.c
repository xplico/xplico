/* session_decoding.c
 * Session decoding monitoring
 *
 * $Id: $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2014 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#define _GNU_SOURCE
#include <sys/types.h>
#include <dirent.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <netinet/in.h>
#include <semaphore.h>
#include <pthread.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "session_decoding.h"
#include "dbinterface.h"
#include "config_file.h"
#include "log.h"


#define DM_MNP_STR_DIM     32
#define DM_PCAP_BUFFER     (1024*1024)

typedef struct {
    char dsctr[DM_MNP_STR_DIM];
    char bin[DM_MNP_STR_DIM];
    char cfg[DM_MNP_STR_DIM];
    bool enabled;
    char port[DM_MNP_STR_DIM];
} manipula;


typedef struct {
    int pol;
    int sd4;
    int sd6;
    char main_dir[DM_MNP_STR_DIM];
    char cert[DM_MNP_STR_DIM];
} pcapip_thr;


static char *ssl_cert = NULL;
static char filename[DM_FILENAME_PATH];
static manipula manip[] = {
    {.dsctr = "fbwchat", .bin = "mfbc"},
    {.dsctr = "webmail", .bin = "mwmail"},
    {.dsctr = "httpfd", .bin = "mfile"},
    {.dsctr = "paltalk_exp", .bin = "mpaltalk"},
    {.dsctr = "webymsg", .bin = "mwebymsg"} /*,
    {.dsctr = "imap", .bin = "mimap"}
*/
};


static int ListSort(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}


static unsigned short SeDePort(unsigned short port)
{
    struct sockaddr_in servAddr;
    int yes, sd;
    
    /* create socket */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        LogPrintf(LV_WARNING, "Can't open socket (PCAPoverIP)\n");
        return 0;
    }
    yes = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
                   (char *) &yes, sizeof (yes)) < 0) {
        printf("setsockopt\n");
        close(sd);
        return 0;
    }
#ifdef SO_REUSEPORT
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT,
                   (char *) &yes, sizeof(yes)) < 0) {
        perror("SO_REUSEPORT");
        close(sd);
        return 0;
    }
#endif

    do {
        /* bind server port */
        memset (&servAddr, 0, sizeof (servAddr));
        servAddr.sin_family = AF_INET;
        servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servAddr.sin_port = htons(port);
        
        if (bind(sd, (struct sockaddr *) &servAddr, sizeof(servAddr)) == 0) {
            break;
        }
        port++;
    } while (port != 0);
    
    close(sd);
    
    return port;
}


static int *SeDePcapIP(const char *main_dir, int pol_id, int *sd)
{
    struct addrinfo hints, *servinfo, *add;
    char sport[25];
    int rv, yes, opts;
    int sd4, sd6;
    char pcapip_port[DM_FILENAME_PATH];
    unsigned short port;
    FILE *fp;

    port = DM_PCAP_IP_DEF_PROT + pol_id;
    port = SeDePort(port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;        /* use my IP */
    hints.ai_protocol = IPPROTO_TCP;
    sprintf(sport, "%i", port);

    rv = getaddrinfo(NULL, sport, &hints, &servinfo);
    if (rv != 0) {
        LogPrintf(LV_ERROR, "getaddrinfo() failed, %s\n", gai_strerror(rv));
        return NULL;
    }
    sd4 = sd6 = 0;
    for (add = servinfo; add != NULL; add = add->ai_next) {
        if (add->ai_family == AF_INET) {
            if (sd4 == 0) {
                sd4 = socket(add->ai_family, add->ai_socktype, add->ai_protocol); 
                if (sd4 == -1) {
                    sd4 = 0;
                    continue;
                }
                
                yes = 1;
                if (setsockopt(sd4, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof (yes)) < 0) {
                    printf("setsockopt\n");
                    close(sd4);
                    return NULL;
                }
#ifdef SO_REUSEPORT
                if (setsockopt(sd4, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, sizeof(yes)) < 0) {
                    perror("SO_REUSEPORT");
                    close(sd4);
                    return NULL;
                }
#endif
                opts = fcntl(sd4, F_GETFL);
                if (opts < 0) {
                    perror("fcntl(F_GETFL) failed");
                    close(sd4);
                    return NULL;
                }
                opts = opts | O_NONBLOCK;
                if (fcntl(sd4, F_SETFL, opts) < 0) {
                    perror("fcntl(F_SETFL) failed");
                    close(sd4);
                    return NULL;
                }
                rv = bind(sd4, add->ai_addr, add->ai_addrlen);
                if (rv == -1) {
                    printf("Cannot bind port\n");
                    close(sd4);
                    return NULL;
                }
            }
        }
        else if (add->ai_family == AF_INET6) {
            if (sd6 == 0) {
                sd6 = socket(add->ai_family, add->ai_socktype, add->ai_protocol); 
        		if (sd6 == -1) {
                    sd6 = 0;
                    continue;
                }
                
                yes = 1;
                if (setsockopt(sd6, SOL_SOCKET, SO_REUSEADDR, (char *) &yes, sizeof (yes)) < 0) {
                    printf("setsockopt\n");
                    close(sd6);
                    return NULL;
                }
#ifdef SO_REUSEPORT
                if (setsockopt(sd6, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, sizeof(yes)) < 0) {
                    perror("SO_REUSEPORT");
                    close(sd6);
                    return NULL;
                }
#endif
                if (setsockopt(sd6, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes)) < 0) {
                    perror("IPV6_V6ONLY");
                    close(sd6);
                    return NULL;
                }
                
                opts = fcntl(sd6, F_GETFL);
                if (opts < 0) {
                    perror("fcntl(F_GETFL) failed");
                    close(sd6);
                    return NULL;
                }
                opts = opts | O_NONBLOCK;
                if (fcntl(sd6, F_SETFL, opts) < 0) {
                    perror("fcntl(F_SETFL) failed");
                    close(sd6);
                    return NULL;
                }
                rv = bind(sd6, add->ai_addr, add->ai_addrlen);
                if (rv == -1) {
                    printf("Cannot bind port\n");
                    close(sd6);
                    return NULL;
                }
            }
        }
    }

    if (sd4 == 0 && sd6 == 0) {
        LogPrintf(LV_ERROR, "Unable to bind to either IPv4 or IPv6 address\n");
        return NULL;
    }

    if (sd4 != 0) {
        listen(sd4, 1);  /* only one connection */ 
    }
    if (sd6 != 0) {
        listen(sd6, 1);  /* only one connection */ 
    }

    sd[0] = sd4;
    sd[1] = sd6;

    /* info used by the XI */
    sprintf(pcapip_port, DM_TMP_DIR"/"DM_PCAPIP_FILE_PORT, main_dir, pol_id);
    fp = fopen(pcapip_port, "w+");
    if (fp != NULL) {
        fprintf(fp, "%i\n", port);
        fclose(fp);
    }

    return sd;
}


static void ShowCerts(SSL *ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* Get certificates (if available) */
    if (cert != NULL) {
        LogPrintf(LV_DEBUG, "Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        LogPrintf(LV_DEBUG, "Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        LogPrintf(LV_DEBUG, "Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        LogPrintf(LV_WARNING, "No certificates.\n");
}


static void *SeDePcapThread(void *data)
{
    int rv, pol_id, sol_id, opts, rd, wr, wr_tmp;
    int sd4, sd6, maxsd, cnt;
    fd_set sd_set, cp_set;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    int sd, sock;
    pcapip_thr *thr_info;
    char file_pcap[DM_FILENAME_PATH];
    char dec_pcap[DM_FILENAME_PATH];
    char main_dir[DM_FILENAME_PATH];
    char *datacap;
    bool compl;
    FILE *fp;
    time_t tpcap;
    SSL_CTX *ctx;
    const SSL_METHOD *method;
    SSL *ssl;
    
    thr_info = (pcapip_thr *)data;
    sd4 = thr_info->sd4;
    sd6 = thr_info->sd6;
    pol_id = thr_info->pol;
    strcpy(main_dir, thr_info->main_dir);
    thr_info = NULL;
    cnt = 0;
    free(data);
    
    /* setupt ssl */
    ctx = NULL;
    ssl = NULL;
    if (ssl_cert != NULL) {
        /* create new server-method instance */
        method = SSLv23_server_method();
        if (method == NULL) {
            ERR_print_errors_fp(stderr);
            abort();
        }
        /* create new context from method */
        ctx = SSL_CTX_new(method);
        if (ctx != NULL) {
            /* set the local certificate from CertFile */
            if (SSL_CTX_use_certificate_file(ctx, ssl_cert, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ctx);
                ctx = NULL;
            }
            /* set the private key from KeyFile (may be the same as CertFile) */
            if (ctx != NULL && SSL_CTX_use_PrivateKey_file(ctx, ssl_cert, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ctx);
                ctx = NULL;
            }
            /* verify private key */
            if (ctx != NULL && !SSL_CTX_check_private_key(ctx)) {
                ERR_print_errors_fp(stderr);
                SSL_CTX_free(ctx);
                ctx = NULL;
            }
        }
        else {
            ERR_print_errors_fp(stderr);
        }
    }
    
    /* wait first connection */
    FD_ZERO(&sd_set);
    if (sd4 != 0)
        FD_SET(sd4, &sd_set);
    if (sd6 != 0)
        FD_SET(sd6, &sd_set);
    maxsd = sd4;
    if (sd6 > maxsd)
        maxsd = sd6;
    while (1) {
        memcpy(&cp_set, &sd_set, sizeof(sd_set));
        rv = select(maxsd + 1, &cp_set, NULL, NULL, NULL);
        if (rv < 0) {
            if (errno == EINTR)
                continue;
            
            if (sd4 != 0)
                close(sd4);
            if (sd6 != 0)
                close(sd6);
            
            return NULL;
        }

        if (sd4 != 0 && FD_ISSET(sd4, &cp_set)) {
            sin_size = sizeof(their_addr);
            sock = accept(sd4, (struct sockaddr *)&their_addr, &sin_size);
            if (sock == -1)
                continue;
            opts = fcntl(sd4, F_GETFL);
            if (opts < 0) {
                perror("fcntl(F_GETFL) failed");
                continue;
            }
            opts = (opts & (~O_NONBLOCK));
            if (fcntl(sd4, F_SETFL, opts) < 0) {
                perror("fcntl(F_SETFL) failed");
                continue;
            }
            
            sd = sd4;
            close(sd6);
            break;
        }
        if (sd6 != 0 && FD_ISSET(sd6, &cp_set)) {
            sin_size = sizeof(their_addr);
            sock = accept(sd6, (struct sockaddr *)&their_addr, &sin_size);
            if (sock == -1)
                continue;
            opts = fcntl(sd6, F_GETFL);
            if (opts < 0) {
                perror("fcntl(F_GETFL) failed");
                continue;
            }
            opts = (opts & (~O_NONBLOCK));
            if (fcntl(sd6, F_SETFL, opts) < 0) {
                perror("fcntl(F_SETFL) failed");
                continue;
            }
            
            sd = sd6;
            close(sd4);
            break;
        }
    }

    while (1) {
        if (sock == -1) {
            sock = accept(sd, (struct sockaddr *)&their_addr, &sin_size);
            if (sock == -1)
                if (errno != EAGAIN)
                    return NULL;
                continue;
        }
        if (ctx != NULL) {
            /* get new SSL state with context */
            ssl = SSL_new(ctx);
            /* set connection socket to SSL state */
            SSL_set_fd(ssl, sock);
            /* SSL-protocol accept */
            if (SSL_accept(ssl) != 1) {
                ERR_print_errors_fp(stderr);
            }
            else {
                ShowCerts(ssl);
            }
        }

        /* write file */
        compl = TRUE;
        tpcap = time(NULL);
        sprintf(file_pcap, DM_TMP_DIR"/%lld_%i_%i.pcap", main_dir, pol_id, (long long)tpcap, pol_id, cnt);
        fp = fopen(file_pcap, "w");
        if (fp != NULL) {
            datacap = malloc(DM_PCAP_BUFFER);
            if (datacap != NULL) {
                do {
                    if (ctx != NULL) {
                        rd = SSL_read(ssl, datacap, DM_PCAP_BUFFER);
                    }
                    else {
                        rd = read(sock, datacap, DM_PCAP_BUFFER);
                    }
                    if (rd > 0) {
                        wr = 0;
                        do {
                            wr_tmp = fwrite(datacap+wr, 1, rd-wr, fp);
                            if (wr_tmp == -1) {
                                if (errno != EINTR) {
                                    compl = FALSE;
                                    break;
                                }
                            }
                            else {
                                wr += wr_tmp;
                            }
                        } while (wr != rd);
                    }
                    else if (rd == -1 && errno != EINTR) {
                        compl = FALSE;
                        break;
                    }
                } while (rd != 0);
                free(datacap);
            }
            else {
                compl = FALSE;
            }
            fclose(fp);
            if (ssl != NULL) {
                SSL_free(ssl);
                ssl = NULL;
            }
            close(sock);
            sock = -1;
        }
        else {
            if (ssl != NULL) {
                SSL_free(ssl);
                ssl = NULL;
            }
            compl = FALSE;
            close(sock);
            sock = -1;
        }

        /* decode pcap */
        if (compl == TRUE) {
            sol_id = DemaSol(pol_id);
            sprintf(dec_pcap, DM_NEW_DIR"/%lld_%i_%i.pcap", main_dir, pol_id, sol_id, (long long)tpcap, pol_id, cnt++);
            rename(file_pcap, dec_pcap);
        }
    }
    
    close(sd);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    return NULL;
}


int SeDeInit(char *cert, char *root_dir)
{
    struct stat info;
    
    if (cert[0] == '\0') {
        /* default file path */
        sprintf(cert, DM_DEFAULT_XPLICO_CERT, root_dir);
    }
    if (stat(cert, &info) != 0) {
        ssl_cert = NULL;
        return 0;
    }
    
    ssl_cert = malloc(strlen(cert)+1);
    strcpy(ssl_cert, cert);

    /* load & register all cryptos, etc. */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    /* load all error messages */
    SSL_load_error_strings();

    return 0;
}


int SeDeFind(char *main_dir, podec *tbl, int dim)
{
    DIR *dir, *dir1;
    struct dirent *entry, *entry1;
    int i, tmp, pol_id, sol_id;
    int new, next, pre;
    int len_pol, len_ses, ret;
    char dir_path[DM_FILENAME_PATH];
    char pcapip_port[DM_FILENAME_PATH];
    pthread_t pid;
    pcapip_thr *thr_info;
    
    dir = opendir(main_dir);
    if (dir == NULL) {
        perror("");
        exit(-1);
        return -1;
    }

    /* first empty position in tbl */
    next = 0;
    while (tbl[next].pol_id != -1)
        next++;

    /* pol directory */
    new = 0;
    len_pol = strlen(DM_POL_NAME);
    len_ses = strlen(DM_SESSION_NAME);
    while((entry = readdir(dir)) != NULL && new < DM_TBL_ADD) {
        if (entry->d_name[0] == '.')
            continue;
        /* check if this directory is a pol directory and if already exist in tbl */
        if (strncmp(entry->d_name, DM_POL_NAME, len_pol) == 0) {
            if (sscanf(entry->d_name, DM_POL_NAME"%i", &pol_id) == 1) {
                for (i=0; i<dim; i++) {
                    if (tbl[i].pol_id == pol_id) {
                        break;
                    }
                }
                /* next free position */
                while (tbl[next].pol_id != -1)
                    next++;
                if (i == dim) {
                    /* session directory */
                    sprintf(dir_path, DM_POL_DIR, main_dir, pol_id);
                    dir1 = opendir(dir_path);
                    if (dir1 != NULL) {
                        sol_id = INT_MAX;
                        while((entry1 = readdir(dir1)) != NULL) {
                            if (entry->d_name[0] == '.')
                                continue;
                            /* check if this directory is a pol directory and if alrady exist in tbl */
                            if (strncmp(entry1->d_name, DM_SESSION_NAME, len_ses) == 0) {
                                if (sscanf(entry1->d_name, DM_SESSION_NAME"%i", &tmp) == 1) {
                                    if (tmp < sol_id)
                                        sol_id = tmp;
                                }
                            }
                        }
                        closedir(dir1);
                        if (sol_id != INT_MAX) {
                            /* new pol */
                            LogPrintf(LV_TRACE, "New Case dir: %s\n", dir_path);
                            tbl[next].pol_id = pol_id;
                            tbl[next].sol_id = sol_id;
                            tbl[next].run = FALSE;
                            memset(&tbl[next].pid, 0, sizeof(task));
                            tbl[next].end = FALSE;
                            tbl[next].name[0] = '\0';
                            tbl[next].size = 0;
                            tbl[next].filenum = 0;
                            new++;
                        }
                    }
                }
            }
        }
    }
    closedir(dir);

    pre = 0;
    if (next > DM_PCAP_MAX) {
        /* close old connection */
        pre = next - DM_PCAP_MAX;
        for (i=0; i!=pre; i++) {
            if (tbl[i].sd[0] != -1) {
                if (tbl[i].sd[0] != 0)
                    close(tbl[i].sd[0]);
                tbl[i].sd[0] = -1;
            }
            if (tbl[i].sd[1] != -1) {
                if (tbl[i].sd[1] != 0)
                    close(tbl[i].sd[1]);
                tbl[i].sd[1] = -1;
            }
            sprintf(pcapip_port, DM_TMP_DIR"/"DM_PCAPIP_FILE_PORT, main_dir, tbl[i].pol_id);
            remove(pcapip_port);
        }
    }
    for (i=pre; i!=next; i++) {
        if (tbl[i].sd[0] == -1 && tbl[i].sd[1] == -1) {
            /* start thread */
            if (SeDePcapIP(main_dir, tbl[i].pol_id, tbl[i].sd) != NULL) {
                thr_info = malloc(sizeof(pcapip_thr));
                thr_info->sd4 = tbl[i].sd[0];
                thr_info->sd6 = tbl[i].sd[1];
                thr_info->pol = tbl[i].pol_id;
                strcpy(thr_info->main_dir, main_dir);
                ret = pthread_create(&pid, NULL, SeDePcapThread, (void *)thr_info);
                if (ret == 0) {
                    pthread_detach(pid);
                }
                else {
                    free(thr_info);
                    if (tbl[i].sd[0] != 0 && tbl[i].sd[0] != -1)
                        close(tbl[i].sd[0]);
                    if (tbl[i].sd[1] != 0 && tbl[i].sd[1] != -1)
                        close(tbl[i].sd[1]);
                    tbl[i].sd[0] = -1;
                    tbl[i].sd[1] = -1;
                }
            }
        }
    }

    return new;
}


int SeDeStart(dbconf *db_c, char *main_dir, int pol, int session, task *pid, bool rt, char *interf, char *filter)
{
    int ptsk, i, n;
    char app_path[DM_FILENAME_PATH];
    char config_file[DM_FILENAME_PATH];
    char work_dir[DM_FILENAME_PATH];
    char end_file[DM_FILENAME_PATH];
    char cmd[2*DM_FILENAME_PATH];
    char *xpl_cfg;
    unsigned short port;
    struct stat app_info;
    struct stat sbuf;
    char bpf_file[DM_FILENAME_PATH];
    FILE *fxcfg;
    struct stat cfg_stat;

    /* remove any other command file */
    sprintf(end_file, DM_DECOD_DIR"/%s", main_dir, pol, session, POL_END_SESSION_FILE);
    remove(end_file);
    n = sizeof(manip)/sizeof(manipula);
    if (DM_MANIP_MAX < n) {
        LogPrintf(LV_WARNING, "To many manipulators\n");
    }
    for (i=0; i!=n; i++) {
        manip[i].enabled = FALSE;
    }
    memset(pid, 0, sizeof(task));
    pid->tot = 0;

    /* remove the semaphore */
    sprintf(cmd, XS_GEA_SEM, pol);
    sem_unlink(cmd);

    /* cfg master files */
    switch (db_c->type) {
    case DB_SQLITE:
        xpl_cfg = DM_XPLICO_LITE_CFG;
        for (i=0; i!=n; i++) {
            sprintf(manip[i].cfg, "%s_install_lite.cfg", manip[i].bin);
        }
        break;

    case DB_MYSQL:
        xpl_cfg = DM_XPLICO_MYSQL_CFG;
        for (i=0; i!=n; i++) {
            sprintf(manip[i].cfg, "%s_install_mysql.cfg", manip[i].bin);
        }
        break;

    case DB_POSTGRESQL:
        xpl_cfg = DM_XPLICO_POSTGRES_CFG;
        for (i=0; i!=n; i++) {
            sprintf(manip[i].cfg, "%s_install_postgres.cfg", manip[i].bin);
        }
        break;

    default:
        return -1;
    }

    /* start manipulators */
    port = DM_MANIP_DEF_PROT; /* basic port */
    for (i=0; i!=n; i++) {
        sprintf(app_path, "%s/bin/%s", main_dir, manip[i].bin);
        sprintf(config_file, "%s/cfg/%s", main_dir, manip[i].cfg);
        if (stat(app_path, &app_info) == 0 && (stat(config_file, &app_info) == 0)) {
            manip[i].enabled = TRUE;
            /*  port to use */
            port = SeDePort(port);
            sprintf(manip[i].port, "%i", port);
            port++;
            ptsk = fork();
            if (ptsk == 0) {
                /* create config file */
                sprintf(config_file, DM_CFG_DIR"/%s", main_dir, pol, manip[i].cfg);
                if (stat(config_file, &cfg_stat) != 0) {
                    sprintf(config_file, "%s/cfg/%s", main_dir, manip[i].cfg);
                }
                sprintf(work_dir, DM_TMP_DIR, main_dir, pol);
                sprintf(cmd, "cp -a %s %s", config_file, work_dir);
                system(cmd);
                sprintf(config_file, DM_TMP_DIR"/%s", main_dir, pol, manip[i].cfg);
                fxcfg = fopen(config_file, "a");
                fprintf(fxcfg, "LOG_DIR_PATH="DM_LOG_DIR"\n", main_dir, pol);
                fprintf(fxcfg, "TMP_DIR_PATH="DM_TMP_DIR"/%s\n", main_dir, pol, manip[i].bin);
                /* DB connection params */
                if (db_c->type != DB_SQLITE) {
                    fprintf(fxcfg, CFG_PAR_DB_HOST"=%s\n", db_c->host);
                    fprintf(fxcfg, CFG_PAR_DB_NAME"=%s\n", db_c->name);
                    fprintf(fxcfg, CFG_PAR_DB_USER"=%s\n", db_c->user);
                    fprintf(fxcfg, CFG_PAR_DB_PASSWORD"=%s\n", db_c->password);
                }
                fclose(fxcfg);

                /* manipulator process */
                sprintf(work_dir, DM_DECOD_DIR, main_dir, pol, session);
                execlp(app_path, manip[i].bin, "-c", config_file, "-s", "-p", manip[i].port, NULL);
                
                exit(-1);
            }
            else if (ptsk == -1) {
                return -1;
            }
            pid->manip[i] = ptsk;
            pid->tot++;
        }
    }
    
    /* start xplico */
    ptsk = fork();
    if (ptsk == 0) {
        sleep(3); /* wait manipulators... to improve */
        /* BPF Filter path */
        sprintf(bpf_file, DM_BPF_FILE_FILTER, main_dir, pol);

        /* create config file */
        sprintf(config_file, DM_CFG_DIR"/%s", main_dir, pol, xpl_cfg);
        if (stat(config_file, &cfg_stat) != 0) {
            sprintf(config_file, "%s/cfg/%s", main_dir, xpl_cfg);
        }
        sprintf(work_dir, DM_TMP_DIR, main_dir, pol);
        sprintf(cmd, "cp -a %s %s", config_file, work_dir);
        system(cmd);
        sprintf(config_file, DM_TMP_DIR"/%s", main_dir, pol, xpl_cfg);
        /* manipulators */
        for (i=0; i!=n; i++) {
            if (manip[i].enabled == TRUE) {
                sprintf(cmd, "echo "DM_XPLICO_MANIP" >> %s", manip[i].dsctr, manip[i].port, config_file);
                system(cmd);
            }
        }
        
        /* log, pol, sol */
        sprintf(cmd, "echo LOG_DIR_PATH="DM_LOG_DIR" >> %s", main_dir, pol, config_file);
        system(cmd);
        sprintf(cmd, "echo TMP_DIR_PATH="DM_TMP_DIR"/xplico >> %s", main_dir, pol, config_file);
        system(cmd);
        sprintf(cmd, "echo POL_ID=%i > "DM_DECOD_DIR"/%s", pol,
                main_dir, pol, session, POL_INIT_SESSION_FILE);
        system(cmd);
        sprintf(cmd, "echo SESSION_ID=%i >> "DM_DECOD_DIR"/%s", session,
                main_dir, pol, session, POL_INIT_SESSION_FILE);
        system(cmd);
        /* DB connection params */
        if (db_c->type != DB_SQLITE) {
            sprintf(cmd, "echo "CFG_PAR_DB_HOST"=%s >> %s", db_c->host, config_file);
            system(cmd);
            sprintf(cmd, "echo "CFG_PAR_DB_NAME"=%s >> %s", db_c->name, config_file);
            system(cmd);
            sprintf(cmd, "echo "CFG_PAR_DB_USER"=%s >> %s", db_c->user, config_file);
            system(cmd);
            sprintf(cmd, "echo "CFG_PAR_DB_PASSWORD"=%s >> %s", db_c->password, config_file);
            system(cmd);
        }

        /* xplico process */
        sprintf(app_path, "%s/bin/xplico", main_dir);
        sprintf(work_dir, DM_DECOD_DIR, main_dir, pol, session);
        if (rt == FALSE) {
            if (stat(bpf_file, &sbuf) == 0) {
                execlp(app_path, "xplico", "-c", config_file, "-m", "pol", "-d", work_dir,
                       "-F", bpf_file, NULL);
            }
            else {
                execlp(app_path, "xplico", "-c", config_file, "-m", "pol", "-d", work_dir, NULL);
            }
        }
        else {
            if (filter != NULL && filter[0] != '\0') {
                execlp(app_path, "xplico", "-c", config_file, "-m", "rltm_pol", "-r", "-i", interf, "-f", filter, "-d", work_dir, NULL);
            }
            else {
                execlp(app_path, "xplico", "-c", config_file, "-m", "rltm_pol", "-r", "-i", interf, "-d", work_dir, NULL);
            }
        }
        exit(-1);
    }
    else if (ptsk == -1) {
        return -1;
    }
    pid->xplico = ptsk;
    pid->tot++;

    return 0;
}


int SeDeEnd(char *main_dir, int pol, int session, task *pid)
{
    char end_file[DM_FILENAME_PATH];
    int fd;

    /* end xplico */
    sprintf(end_file, DM_DECOD_DIR"/%s", main_dir, pol, session, POL_END_SESSION_FILE);
    fd = open(end_file, O_CREAT|O_RDWR, 0x01B6); /* only create file */
    if (fd != -1)
        close(fd);

    return 0;
}


static char *SeDeFileSrc(char *main_dir, int pol, int session, short type, bool *one)
{
    char newdir[DM_FILENAME_PATH];
    DIR *dir;
    struct dirent *entry;
    int i, num;
    char **list;
    
    switch (type) {
    case 0:
        sprintf(newdir, DM_NEW_DIR, main_dir, pol, session);
        break;

    case 1:
        sprintf(newdir, DM_DECOD_DIR, main_dir, pol, session);
        break;
    }
    
    dir = opendir(newdir);
    if (dir == NULL) {
        return NULL;
    }

    /* file list */
    num = 0;
    list = NULL;
    while((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;
        list = realloc(list, sizeof(char *)*(num+1));
        list[num] = malloc(strlen(entry->d_name)+5);
        strcpy(list[num], entry->d_name);
        num++;
    }
    closedir(dir);
    if (one != NULL) {
        if (num > 1)
            *one = FALSE;
        else
            *one = TRUE;
    }
    
    /* sort */
    qsort(list, num, sizeof(char *), ListSort);
    if (num == 0) {
        return NULL;
    }
    if (list != NULL) {
        strcpy(filename, list[0]);
        for (i=0; i<num; i++) {
            free(list[i]);
        }
        free(list);
    }

    return filename;
}


char *SeDeFileNew(char *main_dir, int pol, int session, bool *one)
{
    return SeDeFileSrc(main_dir, pol, session, 0, one);
}


char *SeDeFileDecode(char *main_dir, int pol, int session)
{
    return SeDeFileSrc(main_dir, pol, session, 1, NULL);
}


bool SeDeFileActive(char *filepath)
{
    int fd;
    bool ret;

    ret = FALSE;
    fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return FALSE;
    }

    if (fcntl(fd, F_SETLEASE, F_WRLCK) && EAGAIN == errno) {
        ret = TRUE;
    }
    else {
        fcntl(fd, F_SETLEASE, F_UNLCK);
    }
    close(fd);
    
    return ret;

}


int SeDeNextSession(char *main_dir, int pol, int session)
{
    DIR *dir;
    struct dirent *entry;
    char dir_path[DM_FILENAME_PATH];
    int len_ses;
    int tmp;
    int sol_id;

    sol_id = -1;

    /* session directory */
    len_ses = strlen(DM_SESSION_NAME);
    sprintf(dir_path, DM_POL_DIR, main_dir, pol);
    dir = opendir(dir_path);
    if (dir != NULL) {
        sol_id = INT_MAX;
        while((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;
            /* check if this directory is a pol directory and if alrady exist in tbl */
            if (strncmp(entry->d_name, DM_SESSION_NAME, len_ses) == 0) {
                if (sscanf(entry->d_name, DM_SESSION_NAME"%i", &tmp) == 1) {
                    if (tmp < sol_id && tmp > session)
                        sol_id = tmp;
                }
            }
        }
        closedir(dir);
        
        /* check value */
        if (sol_id == INT_MAX) {
            sol_id = -1;
        }
    }
    
    return sol_id;
}


int SeDeRun(task *pid, pid_t chld, bool tclear)
{
    int ret, i, n;
    
    ret = -1;
    n = sizeof(manip)/sizeof(manipula);

    /* check all application */
    if (pid->xplico == chld) {
        if (tclear)
            pid->xplico = 0;
        ret = 0;
    }
    else {
        for (i=0; i!=n; i++) {
            if (pid->manip[i] == chld) {
                LogPrintf(LV_DEBUG, "The end of %s\n", manip[i].bin);
                if (tclear)
                    pid->manip[i] = 0;
                ret = 0;
                break;
            }
        }
    }

    return ret;
}


int SeDeKill(podec *tbl, int id)
{
    int i, n;

    if (tbl[id].run == TRUE) {
        n = sizeof(manip)/sizeof(manipula);
        /* decoder */
        if (tbl[id].pid.xplico != 0)
            kill(tbl[id].pid.xplico, SIGKILL);
        /* manipulators */
        for (i=0; i!=n; i++) {
            if (tbl[id].pid.manip[i] != 0) {
                kill(tbl[id].pid.manip[i], SIGKILL);
            }
        }
    }
    
    return 0;
}

