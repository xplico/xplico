/* fileformat.c
 * File format funtions: uncompres, decode, ...
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <zlib.h>

#include "fileformat.h"
#include "strutil.h"
#include "istypes.h"
#include "dmemory.h"
#include "log.h"

/* max malloc limit */
#define  FF_MALLOC_LIMIT (10*1024*1024)
#define  FF_BUFFER_DIM   (3*1024*1024)


static char *FFMultiPartHeaderEnd(const char *header, unsigned long len)
{
    const char *lf, *nxtlf, *end;
    const char *buf_end;
   
    end = NULL;
    buf_end = header + len;
    lf =  memchr(header, '\n', len);
    if (lf == NULL)
        return NULL;
    lf++; /* next charater */
    nxtlf = memchr(lf, '\n', buf_end - lf);
    while (nxtlf != NULL) {
        if (nxtlf-lf < 2) {
            end = nxtlf;
            break;
        }
        nxtlf++;
        lf = nxtlf;
        nxtlf = memchr(nxtlf, '\n', buf_end - nxtlf);
    }

    return (char *)end;
}


static char *FFMultiPartHeaderParam(const char *header, int hlen, const char *param)
{
    const char *line, *eol, *lineend, *hend, *c;
    char *ret;
    int len, host_len, param_len;

    line = header;
    len = hlen;
    hend = header + len;
    lineend = NULL;
    ret = NULL;
    param_len = strlen(param);
    while (lineend < hend) {
        lineend = find_line_end(line, line+len, &eol);
        if (lineend != line+len && (*eol == '\r' || *eol == '\n')) {
            if (strncasecmp(line, param, param_len) == 0) {
                c = line + param_len;
                while (*c == ' ' && c < lineend)
                    c++;
                host_len = eol - c;
                ret = xmalloc(host_len + 1);
                memcpy(ret, c, host_len);
                ret[host_len] = '\0';
                break;
            }
        }
        line = lineend;
        len = hend - lineend;
    }

    return ret;
}


int FFormatUncompress(const char *encoding, const char *file_in,  const char *file_out)
{
    bool decode;
    z_stream zbuff;
    unsigned char *buff;
    unsigned char *raw;
    ssize_t size;
    int ret;
    size_t wsize;
    struct stat info_file;
    FILE *fp;
    
    if (encoding != NULL) {
        decode = FALSE;
        memset(&zbuff, 0, sizeof(z_stream));
        if (strcasecmp(encoding, "gzip") == 0) {
            if (inflateInit2(&zbuff, 47) == Z_OK) {
                decode = TRUE;
            }
        }
        else if (strcasecmp(encoding, "deflate") == 0) {
            if (inflateInit2(&zbuff, -15) == Z_OK) {
                decode = TRUE;
            }
        }
        if (decode && stat(file_in, &info_file) == 0 && info_file.st_size < FF_MALLOC_LIMIT) {
            raw = xmalloc(info_file.st_size);
            fp = fopen(file_in, "r");
            zbuff.avail_in = fread(raw, 1, info_file.st_size, fp);
            fclose(fp);
            zbuff.next_in = raw;
            size = 10240;
            buff = xmalloc(size);
            if (buff != NULL) {
                fp = fopen(file_out, "w");
                do {
                    zbuff.next_out = buff;
                    zbuff.avail_out = size;
                    ret = inflate(&zbuff, Z_SYNC_FLUSH);
                    if (ret == Z_OK || ret == Z_STREAM_END) {
                        wsize = size - zbuff.avail_out;
                        if (fp != NULL)
                            fwrite(buff, 1, wsize, fp);
                        if (ret == Z_STREAM_END) {
                            inflateEnd(&zbuff);
                            break;
                        }
                    }
                    else {
                        if (fp != NULL)
                            fclose(fp);
                        inflateEnd(&zbuff);
                        xfree(buff);
                        xfree(raw);
                        rename(file_in, file_out);
                        
                        return -1;
                    }
                } while (zbuff.avail_in);
                if (fp != NULL)
                    fclose(fp);
                xfree(buff);
            }
            else {
                LogPrintf(LV_ERROR, "No memory");
            }
            xfree(raw);
        }
        else {
            rename(file_in, file_out);
        }
    }
    
    return 0;
}


int FFormatCopy(char *old, char *new)
{
    char *buff;
    FILE *in, *out;
    size_t len;
    int ret = 0;

    /* copy */        
    in = fopen(old, "r");
    if (in != NULL) {
        out = fopen(new, "w");
        if (out != NULL) {
            buff = xmalloc(FF_BUFFER_DIM);
            if (buff != NULL) {
                while ((len = fread(buff, 1, FF_BUFFER_DIM, in)) != 0)
                    fwrite(buff, 1, len, out);
                xfree(buff);
            }
            fclose(out);
        }
        else {
            LogPrintf(LV_WARNING, "Unable to open file (%s)", new);
            ret = -1;
        }
        fclose(in);
    }
    else {
        LogPrintf(LV_WARNING, "Unable to open file (%s)", old);
        ret = -1;
    }

    return ret;
}


multipart_f *FFormatMultipart(const char *file_name, const char *boundary)
{
    FILE *fp, *fpp;
    multipart_f *mp, *mmp;
    char *bndr, *buff, *tmp, *tmpe;
    unsigned long len, rd, bdr_len, hlen, part, wlen, plen;
    bool header;

    if (file_name == NULL)
        return NULL;
    fp = fopen(file_name, "r");
    if (fp == NULL)
        return NULL;
    
    buff = xmalloc(FF_BUFFER_DIM + 2);
    if (buff == NULL) {
        LogPrintf(LV_ERROR, "No memory");
        return NULL;
    }
    len = 0;
    len = fread(buff, 1, FF_BUFFER_DIM, fp);
    buff[len] = '\0';
    if (boundary != NULL) {
        bndr = xmalloc(strlen(boundary) + 10);
        sprintf(bndr, "--%s", boundary);
    }
    else {
        if (len != 0) {
            tmp = strchr(buff, '\r');
            if (tmp == NULL)
                tmp = strchr(buff, '\n');
            if (tmp == NULL) {
                LogPrintf(LV_ERROR, "Not Multipart boundary file");
                xfree(buff);
                fclose(fp);
                return NULL;
            }
            bndr = xmalloc(tmp-buff+10);
            memcpy(bndr, buff, tmp-buff);
            bndr[tmp-buff] = '\0';
        }
    }
    bdr_len = strlen(bndr);
    mp = mmp = NULL;
    fpp = NULL;
    header = TRUE;
    part = 0;
    /* extract parts */
    while (len) {
        if (header) {
            /* find header of part */
            tmp = FFMultiPartHeaderEnd(buff, len);
            if (tmp == NULL) {
                /* end */
                break;
            }
            /* check end boundary */
            if (buff[bdr_len] == '-' && buff[bdr_len+1] == '-')
                break;
            hlen = tmp - buff + 1;
            tmp = FFMultiPartHeaderParam(buff, hlen, "Content-Disposition:");
            if (tmp != NULL) {
                if (mp != NULL) {
                    mp->nxt = xmalloc(sizeof(multipart_f));
                    mp = mp->nxt;
                }
                else {
                    mp = xmalloc(sizeof(multipart_f));
                    mmp = mp;
                }
                part++;
                memset(mp, 0, sizeof(multipart_f));
                mp->vlen = 0;
                mp->name = tmp;
                tmp = strstr(tmp, "filename=");
                if (tmp != NULL) {
                    tmp += 10;
                    tmpe = strrchr(tmp, '\\');
                    if (tmpe != NULL) {
                        tmp = tmpe;
                        tmp++;
                    }
                    else {
                        tmpe = strrchr(tmp, '/');
                        if (tmpe != NULL) {
                            tmp = tmpe;
                            tmp++;
                        }
                    }
                    mp->file_name = xmalloc(strlen(tmp)+1);
                    strcpy(mp->file_name, tmp);
                    tmp = strchr(mp->file_name, '"');
                    if (tmp != NULL)
                        *tmp = '\0';
                    mp->file_path = xmalloc(strlen(file_name)+10);
                    sprintf(mp->file_path, "%s_part_%lu", file_name, part);
                    fpp = fopen(mp->file_path, "w");
                }
                tmp = strstr(mp->name, "name=");
                if (tmp != NULL) {
                    xstrcpy(mp->name, tmp+6);
                    tmp = strchr(mp->name, '"');
                    if (tmp != NULL)
                        *tmp = '\0';
                }
                else {
                    xfree(mp->name);
                    mp->name = strdup("xplico-file_without_name");
                }
                header = FALSE;
            }
           
            tmp = FFMultiPartHeaderParam(buff, hlen, "Content-Range:");
            if (tmp != NULL) {
                if (header) {
                    if (mp != NULL) {
                        mp->nxt = xmalloc(sizeof(multipart_f));
                        mp = mp->nxt;
                    }
                    else {
                        mp = xmalloc(sizeof(multipart_f));
                        mmp = mp;
                    }
                    part++;
                    memset(mp, 0, sizeof(multipart_f));
                    mp->vlen = 0;
                }
                mp->content_range = tmp;
                mp->file_path = xmalloc(strlen(file_name)+10);
                sprintf(mp->file_path, "%s_part_%lu", file_name, part);
                fpp = fopen(mp->file_path, "w");
                header = FALSE;
            }
            if (header) {
                LogPrintf(LV_ERROR, "Multipart boundary header");
                break;
            }
            
            tmp = FFMultiPartHeaderParam(buff, hlen, "Content-Type:");
            if (tmp != NULL) {
                mp->content_type = tmp;
            }
            len -= hlen;
            xmemcpy(buff, buff + hlen, len);
            rd = fread(buff + len, 1, FF_BUFFER_DIM - len, fp);
            if (rd != 0)
                len += rd;
            buff[len] = '\0';
        }
        else {
            /* find the end of part and the start of new part */
            tmp = buff;
            do {
                tmp = memchr(tmp, bndr[0], len - (tmp - buff));
                if (tmp != NULL) {
                    if (len - (tmp - buff) >= bdr_len) {
                        if (tmp[bdr_len-1] == bndr[bdr_len-1]) {
                            tmpe = strstr(tmp, bndr);
                            if (tmpe != NULL) {
                                tmp = tmpe;
                                break;
                            }
                        }
                        tmp++;
                    }
                    else {
                        tmp = NULL;
                    }
                    if (len == (tmp - buff)) {
                        tmp = NULL;
                    }
                }
            } while (tmp != NULL);
            if (tmp != NULL) {
                if (mp != NULL) {
                    /* part completed */
                    plen = tmp - buff;
                    /* check \n\r */
                    if (buff[plen - 1] == '\n')
                        plen--;
                    if (buff[plen - 1] == '\r')
                        plen--;
                    if (mp->file_path != NULL) {
                        if (fpp != NULL) {
                            fwrite(buff, 1, plen, fpp);
                            fclose(fpp);
                            fpp = NULL;
                        }
                    }
                    else {
                        mp->value = xrealloc(mp->value, mp->vlen + plen + 1);
                        memcpy(mp->value+mp->vlen, buff, plen);
                        mp->vlen += plen;
                        mp->value[mp->vlen] = '\0';
                    }
                    header = TRUE;
                    len -= (tmp - buff);
                    xmemcpy(buff, tmp, len);
                    rd = fread(buff + len, 1, FF_BUFFER_DIM - len, fp);
                    if (rd != 0)
                        len += rd;
                    buff[len] = '\0';
                }
                else {
                    LogPrintf(LV_ERROR, "Multipart boundary without part");
                    break;
                }
            }
            else {
                /* data */
                if (len > bdr_len)
                    wlen = len - bdr_len;
                else
                    wlen = len;
                if (mp->file_path != NULL) {
                    if (fpp != NULL) {
                        fwrite(buff, 1, wlen, fpp);
                    }
                }
                else {
                    mp->value = xrealloc(mp->value, mp->vlen + wlen + 1);
                    memcpy(mp->value+mp->vlen, buff, wlen);
                    mp->vlen += wlen;
                    mp->value[mp->vlen] = '\0';
                }
                if (len != wlen) {
                    xmemcpy(buff, buff+wlen, bdr_len);
                    len = bdr_len;
                }
                else
                    len = 0;
                rd = fread(buff+bdr_len, 1, FF_BUFFER_DIM - bdr_len, fp);
                if (rd != 0)
                    len += rd;
                buff[len] = '\0';
            }
        }
    }

    fclose(fp);
    xfree(bndr);
    xfree(buff);
    if (fpp != NULL)
        fclose(fpp);
    
    return mmp;
}


void FFormatMultipartPrint(multipart_f *mp)
{
    short i = 0;

    while (mp != NULL) {
        if (mp->name != NULL)
            LogPrintf(LV_DEBUG, "name [%i]: %s", i, mp->name);
        if (mp->value != NULL)
            LogPrintf(LV_DEBUG, "  value (%i byte): %s", mp->vlen, mp->value);
        if (mp->file_name != NULL)
            LogPrintf(LV_DEBUG, "  file_name: %s", mp->file_name);
        if (mp->file_path != NULL)
            LogPrintf(LV_DEBUG, "  file_path: %s", mp->file_path);
        if (mp->content_type != NULL)
            LogPrintf(LV_DEBUG, "  content_type: %s", mp->content_type);
        if (mp->content_range != NULL)
            LogPrintf(LV_DEBUG, "  content_range: %s", mp->content_range);
        mp = mp->nxt;
        i++;
    }
}


int FFormatMultipartFree(multipart_f *mp)
{
    multipart_f *fr;

    while (mp != NULL) {
        if (mp->name != NULL)
            xfree(mp->name);
        if (mp->value != NULL)
            xfree(mp->value);
        if (mp->file_name != NULL)
            xfree(mp->file_name);
        if (mp->file_path != NULL) {
            remove(mp->file_path);
            xfree(mp->file_path);
        }
        if (mp->content_type != NULL)
            xfree(mp->content_type);
        if (mp->content_range != NULL)
            xfree(mp->content_range);
        fr = mp;
        mp = mp->nxt;
        xfree(fr);
    }
    
    return 0;
}


void f_format_link(void)
{
    
}
