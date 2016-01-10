/* mmsdec.c
 * Test code for mms decoder
 *
 * $Id: $
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
 *
 */

#include <stdio.h>
#include <string.h>

#include "mms_decode.h"

#define MMS_RAW_DIM  1024*500


void Usage(char *argv[])
{
    printf("Usage:\n");
    printf("\t%s <mms_file>\n\n", argv[0]);
}

int main(int argc, char *argv[])
{
    int len;
    char *file = argv[1];
    unsigned char mms_raw[MMS_RAW_DIM];
    mms_message msg;
    FILE *fp;

    if (argc != 2) {
        Usage(argv);
        return 0;
    }

    fp = fopen(file, "r");
    if (fp != NULL) {
        len = fread(mms_raw, 1, MMS_RAW_DIM, fp);
        memset(&msg, 0, sizeof(mms_message));
        MMSDecode(&msg, mms_raw, len, "./");
        MMSPrint(&msg);
        MMSFree(&msg);
        fclose(fp);
    }

    return 0;
}
