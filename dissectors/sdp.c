/* sdp.c
 * common functions to manage sdp packet
 *
 * $Id: sdp.c,v 1.1 2007/10/30 13:29:38 costa Exp $
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

#include "dmemory.h"
#include "sdp.h"
#include "log.h"


void SdpMsgFree(sdp_msg *msg)
{
    short i, j;

    if (msg == NULL)
        return;

    if (msg->owner.username)
        DMemFree(msg->owner.username);
    if (msg->owner.address)
        DMemFree(msg->owner.address);
    if (msg->ses_name)
        DMemFree(msg->ses_name);
    if (msg->ses_info)
        DMemFree(msg->ses_info);
    if (msg->uri)
        DMemFree(msg->uri);
    if (msg->email)
        DMemFree(msg->email);
    if (msg->phone)
        DMemFree(msg->phone);
    if (msg->cntn_info.address)
        DMemFree(msg->cntn_info.address);
    for (i=0; i<msg->transp.count; i++) {
        DMemFree(msg->transp.proto[i]);
        for (j=0; j<msg->transp.media[i].pt_count; j++)
            if (msg->transp.media[i].rtp_dyn_payload[j] !=  NULL)
                DMemFree(msg->transp.media[i].rtp_dyn_payload[j]);
    }
}


void SdpMsgPrint(sdp_msg *msg)
{
    short i, j;

    if (msg == NULL)
        return;

    LogPrintf(LV_INFO, "Sdp:");
    LogPrintf(LV_INFO, "\tverison:%i", msg->version);
    LogPrintf(LV_INFO, "\towner:");
    if (msg->owner.username)
        LogPrintf(LV_INFO, "\t\tuser name: %s", msg->owner.username);
    LogPrintf(LV_INFO, "\t\tsid: %lu", msg->owner.sid);
    LogPrintf(LV_INFO, "\t\tsversion: %lu", msg->owner.sversion);
    if (msg->owner.address)
        LogPrintf(LV_INFO, "\t\taddress: %s", msg->owner.address);
    if (msg->ses_name)
        LogPrintf(LV_INFO, "\tsession name: %s", msg->ses_name);
    if (msg->ses_info)
        LogPrintf(LV_INFO, "\tsession info: %s", msg->ses_info);
    if (msg->uri)
        LogPrintf(LV_INFO, "\turi: %s", msg->uri);
    if (msg->email)
        LogPrintf(LV_INFO, "\temail: %s", msg->email);
    if (msg->phone)
        LogPrintf(LV_INFO, "\tphone: %s", msg->phone);
    if (msg->cntn_info.address)
        LogPrintf(LV_INFO, "\tcontact address: %s", msg->cntn_info.address);
    for (i=0; i<msg->transp.count; i++) {
        switch (msg->transp.type[i]) {
        case SDP_MEDIA_AUDIO:
            LogPrintf(LV_INFO, "\tmedia type audio");
            break;

        case SDP_MEDIA_VIDEO:
            LogPrintf(LV_INFO, "\tmedia type video");
            break;

        default:
            LogPrintf(LV_INFO, "\tmedia type unknown");
        }
        LogPrintf(LV_INFO, "\tmedia port: %i", msg->transp.port[i]);
        LogPrintf(LV_INFO, "\tmedia protocol: %s", msg->transp.proto[i]);
        for (j=0; j<msg->transp.media[i].pt_count; j++) {
            LogPrintf(LV_INFO, "\tpt: %i", msg->transp.media[i].pt[j]);
            if (msg->transp.media[i].rtp_dyn_payload[j] !=  NULL)
                LogPrintf(LV_INFO, "\tpt dyn: %s", msg->transp.media[i].rtp_dyn_payload[j]);
        }
    }
}


void sdp_link(void)
{

}
