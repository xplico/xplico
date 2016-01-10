/* webmail.h
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009-2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __WEBMAIL_H__
#define __WEBMAIL_H__

/* host name */
#define WMAIL_HOST_NAME_ROSSOALICE_REX     "alicemail\\.rossoalice\\.alice\\.it"
#define WMAIL_HOST_NAME_YAHOO_REX          "\\.mail\\.yahoo\\.com"
#define WMAIL_HOST_NAME_AOL_REX            "webmail\\.aol\\.com"
#define WMAIL_HOST_NAME_HOTMAIL_REX        "\\.mail\\.live\\.com"
#define WMAIL_HOST_NAME_AOL_V2_REX         "mail\\.aol\\.com"
#define WMAIL_HOST_NAME_GMAIL_REX          "mail\\.google\\.com"
#define WMAIL_HOST_NAME_LIBERO_REX         "posta[0-9]*[a-b]\\.mailbeta\\.libero\\.it"
#define WMAIL_HOST_NAME_LIBERO_OLD_REX     "wpop[0-9]*\\.libero\\.it"
#define WMAIL_HOST_NAME_LIBERO_MOBI_REX    "m\\.mailbeta\\.libero\\.it"

/* client name */
#define WMAIL_YAHOO_ANDROID                "YahooMobileMail"

/* AOL */
#define WMAIL_AOL_PATTERN_READ          "a=GetMessage"
#define WMAIL_REDIFF_PATTERN_WRITE      "/prism/writemail"

/* service type */
#define WMAIL_SERVICE_ROSSOALICE        "rossoalice"
#define WMAIL_SERVICE_YAHOO             "yahoo"
#define WMAIL_SERVICE_YAHOO_V2          "yahoo_v2"
#define WMAIL_SERVICE_AOL               "aol"
#define WMAIL_SERVICE_AOL_V2            "aol_v2"
#define WMAIL_SERVICE_HOTMAIL           "hotmail"
#define WMAIL_SERVICE_GMAIL             "gmail"
#define WMAIL_SERVICE_YAHOO_ANDRO       "yahoo mobile"
#define WMAIL_SERVICE_LIBERO            "libero"
#define WMAIL_SERVICE_LIBERO_OLD        "libero old"
#define WMAIL_SERVICE_LIBERO_MOBI       "libero mobile"


#endif /*__WEBMAIL_H__ */
