/* xplxml.h
 *
 * $Id: xplxml.h,v 1.3 2007/09/22 14:04:57 costa Exp $
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

/*
<?xml version="1.0" encoding="ISO-8859-1"?>

  <flow num="1">
     <frame type="eth">
        <prop name="eth.type" value="5" />
     </frame>
  </flow>
  
  <flow num=2>
  ...
  </flow>
  
  ...
*/

#ifndef __XPLXML_H__
#define __XPLXML_H__

#define XPL_HEADER          "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\r\n<?xml-stylesheet type=\"text/css\" href=\"/css/flows.css\"?>\r\n\r\n"
#define XPL_FLOW_OPEN       "<flow>\r\n  <number>--- Decoding info: stream %d ---</number>\r\n"
#define XPL_FLOW_CLOSE      "</flow>\r\n"
#define XPL_GRP_FRAME_OPEN  "<grp>\r\n"
#define XPL_GRP_FRAME_CLOSE "</grp>\r\n"
#define XPL_FRAME_OPEN      "  <frame>\r\n    <frm_type>%s</frm_type>\r\n"
#define XPL_FRAME_CLOSE     "  </frame>\r\n"
#define XPL_PROP            "    <prop>\r\n      <name>%s</name>\r\n      <value>%s</value>\r\n    </prop>\r\n"




#endif /* __XPLXML_H__ */
