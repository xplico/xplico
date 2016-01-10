#! /bin/bash
# Copyright (c) 2007-2011 Gianluca Costa
#
# Author: Gianluca Costa, 2007-2011
#      g.costa@xplico.org
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

if [ "$1" = "" ]; then
    DIR_BASE=/opt/xplico
else
    DIR_BASE=$1
fi

def=0
if [ -e $DIR_BASE/xplico.db ]; then
    def=1
fi

sqlite3 $DIR_BASE/xplico.db < params.sql
sqlite3 $DIR_BASE/xplico.db < groups.sql
sqlite3 $DIR_BASE/xplico.db < users.sql
sqlite3 $DIR_BASE/xplico.db < pols.sql
sqlite3 $DIR_BASE/xplico.db < sols.sql
sqlite3 $DIR_BASE/xplico.db < sources.sql
sqlite3 $DIR_BASE/xplico.db < emails.sql
sqlite3 $DIR_BASE/xplico.db < sips.sql
sqlite3 $DIR_BASE/xplico.db < rtps.sql
sqlite3 $DIR_BASE/xplico.db < inputs.sql
sqlite3 $DIR_BASE/xplico.db < webs.sql
sqlite3 $DIR_BASE/xplico.db < ftps.sql
sqlite3 $DIR_BASE/xplico.db < ftp_files.sql
sqlite3 $DIR_BASE/xplico.db < pjls.sql
sqlite3 $DIR_BASE/xplico.db < mms.sql
sqlite3 $DIR_BASE/xplico.db < mmscontents.sql
sqlite3 $DIR_BASE/xplico.db < feeds.sql
sqlite3 $DIR_BASE/xplico.db < feed_xmls.sql
sqlite3 $DIR_BASE/xplico.db < tftps.sql
sqlite3 $DIR_BASE/xplico.db < tftp_files.sql
sqlite3 $DIR_BASE/xplico.db < dns_messages.sql
sqlite3 $DIR_BASE/xplico.db < nntp_groups.sql
sqlite3 $DIR_BASE/xplico.db < nntp_articles.sql
sqlite3 $DIR_BASE/xplico.db < fbuchats.sql
sqlite3 $DIR_BASE/xplico.db < fbchats.sql
sqlite3 $DIR_BASE/xplico.db < telnets.sql
sqlite3 $DIR_BASE/xplico.db < webmail.sql
sqlite3 $DIR_BASE/xplico.db < httpfiles.sql
sqlite3 $DIR_BASE/xplico.db < unknows.sql
sqlite3 $DIR_BASE/xplico.db < arps.sql
sqlite3 $DIR_BASE/xplico.db < ircs.sql
sqlite3 $DIR_BASE/xplico.db < irc_channels.sql
sqlite3 $DIR_BASE/xplico.db < paltalk_exps.sql
sqlite3 $DIR_BASE/xplico.db < paltalks.sql
sqlite3 $DIR_BASE/xplico.db < msns.sql
sqlite3 $DIR_BASE/xplico.db < icmpv6s.sql
sqlite3 $DIR_BASE/xplico.db < syslogs.sql
sqlite3 $DIR_BASE/xplico.db < unkfiles.sql
sqlite3 $DIR_BASE/xplico.db < webymsgs.sql
sqlite3 $DIR_BASE/xplico.db < mgcps.sql
sqlite3 $DIR_BASE/xplico.db < whatsapps.sql

if [ $def = 0 ]; then
    sqlite3 $DIR_BASE/xplico.db < default.sql
fi


chmod 666 $DIR_BASE/xplico.db






