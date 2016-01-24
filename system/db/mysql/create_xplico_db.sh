#! /bin/bash
# Copyright (c) 2007-2016 Gianluca Costa
#
# Author: Gianluca Costa, 2007-2016
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
    echo "Usage: ./create_xplico_db.sh <mysql_root_password> <xplico_db_password> [-u]";
    exit;
fi

if [ "$2" = "" ]; then 
    echo "Usage: ./create_xplico_db.sh <mysql_root_password> <xplico_db_password> [-u]";
    exit;
fi

update=0
if [ "$3" = "-u" ]; then
    update=1
else
    if [ "$3" != "" ]; then
        echo "Usage: ./create_xplico_db.sh <mysql_root_password> <xplico_db_password> [-u]";
        exit;
    fi
fi


user="root"
password=$1
xplico_pass=$2

# delete xplico db and user if exist
if [ $update = 0 ]; then
    echo "DROP DATABASE IF EXISTS xplico;" | mysql --user=$user --password=$password
    echo "DROP USER 'xplico'@'localhost';" | mysql --user=$user --password=$password >& /dev/null

# create xplico DB and user
    echo "CREATE DATABASE xplico;" | mysql --user=$user --password=$password
    echo "CREATE USER 'xplico'@'localhost' IDENTIFIED BY '"$xplico_pass"';" | mysql --user=$user --password=$password
    echo "GRANT ALL PRIVILEGES ON xplico.* TO 'xplico'@'localhost';" | mysql --user=$user --password=$password
fi

# create tables
mysql --user=$user --password=$password xplico < params.sql
mysql --user=$user --password=$password xplico < groups.sql
mysql --user=$user --password=$password xplico < users.sql
mysql --user=$user --password=$password xplico < pols.sql
mysql --user=$user --password=$password xplico < sols.sql
mysql --user=$user --password=$password xplico < sources.sql
mysql --user=$user --password=$password xplico < emails.sql
mysql --user=$user --password=$password xplico < sips.sql
mysql --user=$user --password=$password xplico < rtps.sql
mysql --user=$user --password=$password xplico < inputs.sql
mysql --user=$user --password=$password xplico < webs.sql
mysql --user=$user --password=$password xplico < ftps.sql
mysql --user=$user --password=$password xplico < ftp_files.sql
mysql --user=$user --password=$password xplico < pjls.sql
mysql --user=$user --password=$password xplico < mms.sql
mysql --user=$user --password=$password xplico < mmscontents.sql
mysql --user=$user --password=$password xplico < feeds.sql
mysql --user=$user --password=$password xplico < feed_xmls.sql
mysql --user=$user --password=$password xplico < tftps.sql
mysql --user=$user --password=$password xplico < tftp_files.sql
mysql --user=$user --password=$password xplico < dns_messages.sql
mysql --user=$user --password=$password xplico < nntp_groups.sql
mysql --user=$user --password=$password xplico < nntp_articles.sql
mysql --user=$user --password=$password xplico < fbuchats.sql
mysql --user=$user --password=$password xplico < fbchats.sql
mysql --user=$user --password=$password xplico < telnets.sql
mysql --user=$user --password=$password xplico < webmail.sql
mysql --user=$user --password=$password xplico < httpfiles.sql
mysql --user=$user --password=$password xplico < unknows.sql
mysql --user=$user --password=$password xplico < arps.sql
mysql --user=$user --password=$password xplico < ircs.sql
mysql --user=$user --password=$password xplico < irc_channels.sql
mysql --user=$user --password=$password xplico < paltalk_exps.sql
mysql --user=$user --password=$password xplico < paltalks.sql
mysql --user=$user --password=$password xplico < msns.sql
mysql --user=$user --password=$password xplico < icmpv6s.sql
mysql --user=$user --password=$password xplico < syslogs.sql
mysql --user=$user --password=$password xplico < unkfiles.sql
mysql --user=$user --password=$password xplico < webymsgs.sql
mysql --user=$user --password=$password xplico < mgcps.sql
mysql --user=$user --password=$password xplico < whatsapps.sql

if [ $update = 0 ]; then
    mysql --user=$user --password=$password xplico < default.sql
fi





