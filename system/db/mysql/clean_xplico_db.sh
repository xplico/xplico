#! /bin/bash
# Copyright (c) 2007-2016 Gianluca Costa
#
# Author: Gianluca Costa, 2016
#      g.costa@xplico.org
#


if [ "$1" = "" ]; then 
   echo "Usage: ./clean_xplico_db.sh <mysql_root_password>";
   exit;
fi


user="root"
password=$1

mysql --user=$user --password=$password xplico < clean.sql








