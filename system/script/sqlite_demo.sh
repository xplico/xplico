#! /bin/bash
# Copyright (c) 2007 Gianluca Costa
#
# Author: Gianluca Costa, 2007-2010
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


# ulimit
ulimit -n 200000
ulimit -c unlimited
ulimit -m unlimited
ulimit -u unlimited
ulimit -v unlimited

# kill
killall dema

# add xplico parh
export PATH=$PATH:/opt/xplico/bin
rm -f /opt/xplico/bin/core*

# start dema
(cd /opt/xplico/bin; ./dema -d /opt/xplico -b sqlite) &


