# Makefile
#
# $Id: $
#
# Xplico System
# By Gianluca Costa <g.costa@xplico.org>
# Copyright 2007-2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
#
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

PYCMPL = python3 -m compileall

# root directory
ROOT_DIR = $(shell pwd)
ifndef INSTALL_DIR
INSTALL_DIR = /opt/xplico
endif


# src file
SRC = session_mng.py mimedump.py

# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR INSTALL_DIR

all: pycmpl


pycmpl: $(SRC:.py=.pyc)
	chmod +x *.pyc
	rm -rf __pycache__


%.pyc: %.py
	rm -f $@
	$(PYCMPL) $<
	if [ -d "__pycache__" ]; then mv __pycache__/*.pyc $@; fi

clean:
	rm -f *~
	rm -rf __pycache__
	rm -f *.pyc

install:
