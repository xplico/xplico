# Makefile
#
# $Id: $
#
# Xplico System
# By Gianluca Costa <g.costa@xplico.org>
# Copyright 2007-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

# root directory
ROOT_DIR = $(shell pwd)
ifndef INSTALL_DIR
INSTALL_DIR = /opt/xplico
endif

# sub directory
SUBDIRS = 

# xplico library
XPL_LIB =

# src file
SRC = dema.c session_decoding.c dbinterface.c captime.c log.c

# compilation
INCLUDE_DIR = -I$(ROOT_DIR)/include
LDFLAGS = -L$(ROOT_DIR) -ldl -lpthread -lpcap
CFLAGS = -rdynamic $(INCLUDE_DIR) -Wall -g -ggdb -fPIC -D_FILE_OFFSET_BITS=64

LDFLAGS += -L/usr/lib/mysql -L/usr/lib64/mysql -lmysqlclient_r
CFLAGS += -DMYSQLXON=1

# performance
ifdef GPROF
CFLAGS += -pg
endif

# sqlite version
LDFLAGS += -lsqlite3 -lssl -lcrypto

# postgresql version
CFLAGS += $(shell pkg-config --cflags libpq)
LDFLAGS += $(shell pkg-config --libs libpq)


# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR INSTALL_DIR

all: subdir dema

help:
	@echo "Flags:"
	@echo "    VER=<string>  --> string is the release name, otherwise the date is the name"
	@echo "    GPROF=1       --> enable gprof compilation"
	@echo " "
	@echo "Comands:"
	@echo "    help    --> this help"
	@echo "    clean   --> clean"
	@echo "    tgz     --> project snapshot"
	@echo "    install --> install in "$(INSTALL_DIR)
	@echo " "

# version name
ifndef VER
VER = -$(shell date +%Y_%m_%d)
endif

dema: $(SRC:.c=.o)
	$(CC) $(CFLAGS) -o $@ $(SRC:.c=.o) $(LDFLAGS)


subdir:
	@for dir in $(SUBDIRS) ; \
	   do $(MAKE) -C $$dir || exit 1; \
	 done


clean: reset
	@for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean ; done
	rm -f include/*~
	rm -f dema *.o *~ *.log .depend val.* *.expand


install: all
	mkdir -p $(INSTALL_DIR)
	mkdir -p $(INSTALL_DIR)/bin
	cp -a dema $(INSTALL_DIR)/bin
#	strip -s $(INSTALL_DIR)/bin/dema
	cp dema*.cfg $(INSTALL_DIR)/cfg

.PHONY: reset
reset:
	rm -rf tmp/*


%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 


tgz: clean
	cd ..; tar cvzf dema$(VER).tgz --exclude cscope.files --exclude cscope.out --exclude CVS --exclude release dema
	mkdir -p release
	mv ../dema$(VER).tgz release
	rm -f release/*.gpg



.depend: $(SRC)
	$(CC) -M $(CFLAGS) $(SRC) > $@


sinclude .depend
