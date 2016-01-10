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

# sub directory
SUBDIRS = 

# manipulator name
MANIPULA_NAME = mpaltalk

# xplico library
XPL_LIB = $(ROOT_DIR)/common/libxplico_core.a $(ROOT_DIR)/dispatch/libxplico_dispatch.a $(ROOT_DIR)/dissectors/libxplico_dissector.a

# src files
SRC = mmain.c mpei.c analyse.c

# obj files
OBJ = $(SRC:.c=.o)

# dep 
DEP = ../core/mmain.c mpei.c analyse.c

# compilation
LDFLAGS =  -L$(ROOT_DIR) -ldl -lpthread -lz -lssl -lcrypto

# cflags
CFLAGS += -I./include

# verify GeoIP library source code
ifeq ($(wildcard $(GEOIP_LIB)), $(GEOIP_LIB))
XPL_LIB += $(GEOIP_LIB)
endif

# main cflags
MCFLAGS = $(CFLAGS) -DLOG_COMPONENT=-1

# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR


all: subdir $(MANIPULA_NAME)


$(MANIPULA_NAME): $(OBJ) $(XPL_LIB)
	$(CC) $(MCFLAGS) -o $@ $(OBJ) $(XPL_LIB) $(LDFLAGS)
	rm -f modules config tmp
	cp $(MANIPULA_NAME) $(ROOT_DIR)

subdir:
	@for dir in $(SUBDIRS) ; \
	   do $(MAKE) -C $$dir || exit 1; \
	 done


clean:
	@for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean || exit 1; done
	rm -f $(MANIPULA_NAME) $(ROOT_DIR)/$(MANIPULA_NAME) *.o *.so *~ include/*~ .depend *.expand
	rm -f modules config tmp xdecode

install:
	cp $(MANIPULA_NAME) $(INSTALL_DIR)/bin


mmain.o: ../core/mmain.c
	$(CC) $(MCFLAGS) -c -o $@ $<

%.o: %.c
	$(CC) $(MCFLAGS) -c -o $@ $<


.depend: $(DEP)
	$(CC) -M $(MCFLAGS) $(DEP) > $@


sinclude .depend
