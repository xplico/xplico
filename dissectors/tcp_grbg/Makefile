# Makefile
#
# $Id:  $
#
# Xplico - Internet Traffic Decoder
# By Gianluca Costa <g.costa@xplico.org>
# Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

# dissector name
DIS_NAME = dis_tcp_grb


# dissector library (.so)
DIS_SO = $(DIS_NAME).so

# sub directory
SUBDIRS = 

# src file
SRC = dis_log.c tcp_garbage.c

# C flags specific to the dissector
CFLAGS += -I$(ROOT_DIR)/../nDPI/src/include -I$(ROOT_DIR)/../nDPI/src/lib

# library specific to the dissector
LDFLAGS = $(ROOT_DIR)/../nDPI/src/lib/.libs/libndpi.a

# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR


all: subdir $(DIS_SO)


$(DIS_SO): $(SRC:.c=.o) $(ROOT_DIR)/../nDPI/src/lib/.libs/libndpi.a
	$(CC) $(CFLAGS) -shared -Wl,-soname,$@ -o $@ $(SRC:.c=.o) $(LDFLAGS)


subdir:
	@for dir in $(SUBDIRS) ; \
	   do $(MAKE) -C $$dir || exit 1; \
	 done \

clean:
	@for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean || exit 1; done
	rm -f *.o *.so *~ include/*~ .depend *.expand


.depend: $(SRC)
	$(CC) -M $(CFLAGS) $(SRC) > $@


include ../Makefilelog
sinclude .depend
