# Makefile
#
# $Id: Makefile,v 1.5 2007/10/30 13:29:37 costa Exp $
#
# Xplico - Internet Traffic Decoder
# By Gianluca Costa <g.costa@xplico.org>
# Copyright 2007-2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
DIS_NAME = dis_ip
DIS_NAME_NOCHECK = $(DIS_NAME)_nocheck

# dissector library (.so)
DIS_SO = $(DIS_NAME).so
DIS_SO_NC = $(DIS_NAME_NOCHECK).so

# sub directory
SUBDIRS = 

# src file
SRC = dis_log.c ip.c


# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR


all: subdir $(DIS_SO) $(DIS_SO_NC)


$(DIS_SO): $(SRC:.c=.o)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$@ -o $@ $(SRC:.c=.o) $(LDFLAGS)


$(DIS_SO_NC): dis_log.o ip_nc.o
	$(CC) $(CFLAGS) -shared -Wl,-soname,$@ -o $@ dis_log.o ip_nc.o $(LDFLAGS)


subdir:
	@for dir in $(SUBDIRS) ; \
	   do $(MAKE) -C $$dir || exit 1; \
	 done \

clean:
	@for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean || exit 1; done
	rm -f *.o *.so *~ include/*~ .depend *.expand


.depend: $(SRC)
	$(CC) -M $(CFLAGS) $(SRC) > $@

ip_nc.o: ip.o
	$(CC) $(CFLAGS) -DXPL_DIS_IP_CHECKSUM=1 -c -o $@ ip.c


include ../Makefilelog
sinclude .depend
