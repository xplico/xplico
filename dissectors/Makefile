# Makefile
#
# $Id:  $
#
# Xplico - Internet Traffic Decoder
# By Gianluca Costa <g.costa@xplico.org>
# Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
SUBDIRS =  pcapf eth ip ipv6 tcp tcp_grbg udp udp_grbg http pop imap smtp
SUBDIRS += ppp pol sdp ftp dns icmp ipp pjl mms sll tftp vlan l2tp pppoe nntp
SUBDIRS += ieee80211 llc fbwchat telnet webmail httpfd rtp sip rtcp irc msn paltalk
SUBDIRS += arp paltalk_express radiotap icmpv6 ppi syslog prism null chdlc webymsg
SUBDIRS += wa mgcp dns_ca tcp_ca udp_ca ipsec ipsec_ca mpls gtp

# src file
SRC = in_cksum.c http.c sdp.c link.c
CFLAGS_CORE = $(CFLAGS)

# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR

# log parametrization for core
CFLAGS_CORE += -DLOG_COMPONENT=-1

all: subdir libxplico_dissector.a


libxplico_dissector.a: $(SRC:.c=.o)
	ar rcs $@ $(SRC:.c=.o)
	ranlib $@


subdir:
	@for dir in $(SUBDIRS) ; \
	   do $(MAKE) -C $$dir || exit 1; \
	 done \

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir clean || exit 1;rm -f $$dir/dis_log.c;  done
	rm -f *.o *.so *.a *~ include/*~ .depend *.expand


.depend: $(SRC) dis_log.c
	@for dir in $(SUBDIRS) ; do cp -a dis_log.c $$dir/dis_log.c; done
	$(CC) -M $(CFLAGS_CORE) $(SRC) > $@


# custom to use CFLAGS_CORE
.c.o:
	$(CC) -c $< -o $@ $(CFLAGS_CORE)


ifdef SRC
sinclude .depend
endif
