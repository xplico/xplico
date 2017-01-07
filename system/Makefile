# Makefile
#
# $Id: $
#
# Xplico System
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
SUBDIRS = dema trigcap script



# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR INSTALL_DIR

all: subdir 


subdir:
	@for dir in $(SUBDIRS) ; \
	   do $(MAKE) -C $$dir  || exit 1; \
	 done \

clean:
	@for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir clean || exit 1; done
	rm -f *~ .depend */*~ */*/*~ *.expand
	rm -f xi*/*~ xi*/*/*~ xi*/*/*/*~
	rm -f xi*/*/*/*/*~ xi*/*/*/*/*/*~ 
	rm -f xi*/*/*/*/*/*/*~ xi*/*/*/*/*/*/*~
	rm -f xi*/app/tmp/cache/*/*
	rm -f pcap2wav/*~ pcap2wav/*/*~ pcap2wav/*/*/*~
	rm -rf pcap2wav/server/php/files/*


install:
	mkdir -p $(INSTALL_DIR)/script/db/sqlite
	mkdir -p $(INSTALL_DIR)/script/db/mysql
	rm -f */*~ */*/*~
	cp script/*.sh $(INSTALL_DIR)/script
        cp script/*.py $(INSTALL_DIR)/script
	cp script/*.pyc $(INSTALL_DIR)/script
	cp script/*.php $(INSTALL_DIR)/script
	cp script/xplico $(INSTALL_DIR)/script
	cp script/sol_subdir.cfg $(INSTALL_DIR)/cfg
	cp db/sqlite3/*.sh $(INSTALL_DIR)/script/db/sqlite
	cp db/sqlite3/*.py $(INSTALL_DIR)/script/db/sqlite
	cp db/sqlite3/*.sql $(INSTALL_DIR)/script/db/sqlite
	cp db/mysql/*.sh $(INSTALL_DIR)/script/db/mysql
#	cp db/mysql/*.py $(INSTALL_DIR)/script/db/mysql
	cp db/mysql/*.sql $(INSTALL_DIR)/script/db/mysql
	@for dir in $(SUBDIRS) ; do $(MAKE) -C $$dir install || exit 1; done
	cd $(INSTALL_DIR)/script/db/sqlite; ./create_xplico_db.sh $(INSTALL_DIR)
	cp -a xi3 $(INSTALL_DIR)/xi
	cp web_cfg/apache_xi $(INSTALL_DIR)/cfg
	cp web_cfg/httpd_xi $(INSTALL_DIR)/cfg


.depend: $(SRC)
#	$(CC) -M $(CFLAGS) $(SRC) > $@


sinclude .depend
