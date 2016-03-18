# Makefile
#
# $Id:  $
#
# Xplico - Internet Traffic Decoder
# By Gianluca Costa <g.costa@xplico.org>
# Copyright 2012-2013 Gianluca Costa. Web: www.xplico.org
#

# dispatch name
DISP_NAME = disp_capostgres


# dispatch library (.so)
DISP_SO = $(DISP_NAME).so

# sub directory
SUBDIRS = 

# src file
SRC = capostgres.c

# compilation
CFLAGS += $(shell pkg-config --cflags libpq)
LDFLAGS += -lpq

# To make it visible
export CC CCPP ROOT_DIR CFLAGS LDFLAGS INCLUDE_DIR


all: subdir $(DISP_SO)


$(DISP_SO): $(SRC:.c=.o)
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


sinclude .depend
