include common.mak

SUBDIRS	= contrib tcpcrypt lib test util

all:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $(@); done

install: lib/libtcpcrypt.$(SO)
	ls /usr/lib/libtcpcrypt.$(SO) > /dev/null || ln -s $(shell pwd)/lib/libtcpcrypt.$(SO) /usr/lib/libtcpcrypt.$(SO)
	cp util/tcnetstat /usr/local/bin/tcnetstat

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $(@); done
