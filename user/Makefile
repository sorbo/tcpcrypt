include common.mak

SUBDIRS	= contrib tcpcrypt lib test

all:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $(@); done

clean:
	@for dir in $(SUBDIRS); do $(MAKE) -C $$dir $(@); done
