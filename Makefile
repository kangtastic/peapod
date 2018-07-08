# Makefile for peapod - EAPOL Proxy Daemon

ifeq (,$(SYSTEMSERVICE))
PKG_CONFIG		?= $(shell command -v pkg-config > /dev/null && echo pkg-config)
ifeq (pkg-config,$(PKG_CONFIG))
SYSTEMCTL		:= $(shell command -v systemctl > /dev/null && echo systemctl)
ifeq (systemctl,$(SYSTEMCTL))
SYSTEMSERVICE		?= $(shell $(PKG_CONFIG) systemd --variable=systemdsystemunitdir)
SYSTEMSERVICE		:= $(SYSTEMSERVICE)
endif
endif
endif

ifeq (,$(SYSTEMSERVICE))
$(error "Cannot determine systemd system unit .service file directory.")
endif

PREFIX			?= /usr
SBIN			= $(PREFIX)/sbin
SHARE			= $(PREFIX)/share

CC			= gcc
CFLAGS			?= -O2 -fstack-protector-strong -Wall -Wextra -pedantic -Wformat -Werror=format-security -fPIC -pie -Wl,-z,relro -Wl,-z,now --std=gnu11
CFLAGS			+= -I$(IDIR)

YACC			= bison
LEX			= flex

BDIR			= bin
DDIR			= doc
HDIR			= html
IDIR			= include
ODIR			= obj
SDIR			= src

_OBJS			= parser.o lexer.o \
			  args.o b64enc.o daemonize.o iface.o log.o \
			  packet.o peapod.o process.o proxy.o
OBJS			= $(patsubst %,$(ODIR)/%,$(_OBJS))

.PHONY:			all debug
all:			peapod doc service

debug:			CFLAGS := $(filter-out -O2,$(CFLAGS)) -g
debug:			cleanall peapod

.PHONY:			doc
doc:			$(BDIR)/peapod.8.gz $(BDIR)/peapod.conf.5.gz

$(BDIR)/peapod.8.gz:	$(DDIR)/peapod.8
			gzip < $(DDIR)/peapod.8 > $(BDIR)/peapod.8.gz
$(BDIR)/peapod.conf.5.gz: $(DDIR)/peapod.conf.5
			gzip < $(DDIR)/peapod.conf.5 > $(BDIR)/peapod.conf.5.gz

html:			cleanall
			doxygen Doxyfile

.PHONY:			service
service:		$(BDIR)/peapod.service

$(BDIR)/peapod.service:	peapod.service.in
			sed "s|__SBIN__|$(SBIN)|" peapod.service.in > $(BDIR)/peapod.service

.PHONY:			peapod
peapod:			$(ODIR) $(BDIR) $(BDIR)/peapod

$(BDIR)/peapod:		$(OBJS)
			$(CC) -o $@ $^ $(CFLAGS)
$(ODIR):
			mkdir -p $(ODIR)
$(BDIR):
			mkdir -p $(BDIR)
$(ODIR)/%.o:		$(SDIR)/%.c
			$(CC) -c -o $@ $< $(CFLAGS)
$(SDIR)/parser.c:	$(SDIR)/parser.y
			$(YACC) --defines=$(IDIR)/parser.yy.h --output=$(SDIR)/parser.c $(SDIR)/parser.y
$(SDIR)/lexer.c:	$(SDIR)/lexer.l
			$(LEX) --outfile=$(SDIR)/lexer.c $(SDIR)/lexer.l

.PHONY:			clean cleanall cleanhtml
cleanall:		clean cleanhtml

clean:
			rm -rf $(ODIR) $(BDIR)
			rm -f $(IDIR)/parser.yy.h $(SDIR)/parser.c $(SDIR)/lexer.c
cleanhtml:
			rm -rf $(HDIR)

.PHONY:			install installpeapod installdoc installservice \
			uninstall
install:		installpeapod installdoc installservice

installpeapod:		peapod
			install -D -m 755 $(BDIR)/peapod $(DESTDIR)$(SBIN)/peapod
installdoc:		doc $(DDIR)/peapod.8.html $(DDIR)/peapod.conf.5.html $(DDIR)/examples
			install -D -m 644 $(BDIR)/peapod.8.gz $(DESTDIR)$(SHARE)/man/man8/peapod.8.gz
			install -D -m 644 $(BDIR)/peapod.conf.5.gz $(DESTDIR)$(SHARE)/man/man5/peapod.conf.5.gz
			install -D -m 644 -t $(DESTDIR)$(SHARE)/peapod/examples $(wildcard $(DDIR)/examples/*.conf)
			install -D -m 755 $(wildcard $(DDIR)/examples/*.sh) $(DESTDIR)$(SHARE)/peapod/examples
			install -D -m 644 $(DDIR)/peapod.8.html $(DESTDIR)$(SHARE)/peapod/peapod.8.html
			install -D -m 644 $(DDIR)/peapod.conf.5.html $(DESTDIR)$(SHARE)/peapod/peapod.conf.5.html
installservice:		service
			install -D -m 644 $(BDIR)/peapod.service $(DESTDIR)$(SYSTEMSERVICE)/peapod.service

uninstall:
			rm -f $(DESTDIR)$(SBIN)/peapod
			rm -f $(DESTDIR)$(SHARE)/man/man8/peapod.8.gz
			rm -f $(DESTDIR)$(SHARE)/man/man5/peapod.conf.5.gz
			rm -rf $(DESTDIR)$(SHARE)/peapod
