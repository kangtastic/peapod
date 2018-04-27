PROGRAM			= peapod

CC			= gcc
CFLAGS			= -I$(IDIR) -Wall -Wextra -pedantic --std=gnu11 -O3

IDIR			= include
ODIR			= obj
SDIR			= src

PARSER			= parser
LEXER			= lexer

_IDEPS			= args.h b64enc.h defaults.h daemonize.h iface.h \
			  includes.h log.h packet.h parser.h peapod.h \
			  process.h proxy.h
IDEPS			= $(patsubst %,$(IDIR)/%,$(_IDEPS))

_SDEPS			= $(PARSER).c $(LEXER).c
SDEPS			= $(patsubst %,$(SDIR)/%,$(_DEPS))

DEPS			= $(IDEPS) $(SDEPS)

_OBJ			= peapod.o log.o args.o $(PARSER).o $(LEXER).o \
			  b64enc.o daemonize.o iface.o packet.o process.o \
			  proxy.o
OBJ			= $(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o:		$(SDIR)/%.c
			$(CC) -c -o $@ $< $(CFLAGS)

peapod:			$(OBJ)
			$(CC) -o $@ $^ $(CFLAGS)

all:			$(PROGRAM)

$(SDIR)/$(PARSER).c:	$(SDIR)/$(PARSER).y
			bison --defines=$(IDIR)/$(PARSER).yy.h \
				--output=$(SDIR)/$(PARSER).c \
				$(SDIR)/$(PARSER).y

$(SDIR)/$(LEXER).c:	$(SDIR)/$(LEXER).l
			flex --outfile=$(SDIR)/$(LEXER).c $(SDIR)/$(LEXER).l

debug:			CFLAGS += -g
debug:			clean $(PROGRAM)

clean:
			rm -f $(OBJ) $(IDIR)/$(PARSER).yy.h $(SDIR)/$(PARSER).c \
				$(SDIR)/$(LEXER).c $(PROGRAM)
