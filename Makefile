SHELL = /bin/sh

prefix = /usr
exec_prefix = ${prefix}
bindir = ${exec_prefix}/bin
mandir = ${prefix}/share/man/man1

CC ?= gcc
DEBUG = -g
CFLAGS ?= -O2
CFLAGS += $(DEBUG)
SRC = src
DOC = doc

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644

all: bittwist

bittwist:
	$(CC) $(CFLAGS) $(SRC)/bittwist.c -o $(SRC)/bittwist -I/usr/local/include -L/usr/local/lib -lpcap

clean:
	rm -f $(SRC)/bittwist

install:
	mkdir -p $(bindir)
	chmod 755 $(bindir)
	$(INSTALL_PROGRAM) $(SRC)/bittwist $(bindir)
	mkdir -p $(mandir)
	chmod 755 $(mandir)
	$(INSTALL_DATA) $(DOC)/bittwist.1 $(mandir)

uninstall:
	rm -f $(bindir)/bittwist
	rm -f $(mandir)/bittwist.1
