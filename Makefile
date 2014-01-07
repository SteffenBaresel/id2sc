###################################
# Makefile for NEB examples
###################################


# Source code directories
SRC_INCLUDE=./include

CC=gcc
MOD_CFLAGS=-fPIC
CFLAGS=-Wall -g -O2 -DHAVE_CONFIG_H
MOD_LDFLAGS=-shared -L/usr/local/lib
LDFLAGS=-lzdb
LIBS=-I/usr/local/include/zdb
MATHLIBS=-lm

prefix=/usr/local/icinga
exec_prefix=${prefix}
BINDIR=${exec_prefix}/bin
LIBDIR=${exec_prefix}/lib
INSTALL=/usr/bin/install -c
INSTALL_OPTS=-o icinga -g icinga
COMMAND_OPTS=-o icinga -g icinga
STRIP=/usr/bin/strip

CP=@CP@

###############################
# Debug
###############################
ENABLE_DEBUG=no

# Compiler flags for use with Valgrind - set when debug is enabled
ifeq ('$(ENABLE_DEBUG)', 'yes')
	CFLAGS=-O0 -g
endif

all: id2sc.so

id2sc.so: ./src/id2sc.c
	$(CC) $(MOD_CFLAGS) $(CFLAGS) -o ./bin/id2sc.so ./src/id2sc.c $(MOD_LDFLAGS) $(LDFLAGS) $(LIBS) $(MATHLIBS)

clean:
	rm -f id2sc.o
	rm -f core *.o *.so
	rm -f *~ *.*~
	rm -Rf ./include ./bin
	rm Makefile

distclean: clean
	rm -f Makefile

devclean: distclean

install:
	cp -f ./bin/id2sc.so /usr/local/icinga/bin/
