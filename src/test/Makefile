CC=gcc
CFLAGS=-I$(IDIR) -Wall -g

ODIR=../obj
LDIR=../../lib
IDIR=../../include

LIBNAME=mycrypto
LIBFILE=lib$(LIBNAME).a
LIBS=-l$(LIBNAME)

_DEPS=aes.h priv/priv_aes.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))
_OBJS=test.o aes.o
OBJS=$(patsubst %,$(ODIR)/%,$(_OBJS))


all: test
.PHONY: clean

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJS)
	$(CC) -o $@ $(OBJS) $(CFLAGS)
	python openssl_tests.py

clean:
	rm -f $(ODIR)/*.o *~ $(IDIR)/*~ test
