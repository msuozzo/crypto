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
.PHONY: clean obj

$(ODIR)/%.o: %.c $(DEPS) obj
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJS) obj
	$(CC) -o $@ $(OBJS) $(CFLAGS)

clean:
	rm -f $(ODIR)/*.o *~ core $(IDIR)/*~ 
