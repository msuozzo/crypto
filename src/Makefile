CC=gcc
CFLAGS=-I$(IDIR) -Wall -g

ODIR=obj
LDIR=../lib
IDIR=../include

LIBNAME=mycrypto
LIBFILE=lib$(LIBNAME).a
LIBS=-l$(LIBNAME)

_DEPS = aes.h priv/priv_aes.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))
_OBJS=aes.o
OBJS=$(patsubst %,$(ODIR)/%,$(_OBJS))


all: test
.PHONY: clean obj lib

obj:
	mkdir -p obj

$(ODIR)/%.o: %.c $(DEPS) obj
		$(CC) -c -o $@ $< $(CFLAGS)

$(LIBFILE): $(OBJS)
	ar -cvq $(LIBFILE) $(OBJS)

lib: $(LIBFILE)
	mv $(LIBFILE) $(LDIR)


test: $(OBJS) obj
	cd test; make;


clean:
		rm -f $(ODIR)/*.o *~ $(IDIR)/*~ $(LDIR)/$(LIBFILE)
