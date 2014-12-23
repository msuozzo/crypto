
IDIR =../include
CC=clang
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR =../lib

LIBS=-lm

_DEPS = aes.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

_OBJ = aes.o test.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))


all: test
.PHONY: clean obj

obj:
	mkdir -p obj

$(ODIR)/%.o: %.c $(DEPS) obj
		$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJ)
		$(CC) -o $@ $^ $(CFLAGS) $(LIBS)


clean:
		rm -f $(ODIR)/*.o *~ core $(IDIR)/*~ 
