CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -pipe -std=c99 -Wno-packed-bitfield-compat -Wpointer-arith -Wformat-nonliteral -Winit-self -Wshadow -Wcast-qual -Wmissing-prototypes
EXE = fs
LIBS =
PSRC = disk.c fat.c fathelper.c fs.c utils.c
POBJ = disk.o fat.o fathelper.o fs.o utils.o

sched: $(POBJ)
	$(CC) $(CFLAGS) -o $(EXE) $(POBJ) $(LIBS)

clean:
	/bin/rm $(POBJ)

clobber:
	/bin/rm $(POBJ) $(EXE)

fat.o: fat.h fathelper.h fatstruct.h disk.h utils.h
fathelper.o: fatstruct.h disk.h utils.h
fs.o: fat.h utils.h
disk.o: disk.h utils.h
utils.o: utils.h
