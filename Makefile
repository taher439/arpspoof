CC=gcc
CFLAGS= -W -Wall -Werror -Wextra -O2 -g
LIBS= -lpcap -lnet -fopenmp

SRC=$(wildcard *.c)
OBJS=$(SRC:.c=.o)
AOUT=main

all: main clean_obj

main : $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< $(LIBS)

clean_obj:
	@rm *.o

clean:
	@rm $(AOUT)
