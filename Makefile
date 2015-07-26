CC = gcc

LIBS = /users/cse533/Stevens/unpv13e/libunp.a -lpthread
FLAGS = -g -O2

CFLAGS = ${FLAGS} -Wno-int-to-pointer-cast -I/users/cse533/Stevens/unpv13e/lib

all: arp tour

tour: get_hw_addrs.o tour.o
	${CC} ${FLAGS} -o ssrinath_tour tour.o get_hw_addrs.o ${LIBS}
tour.o: tour.c common.h
	${CC} ${CFLAGS} -c tour.c

arp: get_hw_addrs.o arp.o
	${CC} ${FLAGS} -o ssrinath_arp arp.o get_hw_addrs.o ${LIBS}
arp.o: arp.c common.h
	${CC} ${CFLAGS} -c arp.c
get_hw_addrs.o: get_hw_addrs.c hw_addrs.h
	${CC} ${CFLAGS} -c get_hw_addrs.c

clean:  
	rm ssrinath_arp arp.o ssrinath_tour tour.o get_hw_addrs.o
