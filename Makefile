CONFIG_MODULE_SIG=n
CONFIG_MODULE_SIG_ALL=n

obj-m = holdup_main.o 
holdup_main-objs := mmu.o dma.o holdUp.o asm_implementation.o monitor.o

KVERSION = $(shell uname -r)

%.o: %.asm
	nasm -f elf64 -o $@ $^

all:
	python make_symtable.py
	make -C /lib/modules/$(KVERSION)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(shell pwd) clean

