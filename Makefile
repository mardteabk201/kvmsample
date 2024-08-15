all: kvmsample kernel_hyp test.bin test2.bin

kernel_hyp: kernel_hyp.o
	gcc kernel_hyp.c -o kernel_hyp -Wall

kvmsample: main.o
	gcc main.c -o kvmsample -lpthread -Wall

test.bin: test.o
	ld -m elf_i386 --oformat binary -N -e _start -Ttext 0x10000 -o test.bin test.o

test.o: test.S
	as -32 test.S -o test.o

test2.bin: test2.o
	ld -m elf_i386 --oformat binary -N -e _start -Ttext 0x10000 -o test2.bin test2.o

test2.o: test2.S
	as -32 test2.S -o test2.o

clean:
	-rm -rf *.o *.bin kvmsample kernel_hyp
