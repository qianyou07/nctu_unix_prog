all:libmini.so start.o

libmini64.o:libmini64.asm
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC libmini64.asm -o libmini64.o

libmini.o:libmini.c
	gcc -c -g -Wall -fno-stack-protector -fPIC -nostdlib libmini.c

libmini.so:libmini.o libmini64.o
	ld -shared -o libmini.so libmini64.o libmini.o

start.o:start.asm
	yasm -f elf64 -DYASM -D__x86_64__ -DPIC start.asm -o start.o

clean:
	rm libmini64.o
	rm libmini.o
	rm libmini.so
	rm start.o

alarm1:alarm1.c
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm1 alarm1.o start.o -L. -L.. -lmini
	rm alarm1.o

alarm2:alarm2.c
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm2.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm2 alarm2.o start.o -L. -L.. -lmini
	rm alarm2.o

alarm3:alarm3.c
	gcc -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI alarm3.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o alarm3 alarm3.o start.o -L. -L.. -lmini
	rm alarm3.o

jmp1:jmp1.c
	gcc -o jmp1.o -c -g -Wall -fno-stack-protector -nostdlib -I. -I.. -DUSEMINI jmp1.c
	ld -m elf_x86_64 --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o jmp1 jmp1.o start.o -L. -L.. -lmini