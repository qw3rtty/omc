BOFNAME := amsi-killer
CC_x64 := x86_64-w64-mingw32-gcc
CC_x86 := i686-w64-mingw32-gcc

all:
	$(CC_x64) -c $(BOFNAME).c -o $(BOFNAME).x64.o -masm=intel -Wall -Werror -Os -nostdlib -fno-ident -fno-asynchronous-unwind-tables
	$(CC_x86) -c $(BOFNAME).c -o $(BOFNAME).x86.o -masm=intel -Wall -Werror -Os -nostdlib -fno-ident -fno-asynchronous-unwind-tables
