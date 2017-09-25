app:
	nasm -felf32 dump.asm -o dump.o
	i686-w64-mingw32-gcc -O2 -nostdlib -c *.c
	i686-w64-mingw32-ld -e _load -T linker_script -s -o a.exe *.o -lkernel32 -luser32

encryptor:
	gcc -O3 -o encryptor encryptor.c randomctx.c speck.c
