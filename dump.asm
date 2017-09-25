section .data
global _Exe
align 4
_Exe: incbin 'cipher_blob'
times 3 dd 0x00000000

section text progbits alloc exec write align=16 

times 0x100000 nop ; make enough space to load payload
