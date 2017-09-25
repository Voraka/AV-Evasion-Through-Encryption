; // https://artfulcode.wordpress.com/
; // https://github.com/cmovz/
; // License: use it as you wish, just keep this notice. No liability taken.

#include "speck.h"
#include "randomctx.h"
#include <windows.h>

#define ITERATIONS 41296896 // set ITERATIONS from encryptor
#define CIPHER_SIZE 670208

typedef struct {
  DWORD a;
  DWORD b;
  DWORD c;
  DWORD d;
} Counter;

BOOL fill_idata(DWORD* idata, DWORD base);
extern DWORD Exe[];

// Fill with seed from encryptor
unsigned char const seed[] = {
  0xe7,0x66,0x35,0x97,0x40,0x4a,0x0b,0x19,
  0xec,0x69,0x0a,0x5d,0xe3,0x4d,0x8f,0xca,
};

void copy(void* dest, void const* src, unsigned long n)
{
  char* d = dest;
  char const* s = src;
  
  while(n--){
    *d++ = *s++;
  }
}

void compute_key(unsigned char* dest128, unsigned char const* seed128,
                 unsigned int n)
{
  RandomCtx ctx;
  
  randomctx_init(&ctx, seed128);
  
  for(unsigned int i = 0; i < n; ++i){
    randomctx_update(&ctx);
  }
  
  copy(dest128, ctx.state, 16);
}

int load(void)
{
  // decrypt exe
  unsigned char key[16];
  compute_key(key, seed, ITERATIONS);
  
  Speck speck;
  speck_init(&speck, key);
  
  Counter plain = {0,0,0,0};
  for(int i = 0; i < CIPHER_SIZE; i += 16){
    Counter cipher = plain;
    speck_encrypt(&speck, &cipher);
    
    Exe[i/4 + 0] ^= cipher.a;
    Exe[i/4 + 1] ^= cipher.b;
    Exe[i/4 + 2] ^= cipher.c;
    Exe[i/4 + 3] ^= cipher.d;
    
    ++plain.a;
  }

  // rebuild our hello world exe
  // .text
  copy((void*)0x401000, (char*)Exe + 0x400, 0xba04);

  // .rdata
  copy((void*)0x40d000, (char*)Exe + 0xc000, 0x16a4);
  
  // .data
  copy((void*)0x40f000, (char*)Exe + 0xd800, 0x87b5);
  
  // .rsrc
  copy((void*)0x418000, (char*)Exe + 0x16000, 0x8d920);
  
  // fill import table
  if(!fill_idata((DWORD*)0x40d000, 0x400000)){
    MessageBox(NULL, "Failed to fill imports", "Error", MB_OK);
    ExitProcess(-1); 
  }
  
  // call there
  ((void(*)(void))0x401e9a)();
  
  MessageBox(NULL, "Returned", "Status", MB_OK);
  ExitProcess(0);
}
