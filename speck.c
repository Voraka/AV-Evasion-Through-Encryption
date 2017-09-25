; // https://artfulcode.wordpress.com/
; // https://github.com/cmovz/
; // License: use it as you wish, just keep this notice. No liability taken.

#include "speck.h"

#define ROR(x,n) ((x >> n)|(x << (64-n)))
#define ROL(x,n) ((x << n)|(x >> (64-n)))

#define R(x,y,k){\
  x = ROR(x,8);\
  x += y;\
  x ^= k;\
  y = ROL(y,3);\
  y ^= x;\
}

#define RR(x,y,k){\
  y ^= x;\
  y = ROR(y,3);\
  x ^= k;\
  x -= y;\
  x = ROL(x,8);\
}

// convert big-endian bytes to u64
static inline void _bytes_to_u64(u64* dest, void const* bytes)
{
  unsigned char const* s = bytes;

  *dest = 0;
  for(int i = 0; i < 8; ++i){
    *dest |= (u64)s[i] << (56 - i * 8);
  }
}

// convert u64 to big-endian bytes
static inline void _u64_to_bytes(void* dest, u64 const* src)
{
  unsigned char* d = dest;
  
  for(int i = 0; i < 8; ++i){
    d[i] = *src >> (56 - i * 8);
  }
}

void speck_init(Speck* s, void const* key)
{
  u64 k1;
  u64 k0;
  
  _bytes_to_u64(&k1, key);
  _bytes_to_u64(&k0, (char*)key + 8);
  
  s->roundkeys[0] = k0;
  for(int i = 0; i < ROUNDS - 1; ++i){
    R(k1, k0, i);
    s->roundkeys[i+1] = k0;
  }
}

void speck_encrypt(Speck const* s, void* buffer)
{
  u64 a;
  u64 b;
  
  _bytes_to_u64(&a, buffer);
  _bytes_to_u64(&b, (char*)buffer + 8);

  for(int i = 0; i < ROUNDS; ++i){
    R(a, b, s->roundkeys[i]);
  }
  
  _u64_to_bytes(buffer, &a);
  _u64_to_bytes((char*)buffer + 8, &b);
}

void speck_decrypt(Speck const* s, void* buffer)
{
  u64 a;
  u64 b;
  
  _bytes_to_u64(&a, buffer);
  _bytes_to_u64(&b, (char*)buffer + 8);

  for(int i = ROUNDS - 1; i >= 0; --i){
    RR(a, b, s->roundkeys[i]);
  }
  
  _u64_to_bytes(buffer, &a);
  _u64_to_bytes((char*)buffer + 8, &b);
}
