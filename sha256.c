; // https://artfulcode.wordpress.com/
; // https://github.com/cmovz/
; // License: use it as you wish, just keep this notice. No liability taken.

/*
    These functions do not properly clean the stack, which is ok for my
    purposes, but unacceptable for most cryptographic operations. They are also
    not optimized.
*/

#include "sha256.h"

#define ROR(x,n) ((x >> n)|(x << (32-n)))

static u32 const k[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,
  0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,
  0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,
  0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,
  0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
  0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,
  0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,
  0xc67178f2
};

/*
  SHA-256 compression function
*/
static void _sha256_main(u32* hs, void const* block)
{
  u32 w[64];
  
  // copy big-endian block
  unsigned char const* src = block;
  for(int i = 0; i < 64; ++i){
    w[i] = (src[0] << 24) | (src[1] << 16) | (src[2] << 8) | src[3];
    src += 4;
  }
  
  for(int i = 16; i < 64; ++i){
    u32 s0 = ROR(w[i-15],7) ^ ROR(w[i-15],18) ^ (w[i-15] >> 3);
    u32 s1 = ROR(w[i-2],17) ^ ROR(w[i-2],19) ^ (w[i-2] >> 10);
    w[i] = w[i-16] + s0 + w[i-7] + s1;
  }
  
  // working variables
  u32 a = hs[0];
  u32 b = hs[1];
  u32 c = hs[2];
  u32 d = hs[3];
  u32 e = hs[4];
  u32 f = hs[5];
  u32 g = hs[6];
  u32 h = hs[7];
  
  for(int i = 0; i < 64; ++i){
    u32 S1 = ROR(e,6) ^ ROR(e,11) ^ ROR(e,25);
    u32 ch = (e & f) ^ ((~e) & g);
    u32 temp1 = h + S1 + ch + k[i] + w[i];
    u32 S0 = ROR(a,2) ^ ROR(a,13) ^ ROR(a,22);
    u32 maj = (a & b) ^ (a & c) ^ (b & c);  
    u32 temp2 = S0 + maj;
    
    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }
  
  hs[0] += a;
  hs[1] += b;
  hs[2] += c;
  hs[3] += d;
  hs[4] += e;
  hs[5] += f;
  hs[6] += g;
  hs[7] += h;
}

/*
  sha256() performs the mathematical operations described by the SHA-256 
  algorithm on a given message "m" with length "m_size" and saves the message 
  digest on "md", which must be at least 256-bit long. It's ok for "m" and "md"
  to overlap partially or entirely.
*/
void sha256(unsigned char const* m, u64 m_size, unsigned char* md)
{
  u32 hs[8] = {
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,
    0x1f83d9ab,0x5be0cd19
  };
  
  size_t chunks = m_size >> 6;
  while(chunks){
    _sha256_main(hs, m);
    m += 64;
    --chunks;
  }
  
  // now handle last chunk or 2 by appending bit '1' and '0' bits, big-endian
  unsigned char last_chunk[128];
  int rem = m_size & 63;
  int total_size = (rem + 1 + 8 + 63) & ~63; // either 64 or 128
  u64 L = m_size << 3; // bit length
  
  for(int i = 0; i < rem; ++i){
    last_chunk[i] = m[i];
  }
  
  last_chunk[rem] = 0x80;
  
  // append '0' bits
  for(int i = rem + 1; i < total_size - 8; ++i){
    last_chunk[i] = 0x00;
  }
  
  // append big-endian L
  for(int i = 8; i > 0; --i){
    last_chunk[total_size - i] = L >> (i * 8 - 8);
  }
  
  _sha256_main(hs, last_chunk);
  
  if(total_size == 128){
    _sha256_main(hs, last_chunk + 64);
  }
  
  // produce message digest
  for(int i = 0; i < 8; ++i){
    md[i * 4    ] = hs[i] >> 24;
    md[i * 4 + 1] = hs[i] >> 16;
    md[i * 4 + 2] = hs[i] >>  8;
    md[i * 4 + 3] = hs[i]      ;
  }
}
