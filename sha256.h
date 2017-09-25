#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;

void sha256(unsigned char const* m, u64 m_size, unsigned char* md);

#endif
