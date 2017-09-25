#ifndef SPECK_H
#define SPECK_H

#include <stdint.h>

#define ROUNDS 32
typedef uint64_t u64;

typedef struct {
  u64 roundkeys[ROUNDS];
} Speck;

void speck_init(Speck* s, void const* key);
void speck_encrypt(Speck const* s, void* buffer);
void speck_decrypt(Speck const* s, void* buffer);

#endif
