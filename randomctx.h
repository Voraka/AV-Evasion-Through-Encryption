#ifndef RANDOMCTX_H
#define RANDOMCTX_H

typedef struct {
  unsigned char fixed_bytes[16];
  unsigned char state[32];
} RandomCtx;

void randomctx_init(RandomCtx* r, unsigned char const* fixed);
void randomctx_update(RandomCtx* r);
void compute_key(unsigned char* dest128, unsigned char const* seed128,
                 unsigned int n);

#endif
