; // https://artfulcode.wordpress.com/
; // https://github.com/cmovz/
; // License: use it as you wish, just keep this notice. No liability taken.

#include "randomctx.h"
#include "sha256.h"

void randomctx_init(RandomCtx* r, unsigned char const* fixed)
{
  for(int i = 0; i < sizeof r->fixed_bytes; ++i){
    r->fixed_bytes[i] = fixed[i];
  }
  
  for(int i = 0; i < sizeof r->state; ++i){
    r->state[i] = 0x00;
  }
}

void randomctx_update(RandomCtx* r)
{
  sha256((unsigned char const*)r, sizeof *r, r->state);
}
