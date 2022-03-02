#include "0x10-gate.h"

bool register_0x10_algo( algo_gate_t *gate )
{
/*#if defined (0X10_8WAY)
  init_0x10_8way_ctx();
  gate->scanhash  = (void*)&scanhash_0x10_8way;
  gate->hash      = (void*)&0x10_8way_hash;
#elif defined (0X10_4WAY)
  init_0x10_4way_ctx();
  gate->scanhash  = (void*)&scanhash_0x10_4way;
  gate->hash      = (void*)&0x10_4way_hash;
#else */
  init_0x10_ctx();
  gate->scanhash  = (void*)&scanhash_0x10;
  gate->hash      = (void*)&hash0x10;
//#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT ;
  return true;
};

