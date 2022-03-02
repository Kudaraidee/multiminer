#ifndef HASH0X10_GATE_H__
#define HASH0X10_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
/*
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define 0X10_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define 0X10_4WAY 1
#endif
*/
bool register_0x10_algo( algo_gate_t* gate );
#if defined(HSAH0X10_8WAY)

void hash0x10_8way_hash( void *state, const void *input );
int scanhash_0x10_8way( sint thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done);
void init_0x10_8way_ctx();

#elif defined(HASH0X10_4WAY)

void hash0x10_4way_hash( void *state, const void *input );
int scanhash_0x10_4way( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done );
void init_0x10_4way_ctx();

#else 

void hash0x10( void *state, const void *input );
int scanhash_0x10(int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done);
void init_0x10_ctx();

#endif

#endif

