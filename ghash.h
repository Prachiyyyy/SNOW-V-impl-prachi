#ifndef GHASH_H
#define GHASH_H

#include <stdint.h>

typedef uint8_t u8;
typedef uint64_t u64;

// GHASH functions
void ghash_mult(u8 * out, const u8 * x, const u8 * y);
void ghash_update(const u8 * H, u8 * A, const u8 * data, long long length);
void ghash_final(const u8 * H, u8 * A, u64 lenAAD, u64 lenC, const u8 * maskingBlock);


#endif 
