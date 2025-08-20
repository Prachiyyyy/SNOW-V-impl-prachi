#ifndef SNOWV_H
#define SNOWV_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

// SNOW-V 32-bit structure
struct SnowV32
{
    u16 A[16], B[16]; // LFSR
    u32 R1[4], R2[4], R3[4]; // FSM
    
    void aes_enc_round(u32 * result, u32 * state, u32 * roundKey);
    u16 mul_x(u16 v, u16 c);
    u16 mul_x_inv(u16 v, u16 d);
    void permute_sigma(u32 * state);
    void fsm_update(void);
    void lfsr_update(void);
    void keystream(u8 * z);
    void keyiv_setup(u8 * key, u8 * iv, int is_aead_mode);
};

// AEAD functions
void snowv_gcm_encrypt(u8 * A, u8 * ciphertext, u8 * plaintext, u64 plaintext_sz,
                       u8 * aad, u64 aad_sz, u8 * key32, u8 * iv16);
void snowv_gcm_decrypt(u8 * A, u8 * ciphertext, u8 * plaintext, u64 ciphertext_sz,
                       u8 * aad, u64 aad_sz, u8 * key32, u8 * iv16);


#endif 
