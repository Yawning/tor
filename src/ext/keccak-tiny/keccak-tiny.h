#ifndef KECCAK_TINY_H
#define KECCAK_TINY_H

#include <stddef.h>
#include "torint.h"

#define KECCAK_MAX_RATE 200

#define KECCAK_XOF_DELIM  0x1f
#define KECCAK_HASH_DELIM 0x06

#define KECCAK_TARGET_TO_RATE(bits) (KECCAK_MAX_RATE - (bits / 4))

typedef struct keccak_state {
  uint8_t a[KECCAK_MAX_RATE];
  size_t rate;
  uint8_t delim;

  uint8_t block[KECCAK_MAX_RATE];
  size_t offset;

  uint8_t finalized : 1;
} keccak_state;

int keccak_init(keccak_state *s, size_t rate, uint8_t delim);
void keccak_clone(keccak_state *out, const keccak_state *in);
int keccak_update(keccak_state *s, const uint8_t *buf, size_t len);
int keccak_finalize(keccak_state *s);
int keccak_squeeze(keccak_state *s, uint8_t *out, size_t outlen);
void keccak_cleanse(keccak_state *s);

#define decshake(bits) \
  int shake##bits(uint8_t*, size_t, const uint8_t*, size_t);

#define decsha3(bits) \
  int sha3_##bits(uint8_t*, size_t, const uint8_t*, size_t);

decshake(128)
decshake(256)
decsha3(224)
decsha3(256)
decsha3(384)
decsha3(512)
#endif
