/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */
#include "keccak-tiny.h"

#include "torint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
static const uint8_t rho[24] = \
  { 1,  3,   6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
  {10,  7, 11, 17, 18, 3,
    5, 16,  8, 21, 24, 4,
   15, 23, 19, 13, 12, 2,
   20, 14, 22,  9, 6,  1};
static const uint64_t RC[24] = \
  {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;

  for (int i = 0; i < 24; i++) {
    // Theta
    FOR5(x, 1,
         b[x] = 0;
         FOR5(y, 5,
              b[x] ^= a[x + y]; ))
    FOR5(x, 1,
         FOR5(y, 5,
              a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
    // Rho and pi
    t = a[1];
    x = 0;
    REPEAT24(b[0] = a[pi[x]];
             a[pi[x]] = rol(t, rho[x]);
             t = b[0];
             x++; )
    // Chi
    FOR5(y,
       5,
       FOR5(x, 1,
            b[x] = a[y + x];)
       FOR5(x, 1,
            a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
    // Iota
    a[0] ^= RC[i];
  }
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
  _(for (size_t i = 0; i < L; i += ST) { S; })
#define mkapply_ds(NAME, S)                                          \
  static inline void NAME(uint8_t* dst,                              \
                          const uint8_t* src,                        \
                          size_t len) {                              \
    FOR(i, 1, len, S);                                               \
  }
#define mkapply_sd(NAME, S)                                          \
  static inline void NAME(const uint8_t* src,                        \
                          uint8_t* dst,                              \
                          size_t len) {                              \
    FOR(i, 1, len, S);                                               \
  }

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen KECCAK_MAX_RATE

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
  while (L >= s->rate) {  \
    F(s->a, I, s->rate);  \
    P(s->a);              \
    I += s->rate;         \
    L -= s->rate;         \
  }

int
keccak_init(keccak_state *s, size_t rate, uint8_t delim)
{
  if (rate > sizeof(s->a))
    return -1;

  keccak_cleanse(s);
  s->rate = rate;
  s->delim = delim;
  return 0;
}

void
keccak_clone(keccak_state *out, const keccak_state *in)
{
  memcpy(out, in, sizeof(*out));
}

static inline void
keccak_absorb_blocks(keccak_state *s, const uint8_t *b, size_t nr_blocks)
{
  // Absorb input.
  size_t blen = nr_blocks * s->rate;
  foldP(b, blen, xorin);
}

int
keccak_update(keccak_state *s, const uint8_t *buf, size_t len)
{
  if (s->finalized)
    return -1;
  if (buf == NULL) {
    if (len != 0)
      return -1;
    return 0;
  }

  size_t remaining = len;
  while (remaining > 0) {
    if (s->offset == 0) {
      const size_t blocks = remaining / s->rate;
      size_t direct_bytes = blocks * s->rate;
      if (direct_bytes > 0) {
        keccak_absorb_blocks(s, buf, blocks);
        remaining -= direct_bytes;
        buf += direct_bytes;
      }
    }

    const size_t buf_avail = s->rate - s->offset;
    const size_t buf_bytes = (buf_avail > remaining) ? remaining : buf_avail;
    if (buf_bytes > 0) {
      memcpy(&s->block[s->offset], buf, buf_bytes);
      s->offset += buf_bytes;
      remaining -= buf_bytes;
      buf += buf_bytes;
    }
    if (s->offset == s->rate) {
      keccak_absorb_blocks(s, s->block, 1);
      s->offset = 0;
    }
  }
  return 0;
}

int
keccak_finalize(keccak_state *s)
{
  if (s->finalized)
    return -1;

  s->finalized = 1;

  // Xor in the DS and pad frame.
  s->a[s->offset] ^= s->delim;
  s->a[s->rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(s->a, s->block, s->offset);

  memwipe(s->block, 0, sizeof(s->block));
  s->offset = s->rate;

  return 0;
}

static inline void
keccak_squeeze_blocks(keccak_state *s, uint8_t *b, size_t nr_blocks)
{
  for (size_t n = 0; n < nr_blocks; n++) {
    size_t tmp = s->rate;
    keccakf(s->a);
    setout(s->a, b, tmp);
    b += s->rate;
  }
}

int
keccak_squeeze(keccak_state *s, uint8_t *out, size_t outlen)
{
  if (!s->finalized)
    return -1;

  size_t remaining = outlen;
  while (remaining > 0) {
    if (s->offset == s->rate) {
      const size_t blocks = remaining / s->rate;
      const size_t direct_bytes = blocks * s->rate;
      if (blocks > 0) {
        keccak_squeeze_blocks(s, out, blocks);
        out += direct_bytes;
        remaining -= direct_bytes;
      }

      if (remaining > 0) {
        keccak_squeeze_blocks(s, s->block, 1);
        s->offset = 0;
      }
    }

    const size_t buf_bytes = s->rate - s->offset;
    const size_t indirect_bytes = (buf_bytes > remaining) ? remaining : buf_bytes;
    if (indirect_bytes > 0) {
      memcpy(out, &s->block[s->offset], indirect_bytes);
      out += indirect_bytes;
      s->offset += indirect_bytes;
      remaining -= indirect_bytes;
    }
  }
  return 0;
}

void
keccak_cleanse(keccak_state *s)
{
  memwipe(s, 0, sizeof(*s));
}

/** The sponge-based hash construction. **/
static inline int hash(uint8_t* out, size_t outlen,
                       const uint8_t* in, size_t inlen,
                       size_t rate, uint8_t delim) {
  if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
    return -1;
  }

  int ret = 0;
  keccak_state s;
  ret |= keccak_init(&s, rate, delim);
  ret |= keccak_update(&s, in, inlen);
  ret |= keccak_finalize(&s);
  ret |= keccak_squeeze(&s, out, outlen);
  keccak_cleanse(&s);
  return ret;
#if 0
  uint8_t a[Plen] = {0};
  // Absorb input.
  foldP(in, inlen, xorin);
  // Xor in the DS and pad frame.
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(a, in, inlen);
  // Apply P
  P(a);
  // Squeeze output.
  foldP(out, outlen, setout);
  setout(a, out, outlen);
  memset_s(a, 200, 0, 200);
  return 0;
#endif
}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
#define defshake(bits)                                            \
  int shake##bits(uint8_t* out, size_t outlen,                    \
                  const uint8_t* in, size_t inlen) {              \
    return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);  \
  }
#define defsha3(bits)                                             \
  int sha3_##bits(uint8_t* out, size_t outlen,                    \
                  const uint8_t* in, size_t inlen) {              \
    if (outlen > (bits/8)) {                                      \
      return -1;                                                  \
    }                                                             \
    return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x06);  \
  }

/*** FIPS202 SHAKE VOFs ***/
defshake(128)
defshake(256)

/*** FIPS202 SHA3 FOFs ***/
defsha3(224)
defsha3(256)
defsha3(384)
defsha3(512)
