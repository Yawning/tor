/* Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define KEYPIN_PRIVATE

#include "orconfig.h"
#include "compat.h"
#include "crypto.h"
#include "di_ops.h"
#include "ht.h"
#include "keypin.h"
#include "siphash.h"
#include "torint.h"
#include "torlog.h"
#include "util.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef _WIN32
#include <io.h>
#endif

/**
 * @file keypin.c
 * @brief Key-pinning for RSA and Ed25519 identity keys at directory
 *  authorities.
 *
 * This module implements a key-pinning mechanism to ensure that it's safe
 * to use RSA keys as identitifers even as we migrate to Ed25519 keys.  It
 * remembers, for every Ed25519 key we've seen, what the associated Ed25519
 * key is.  This way, if we see a different Ed25519 key with that RSA key,
 * we'll know that there's a mismatch.
 *
 * We persist these entries to disk using a simple format, where each line
 * has a base64-encoded RSA SHA1 hash, then a base64-endoded Ed25519 key.
 * Empty lines, misformed lines, and lines beginning with # are
 * ignored. Lines beginning with @ are reserved for future extensions.
 */

static int keypin_journal_append_entry(const uint8_t *rsa_id_digest,
                                       const uint8_t *ed25519_id_key);
static int keypin_check_and_add_impl(const uint8_t *rsa_id_digest,
                                     const uint8_t *ed25519_id_key,
                                     int do_not_add);

static HT_HEAD(rsamap, keypin_ent_st) the_rsa_map = HT_INITIALIZER();
static HT_HEAD(edmap, keypin_ent_st) the_ed_map = HT_INITIALIZER();

/** Hashtable helper: compare two keypin table entries and return true iff
 * they have the same RSA key IDs. */
static INLINE int
keypin_ents_eq_rsa(const keypin_ent_t *a, const keypin_ent_t *b)
{
  return tor_memeq(a->rsa_id, b->rsa_id, sizeof(a->rsa_id));
}

/** Hashtable helper: hash a keypin table entries based on its RSA key ID */
static INLINE unsigned
keypin_ent_hash_rsa(const keypin_ent_t *a)
{
return (unsigned) siphash24g(a->rsa_id, sizeof(a->rsa_id));
}

/** Hashtable helper: compare two keypin table entries and return true iff
 * they have the same ed25519 keys */
static INLINE int
keypin_ents_eq_ed(const keypin_ent_t *a, const keypin_ent_t *b)
{
  return tor_memeq(a->ed25519_key, b->ed25519_key, sizeof(a->ed25519_key));
}

/** Hashtable helper: hash a keypin table entries based on its ed25519 key */
static INLINE unsigned
keypin_ent_hash_ed(const keypin_ent_t *a)
{
return (unsigned) siphash24g(a->ed25519_key, sizeof(a->ed25519_key));
}

HT_PROTOTYPE(rsamap, keypin_ent_st, rsamap_node, keypin_ent_hash_rsa,
               keypin_ents_eq_rsa);
HT_GENERATE2(rsamap, keypin_ent_st, rsamap_node, keypin_ent_hash_rsa,
               keypin_ents_eq_rsa, 0.6, tor_reallocarray, tor_free_);

HT_PROTOTYPE(edmap, keypin_ent_st, edmap_node, keypin_ent_hash_ed,
               keypin_ents_eq_ed);
HT_GENERATE2(edmap, keypin_ent_st, edmap_node, keypin_ent_hash_ed,
               keypin_ents_eq_ed, 0.6, tor_reallocarray, tor_free_);

/**
 * Check whether we already have an entry in the key pinning table for a
 * router with RSA ID digest <b>rsa_id_digest</b> or for ed25519 key
 * <b>ed25519_id_key</b>.  If we have an entry that matches both keys,
 * return KEYPIN_FOUND. If we find an entry that matches one key but
 * not the other, return KEYPIN_MISMATCH.  If we have no entry for either
 * key, add such an entry to the table and return KEYPIN_ADDED.
 */
int
keypin_check_and_add(const uint8_t *rsa_id_digest,
                     const uint8_t *ed25519_id_key)
{
  return keypin_check_and_add_impl(rsa_id_digest, ed25519_id_key, 0);
}

/**
 * As keypin_check_and_add, but do not add.  Return KEYPIN_NOT_FOUND if
 * we would add.
 */
int
keypin_check(const uint8_t *rsa_id_digest,
             const uint8_t *ed25519_id_key)
{
  return keypin_check_and_add_impl(rsa_id_digest, ed25519_id_key, 1);
}

/**
 * Helper: implements keypin_check and keypin_check_and_add.
 */
static int
keypin_check_and_add_impl(const uint8_t *rsa_id_digest,
                          const uint8_t *ed25519_id_key,
                          int do_not_add)
{
  keypin_ent_t search, *ent;
  memset(&search, 0, sizeof(search));
  memcpy(search.rsa_id, rsa_id_digest, sizeof(search.rsa_id));
  memcpy(search.ed25519_key, ed25519_id_key, sizeof(search.ed25519_key));

  /* Search by RSA key digest first */
  ent = HT_FIND(rsamap, &the_rsa_map, &search);
  if (ent) {
    tor_assert(fast_memeq(ent->rsa_id, rsa_id_digest, sizeof(ent->rsa_id)));
    if (tor_memeq(ent->ed25519_key, ed25519_id_key,sizeof(ent->ed25519_key))) {
      return KEYPIN_FOUND; /* Match on both keys. Great. */
    } else {
      return KEYPIN_MISMATCH; /* Found RSA with different Ed key */
    }
  }

  /* See if we know a different RSA key for this ed key */
  ent = HT_FIND(edmap, &the_ed_map, &search);
  if (ent) {
    /* If we got here, then the ed key matches and the RSA doesn't */
    tor_assert(fast_memeq(ent->ed25519_key, ed25519_id_key,
                          sizeof(ent->ed25519_key)));
    tor_assert(fast_memneq(ent->rsa_id, rsa_id_digest, sizeof(ent->rsa_id)));
    return KEYPIN_MISMATCH;
  }

  /* Okay, this one is new to us. */
  if (do_not_add)
    return KEYPIN_NOT_FOUND;

  ent = tor_memdup(&search, sizeof(search));
  keypin_add_entry_to_map(ent);
  keypin_journal_append_entry(rsa_id_digest, ed25519_id_key);
  return KEYPIN_ADDED;
}

/**
 * Helper: add <b>ent</b> to the hash tables.
 */
MOCK_IMPL(STATIC void,
keypin_add_entry_to_map, (keypin_ent_t *ent))
{
  HT_INSERT(rsamap, &the_rsa_map, ent);
  HT_INSERT(edmap, &the_ed_map, ent);
}

/**
 * Check whether we already have an entry in the key pinning table for a
 * router with RSA ID digest <b>rsa_id_digest</b>.  If we have no such entry,
 * return KEYPIN_NOT_FOUND.  If we find an entry that matches the RSA key but
 * which has an ed25519 key, return KEYPIN_MISMATCH.
 */
int
keypin_check_lone_rsa(const uint8_t *rsa_id_digest)
{
  keypin_ent_t search, *ent;
  memset(&search, 0, sizeof(search));
  memcpy(search.rsa_id, rsa_id_digest, sizeof(search.rsa_id));

  /* Search by RSA key digest first */
  ent = HT_FIND(rsamap, &the_rsa_map, &search);
  if (ent) {
    return KEYPIN_MISMATCH;
  } else {
    return KEYPIN_NOT_FOUND;
  }
}

/** Open fd to the keypinning journal file. */
static int keypin_journal_fd = -1;

/** Open the key-pinning journal to append to <b>fname</b>.  Return 0 on
 * success, -1 on failure. */
int
keypin_open_journal(const char *fname)
{
  /* O_SYNC ??*/
  int fd = tor_open_cloexec(fname, O_WRONLY|O_CREAT, 0600);
  if (fd < 0)
    goto err;

  if (tor_fd_seekend(fd) < 0)
    goto err;

  /* Add a newline in case the last line was only partially written */
  if (write(fd, "\n", 1) < 1)
    goto err;

  /* Add something about when we opened this file. */
  char buf[80];
  char tbuf[ISO_TIME_LEN+1];
  format_iso_time(tbuf, approx_time());
  tor_snprintf(buf, sizeof(buf), "@opened-at %s\n", tbuf);
  if (write_all(fd, buf, strlen(buf), 0) < 0)
    goto err;

  keypin_journal_fd = fd;
  return 0;
 err:
  if (fd >= 0)
    close(fd);
  return -1;
}

/** Close the keypinning journal file. */
int
keypin_close_journal(void)
{
  if (keypin_journal_fd >= 0)
    close(keypin_journal_fd);
  keypin_journal_fd = -1;
  return 0;
}

/** Length of a keypinning journal line, including terminating newline. */
#define JOURNAL_LINE_LEN (BASE64_DIGEST_LEN + BASE64_DIGEST256_LEN + 2)

/** Add an entry to the keypinning journal to map <b>rsa_id_digest</b> and
 * <b>ed25519_id_key</b>. */
static int
keypin_journal_append_entry(const uint8_t *rsa_id_digest,
                            const uint8_t *ed25519_id_key)
{
  if (keypin_journal_fd == -1)
    return -1;
  char line[JOURNAL_LINE_LEN];
  digest_to_base64(line, (const char*)rsa_id_digest);
  line[BASE64_DIGEST_LEN] = ' ';
  digest256_to_base64(line + BASE64_DIGEST_LEN + 1,
                      (const char*)ed25519_id_key);
  line[BASE64_DIGEST_LEN+1+BASE64_DIGEST256_LEN] = '\n';

  if (write_all(keypin_journal_fd, line, JOURNAL_LINE_LEN, 0)<0) {
    log_warn(LD_DIRSERV, "Error while adding a line to the key-pinning "
             "journal: %s", strerror(errno));
    keypin_close_journal();
    return -1;
  }

  return 0;
}

/** Load a journal from the <b>size</b>-byte region at <b>data</b>.  Return 0
 * on success, -1 on failure. */
STATIC int
keypin_load_journal_impl(const char *data, size_t size)
{
  const char *start = data, *end = data + size, *next;

  int n_corrupt_lines = 0;
  int n_entries = 0;
  int n_duplicates = 0;
  int n_conflicts = 0;

  for (const char *cp = start; cp < end; cp = next) {
    const char *eol = memchr(cp, '\n', end-cp);
    const char *eos = eol ? eol : end;
    const size_t len = eos - cp;

    next = eol ? eol + 1 : end;

    if (len == 0) {
      continue;
    }

    if (*cp == '@') {
      /* Lines that start with @ are reserved. Ignore for now. */
      continue;
    }
    if (*cp == '#') {
      /* Lines that start with # are comments. */
      continue;
    }

    /* Is it the right length?  (The -1 here is for the newline.) */
    if (len != JOURNAL_LINE_LEN - 1) {
      /* Lines with a bad length are corrupt unless they are empty.
       * Ignore them either way */
      for (const char *s = cp; s < eos; ++s) {
        if (! TOR_ISSPACE(*s)) {
          ++n_corrupt_lines;
          break;
        }
      }
      continue;
    }

    keypin_ent_t *ent = keypin_parse_journal_line(cp);

    if (ent == NULL) {
      ++n_corrupt_lines;
      continue;
    }

    const keypin_ent_t *ent2;
    if ((ent2 = HT_FIND(rsamap, &the_rsa_map, ent))) {
      if (fast_memeq(ent2->ed25519_key, ent->ed25519_key, DIGEST256_LEN)) {
        ++n_duplicates;
      } else {
        ++n_conflicts;
      }
      tor_free(ent);
      continue;
    } else if (HT_FIND(edmap, &the_ed_map, ent)) {
      tor_free(ent);
      ++n_conflicts;
      continue;
    }

    keypin_add_entry_to_map(ent);
    ++n_entries;
  }

  int severity = (n_corrupt_lines || n_duplicates) ? LOG_WARN : LOG_INFO;
  tor_log(severity, LD_DIRSERV,
          "Loaded %d entries from keypin journal. "
          "Found %d corrupt lines, %d duplicates, and %d conflicts.",
          n_entries, n_corrupt_lines, n_duplicates, n_conflicts);

  return 0;
}

/**
 * Load a journal from the file called <b>fname</b>. Return 0 on success,
 * -1 on failure.
 */
int
keypin_load_journal(const char *fname)
{
  tor_mmap_t *map = tor_mmap_file(fname);
  if (!map) {
    if (errno == ENOENT)
      return 0;
    else
      return -1;
  }
  int r = keypin_load_journal_impl(map->data, map->size);
  tor_munmap_file(map);
  return r;
}

/** Parse a single keypinning journal line entry from <b>cp</b>.  The input
 * does not need to be NUL-terminated, but it <em>does</em> need to have
 * KEYPIN_JOURNAL_LINE_LEN -1 bytes available to read.  Return a new entry
 * on success, and NULL on failure.
 */
STATIC keypin_ent_t *
keypin_parse_journal_line(const char *cp)
{
  /* XXXX assumes !USE_OPENSSL_BASE64 */
  keypin_ent_t *ent = tor_malloc_zero(sizeof(keypin_ent_t));

  if (base64_decode((char*)ent->rsa_id, sizeof(ent->rsa_id),
             cp, BASE64_DIGEST_LEN) != DIGEST_LEN ||
      cp[BASE64_DIGEST_LEN] != ' ' ||
      base64_decode((char*)ent->ed25519_key, sizeof(ent->ed25519_key),
             cp+BASE64_DIGEST_LEN+1, BASE64_DIGEST256_LEN) != DIGEST256_LEN) {
    tor_free(ent);
    return NULL;
  } else {
    return ent;
  }
}

/** Remove all entries from the keypinning table.*/
void
keypin_clear(void)
{
  int bad_entries = 0;
  {
    keypin_ent_t **ent, **next, *this;
    for (ent = HT_START(rsamap, &the_rsa_map); ent != NULL; ent = next) {
      this = *ent;
      next = HT_NEXT_RMV(rsamap, &the_rsa_map, ent);

      keypin_ent_t *other_ent = HT_REMOVE(edmap, &the_ed_map, this);
      bad_entries += (other_ent != this);

      tor_free(this);
    }
  }
  bad_entries += HT_SIZE(&the_ed_map);

  HT_CLEAR(edmap,&the_ed_map);
  HT_CLEAR(rsamap,&the_rsa_map);

  if (bad_entries) {
    log_warn(LD_BUG, "Found %d discrepencies in the the keypin database.",
             bad_entries);
  }
}
