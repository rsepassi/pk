// Based on github.com/attractivechaos/klib
//
// The MIT License
//
// Copyright (c) 2008, 2009, 2011 by Attractive Chaos <attractor@live.co.uk>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include "list.h"
#include "stdtypes.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define __ac_flag(flag, i)     (*(i32*)(list_get(&flag, i >> 4)))
#define __ac_isempty(flag, i)  ((__ac_flag(flag, i) >> ((i & 0xfU) << 1)) & 2)
#define __ac_isdel(flag, i)    ((__ac_flag(flag, i) >> ((i & 0xfU) << 1)) & 1)
#define __ac_iseither(flag, i) ((__ac_flag(flag, i) >> ((i & 0xfU) << 1)) & 3)
#define __ac_set_isdel_false(flag, i)                                          \
  (__ac_flag(flag, i) &= ~(1ul << ((i & 0xfU) << 1)))
#define __ac_set_isempty_false(flag, i)                                        \
  (__ac_flag(flag, i) &= ~(i32)(2ul << ((i & 0xfU) << 1)))
#define __ac_set_isboth_false(flag, i)                                         \
  (__ac_flag(flag, i) &= ~(i32)(3ul << ((i & 0xfU) << 1)))
#define __ac_set_isdel_true(flag, i)                                           \
  (__ac_flag(flag, i) |= 1ul << ((i & 0xfU) << 1))
#define __ac_fsize(m) ((m) < 16 ? 1 : (m) >> 4)
#define kroundup32(x)                                                          \
  (--(x), (x) |= (x) >> 1, (x) |= (x) >> 2, (x) |= (x) >> 4, (x) |= (x) >> 8,  \
   (x) |= (x) >> 16, ++(x))

static const double __ac_HASH_UPPER = 0.77;

typedef i32 (*HashFunc)(void* key);
typedef bool (*HashEqFunc)(void* a, void* b);

typedef struct {
  i32        n_buckets;
  i32        size;
  i32        n_occupied;
  i32        upper_bound;
  List       keys;   // KeyT
  List       vals;   // ValT
  List       flags;  // i32
  Allocator  allocator;
  HashFunc   hashfn;
  HashEqFunc hasheq;
  bool       is_map;
} Hashmap;

typedef Hashmap Hashset;
typedef i32     HashmapIter;
typedef i32     HashsetIter;

static inline int hashmap_init(Hashmap* h, usize keysz, usize keyalign,
                               usize valsz, usize valalign, HashFunc hfn,
                               HashEqFunc heq, Allocator a) {
  *h = (Hashmap){0};
  if (list_init(&h->keys, keysz, keyalign, a, 0))
    return -1;
  if (list_init(&h->vals, valsz, valalign, a, 0))
    return -1;
  if (List_init(&h->flags, i32, a, 0))
    return -1;
  h->allocator = a;
  h->hashfn    = hfn;
  h->hasheq    = heq;
  h->is_map    = true;
  return 0;
}

static inline int hashset_init(Hashmap* h, usize keysz, usize keyalign,
                               HashFunc hfn, HashEqFunc heq, Allocator a) {
  *h = (Hashmap){0};
  if (list_init(&h->keys, keysz, keyalign, a, 0))
    return -1;
  if (List_init(&h->flags, i32, a, 0))
    return -1;
  h->allocator = a;
  h->hashfn    = hfn;
  h->hasheq    = heq;
  h->is_map    = false;
  return 0;
}

static inline void hashmap_deinit(Hashmap* h) {
  list_deinit(&h->keys);
  if (h->is_map)
    list_deinit(&h->vals);
  list_deinit(&h->flags);
}

static inline void hashmap_clear(Hashmap* h) {
  if (!h->flags.len)
    return;
  memset(h->flags.data.buf, 0xaa, h->flags.data.len);
  h->size       = 0;
  h->n_occupied = 0;
}

static inline HashmapIter hashmap_get(Hashmap* h, void* key) {
  if (!h->n_buckets)
    return 0;

  i32 mask = h->n_buckets - 1;
  i32 k    = h->hashfn(key);
  i32 i    = k & mask;
  i32 last = i;
  i32 step = 0;
  while (!__ac_isempty(h->flags, i) &&
         (__ac_isdel(h->flags, i) || !h->hasheq(list_get(&h->keys, i), key))) {
    i = (i + (++step)) & mask;
    if (i == last)
      return h->n_buckets;
  }
  return __ac_iseither(h->flags, i) ? h->n_buckets : i;
}

static inline void hashmap_del(Hashmap* h, HashmapIter it) {
  if (it != h->n_buckets && !__ac_iseither(h->flags, it)) {
    __ac_set_isdel_true(h->flags, it);
    --h->size;
  }
}

static inline int hashmap_resize(Hashmap* h, i32 new_n_buckets) {
  // This function uses 0.25*n_buckets bytes of working space instead of
  // [sizeof(key_t+val_t)+.25]*n_buckets.

  List new_flags;
  i32* new_flags_p = 0;
  if (List_init(&new_flags, i32, h->allocator, 0))
    return -1;
  i32 j = 1;
  {
    kroundup32(new_n_buckets);
    if (new_n_buckets < 4)
      new_n_buckets = 4;
    if (h->size >= (i32)(new_n_buckets * __ac_HASH_UPPER + 0.5)) {
      j = 0;  // requested size is too small
    } else {  // hash table size to be changed (shrink or expand); rehash
      if (list_addn(&new_flags, __ac_fsize(new_n_buckets),
                    (void**)&new_flags_p))
        return -1;
      memset(new_flags.data.buf, 0xaa, new_flags.data.len);
      if (h->n_buckets < new_n_buckets) {  // expand
        if (list_reserve(&h->keys, new_n_buckets)) {
          list_deinit(&new_flags);
          return -1;
        }
        h->keys.len = new_n_buckets;

        if (h->is_map) {
          if (list_reserve(&h->vals, new_n_buckets)) {
            list_deinit(&new_flags);
            return -1;
          }
          h->vals.len = new_n_buckets;
        }
      }  // otherwise shrink
    }
  }

  if (!j)
    return 0;

  // rehashing is needed
  for (j = 0; j != h->n_buckets; ++j) {
    if (__ac_iseither(h->flags, j) == 0) {
      u8 keybuf[h->keys.elsz];
      memcpy(keybuf, list_get(&h->keys, j), h->keys.elsz);
      u8  valbuf[h->vals.elsz];
      i32 new_mask = new_n_buckets - 1;
      if (h->is_map)
        memcpy(valbuf, list_get(&h->vals, j), h->vals.elsz);
      __ac_set_isdel_true(h->flags, j);
      while (1) {  // kick-out process; sort of like in Cuckoo hashing
        i32 k    = h->hashfn(keybuf);
        i32 i    = k & new_mask;
        i32 step = 0;
        while (!__ac_isempty(new_flags, i))
          i = (i + (++step)) & new_mask;
        __ac_set_isempty_false(new_flags, i);
        if (i < h->n_buckets && __ac_iseither(h->flags, i) == 0) {
          // kick out the existing element
          {
            u8 tmpbuf[h->keys.elsz];
            memcpy(tmpbuf, list_get(&h->keys, j), h->keys.elsz);
            list_set(&h->keys, i, keybuf);
            memcpy(keybuf, tmpbuf, h->keys.elsz);
          }
          if (h->is_map) {
            u8 tmpbuf[h->vals.elsz];
            memcpy(tmpbuf, list_get(&h->vals, j), h->vals.elsz);
            list_set(&h->vals, i, valbuf);
            memcpy(valbuf, tmpbuf, h->vals.elsz);
          }
          // mark it as deleted in the old hash table
          __ac_set_isdel_true(h->flags, i);
        } else {
          // write the element and jump out of the loop
          list_set(&h->keys, i, keybuf);
          if (h->is_map)
            list_set(&h->vals, i, valbuf);
          break;
        }
      }
    }
  }

  if (h->n_buckets > new_n_buckets) {  // shrink the hash table
    h->keys.len = new_n_buckets;
    if (h->is_map)
      h->vals.len = new_n_buckets;
  }

  list_deinit(&h->flags);  // free the working space
  h->flags       = new_flags;
  h->n_buckets   = new_n_buckets;
  h->n_occupied  = h->size;
  h->upper_bound = (i32)(h->n_buckets * __ac_HASH_UPPER + 0.5);

  return 0;
}

typedef enum {
  HashmapStatus_OK,
  HashmapStatus_ERR,
  HashmapStatus_New,
  HashmapStatus_Present,
  HashmapStatus_Deleted,
} HashmapStatus;

static inline HashmapIter hashmap_put(Hashmap* h, void* key,
                                      HashmapStatus* ret) {
  if (h->n_occupied >= h->upper_bound) {
    // update the hash table
    if (h->n_buckets > (h->size << 1)) {
      if (hashmap_resize(h, h->n_buckets - 1) < 0) {
        // clear "deleted" elements
        *ret = HashmapStatus_ERR;
        return h->n_buckets;
      }
    } else if (hashmap_resize(h, h->n_buckets + 1) < 0) {
      // expand the hash table
      *ret = HashmapStatus_ERR;
      return h->n_buckets;
    }
  }
  // TODO: implement automatically shrinking

  i32 x = h->n_buckets;
  {
    i32 mask = h->n_buckets - 1;
    i32 site = h->n_buckets;
    i32 k    = h->hashfn(key);
    i32 i    = k & mask;
    i32 step = 0;

    if (__ac_isempty(h->flags, i))
      x = i;  // for speed up
    else {
      i32 last = i;
      while (
          !__ac_isempty(h->flags, i) &&
          (__ac_isdel(h->flags, i) || !h->hasheq(list_get(&h->keys, i), key))) {
        if (__ac_isdel(h->flags, i))
          site = i;
        i = (i + (++step)) & mask;
        if (i == last) {
          x = site;
          break;
        }
      }
      if (x == h->n_buckets) {
        if (__ac_isempty(h->flags, i) && site != h->n_buckets)
          x = site;
        else
          x = i;
      }
    }
  }
  if (__ac_isempty(h->flags, x)) {
    // not present at all
    list_set(&h->keys, x, key);
    __ac_set_isboth_false(h->flags, x);
    ++h->size;
    ++h->n_occupied;
    *ret = HashmapStatus_New;
  } else if (__ac_isdel(h->flags, x)) {
    // deleted
    list_set(&h->keys, x, key);
    __ac_set_isboth_false(h->flags, x);
    ++h->size;
    *ret = HashmapStatus_Deleted;
  } else
    // Don't touch h->keys[x] if present and not deleted
    *ret = HashmapStatus_Present;
  return x;
}

#define hashmap_exist(h, x) (!__ac_iseither((h)->flags, (x)))
#define hashmap_key(h, x)   (list_get(&(h)->keys, x))
#define hashmap_val(h, x)   (list_get(&(h)->vals, x))
#define hashmap_begin(h)    ((i32)0)
#define hashmap_end(h)      ((h)->n_buckets)

#define hashmap_foreach(h, kvar, vvar, code)                                   \
  do {                                                                         \
    for (i32 __i = hashmap_begin(h); __i != hashmap_end(h); ++__i) {           \
      if (!hashmap_exist(h, __i))                                              \
        continue;                                                              \
      (kvar) = hashmap_key(h, __i);                                            \
      (vvar) = hashmap_val(h, __i);                                            \
      code;                                                                    \
    }                                                                          \
  } while (0)

#define hashset_foreach(h, kvar, code)                                         \
  do {                                                                         \
    for (i32 __i = hashmap_begin(h); __i != hashmap_end(h); ++__i) {           \
      if (!hashmap_exist(h, __i))                                              \
        continue;                                                              \
      (kvar) = hashmap_key(h, __i);                                            \
      code;                                                                    \
    }                                                                          \
  } while (0)

// Hash functions

#define Hashfn(fn)   __hashfn_wrap_##fn
#define Hasheqfn(fn) __hasheq_wrap_##fn
#define DECLARE_Hashfn(T, hfn, heq)                                            \
  static inline i32  Hashfn(hfn)(void* key) { return hfn(*(T*)(key)); }        \
  static inline bool Hasheqfn(heq)(void* a, void* b) {                         \
    return heq(*(T*)(a), *(T*)(b));                                            \
  }                                                                            \
  struct __dummy##hfn {}

static inline i32  hashmap_hash_i32(i32 i) { return i; }
static inline bool hashmap_hash_i32_eq(i32 a, i32 b) { return a == b; }
DECLARE_Hashfn(i32, hashmap_hash_i32, hashmap_hash_i32_eq);

static inline i32 hashmap_hash_i64(i64 i) {
  return (i32)((i) >> 33 ^ (i) ^ (i) << 11);
}
static inline bool hashmap_hash_i64_eq(i64 a, i64 b) { return a == b; }
DECLARE_Hashfn(i64, hashmap_hash_i64, hashmap_hash_i64_eq);

static inline i32 hashmap_hash_u64(u64 i) {
  return (i32)((i) >> 33 ^ (i) ^ (i) << 11);
}
static inline bool hashmap_hash_u64_eq(u64 a, u64 b) { return a == b; }
DECLARE_Hashfn(u64, hashmap_hash_u64, hashmap_hash_u64_eq);

static inline i32 hashmap_hash_cstr(char* s) {
  // X31 hash
  if (s == 0)
    return 0;
  i32 h = (i32)*s;
  for (++s; *s; ++s)
    h = (h << 5) - h + (i32)*s;
  return h;
}
static inline bool hashmap_hash_cstr_eq(char* a, char* b) {
  return strcmp(a, b) == 0;
}
DECLARE_Hashfn(char*, hashmap_hash_cstr, hashmap_hash_cstr_eq);

static inline i32 hashmap_hash_bytes(Bytes s) {
  // X31 hash
  if (s.len == 0)
    return 0;

  i32 h = s.buf[0];
  for (usize i = 1; i < s.len; ++i)
    h = (h << 5) - h + s.buf[i];
  return h;
}
static inline bool hashmap_hash_bytes_eq(Bytes a, Bytes b) {
  return str_eq(a, b);
}
DECLARE_Hashfn(Bytes, hashmap_hash_bytes, hashmap_hash_bytes_eq);

// Hashmap creation macros
#define Hashmap_create(h, K, V, hfn, heq, a)                                   \
  hashmap_init(h, sizeof(K), _Alignof(K), sizeof(V), _Alignof(V), Hashfn(hfn), \
               Hasheqfn(heq), a)
#define Hashset_create(h, K, hfn, heq, a)                                      \
  hashset_init(h, sizeof(K), _Alignof(K), Hashfn(hfn), Hasheqfn(heq), a)

#define Hashmap_i32_create(h, V, a)                                            \
  Hashmap_create(h, i32, V, hashmap_hash_i32, hashmap_hash_i32_eq, a)
#define Hashmap_i64_create(h, V, a)                                            \
  Hashmap_create(h, i64, V, hashmap_hash_i64, hashmap_hash_i64_eq, a)
#define Hashmap_u64_create(h, V, a)                                            \
  Hashmap_create(h, u64, V, hashmap_hash_u64, hashmap_hash_u64_eq, a)
#define Hashmap_cstr_create(h, V, a)                                           \
  Hashmap_create(h, char*, V, hashmap_hash_cstr, hashmap_hash_cstr_eq, a)
#define Hashmap_bytes_create(h, V, a)                                          \
  Hashmap_create(h, Bytes, V, hashmap_hash_bytes, hashmap_hash_bytes_eq, a)
