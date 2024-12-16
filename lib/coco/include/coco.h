#pragma once

#include "minicoro.h"
#include "queue.h"
#include "stdtypes.h"

typedef struct {
  mco_coro* co;
  bool      done;
  Node2     node;
  void*     data;
} CocoWait;

#define CocoWait() ((CocoWait){mco_running(), 0, {0}, 0})

#define COCO_AWAIT(wait)                                                       \
  do {                                                                         \
    while (!(wait)->done) {                                                    \
      coco_yield();                                                            \
    }                                                                          \
  } while (0)

#define COCO_DONE(wait)                                                        \
  do {                                                                         \
    (wait)->done = true;                                                       \
    CHECK(mco_resume((wait)->co) == MCO_SUCCESS);                              \
  } while (0)

typedef void (*CocoFn)(void*);
int coco_go(mco_coro** co, usize stack_sz, CocoFn fn, void* arg);

typedef struct {
  CocoFn fn;
  void*  arg;
} CocoPoolWork;

typedef struct CocoPool_s CocoPool;

typedef struct {
  CocoPool*    pool;
  mco_coro*    co;
  Node         node;
  CocoPoolWork work;
  bool         exit;
  char         debug_name[16];
} CocoPoolItem;

struct CocoPool_s {
  CocoPoolItem* cos;
  usize         cos_len;
  Allocator     al;
  Queue         free;     // CocoPoolItem
  Queue         waiters;  // CocoPoolItem
};

int  CocoPool_init(CocoPool* pool, usize n, usize stack_sz, Allocator al,
                   Str name);
void CocoPool_deinit(CocoPool* pool);
int  CocoPool_go(CocoPool* pool, CocoFn fn, void* arg);
int  CocoPool_gonow(CocoPool* pool, CocoFn fn, void* arg);
int  CocoPool_gonow2(CocoPool* pool, CocoFn fn, void* arg, Str name);

static inline void coco_yield(void) { CHECK0(mco_yield(mco_running())); }
