#include "coco.h"

#include "log.h"

typedef struct {
  CocoFn fn;
  void*  arg;
} CocoCtx;

static void coco_mco_fn(mco_coro* co) {
  CocoCtx* ctx = co->user_data;
  ctx->fn(ctx->arg);
}

int coco_go(mco_coro** co, size_t stack_sz, CocoFn fn, void* arg) {
  STATIC_CHECK(MCO_SUCCESS == 0);
  CocoCtx ctx    = {0};
  ctx.fn         = fn;
  ctx.arg        = arg;
  mco_desc desc  = mco_desc_init(coco_mco_fn, stack_sz);
  desc.user_data = &ctx;
  int rc;
  if ((rc = mco_create(co, &desc)) != MCO_SUCCESS)
    return rc;
  if ((rc = mco_resume(*co)) != MCO_SUCCESS)
    return rc;
  return 0;
}

static void* stack_alloc(size_t size, void* udata) {
  Allocator* al = udata;
  Bytes      b;
  if (allocator_u8(*al, &b, size))
    return 0;
  return b.buf;
}

static void stack_dealloc(void* ptr, size_t size, void* udata) {
  Allocator* al = udata;
  allocator_free(*al, Bytes(ptr, size));
}

static void pool_codone(CocoPoolItem* x) {
  q_enq(&x->pool->free, &x->node);

  Node* waiter;
  if ((waiter = q_deq(&x->pool->waiters))) {
    CocoWait* wait = CONTAINER_OF(waiter, CocoWait, node);
    COCO_DONE(wait);
  }
}

static void pool_comain(mco_coro* co) {
  CocoPoolItem* x = co->user_data;

  while (1) {
    if (x->exit)
      break;

    if (x->work.fn == NULL) {
      CHECK0(mco_yield(mco_running()));
      continue;
    }

    x->work.fn(x->work.arg);
    x->work = (CocoPoolWork){0};
    pool_codone(x);
  }
}

int CocoPool_init(CocoPool* pool, usize n, usize stack_sz, Allocator al) {
  ZERO(pool);

  Bytes b;
  int   rc;
  if ((rc = Alloc_alloc(al, &b, CocoPoolItem, n)))
    return rc;

  pool->cos     = (void*)b.buf;
  pool->cos_len = n;
  pool->al      = al;

  mco_desc desc       = mco_desc_init(pool_comain, stack_sz);
  desc.allocator_data = &pool->al;
  desc.alloc_cb       = stack_alloc;
  desc.dealloc_cb     = stack_dealloc;

  for (usize i = 0; i < n; ++i) {
    CocoPoolItem* x = &pool->cos[i];
    ZERO(x);

    x->pool        = pool;
    desc.user_data = x;
    q_enq(&pool->free, &x->node);
    CHECK0(mco_create(&x->co, &desc));
  }

  return 0;
}

static bool CocoPool_allexited(CocoPool* pool) {
  for (usize i = 0; i < pool->cos_len; ++i) {
    CocoPoolItem* x = &pool->cos[i];
    if (mco_status(x->co) != MCO_DEAD)
      return false;
  }
  return true;
}

static void CocoPool_exitall(CocoPool* pool) {
  for (usize i = 0; i < pool->cos_len; ++i) {
    CocoPoolItem* x = &pool->cos[i];
    x->exit = true;
    CHECK0(mco_resume(x->co));
  }

  if (mco_running())
    while (!CocoPool_allexited(pool))
      CHECK0(mco_yield(mco_running()));
}

void CocoPool_deinit(CocoPool* pool) {
  CocoPool_exitall(pool);
  for (usize i = 0; i < pool->cos_len; ++i) {
    CocoPoolItem* x = &pool->cos[i];
    mco_destroy(x->co);
  }
  allocator_free(pool->al,
                 Bytes(pool->cos, pool->cos_len * sizeof(CocoPoolItem)));
}

int CocoPool_go(CocoPool* pool, CocoFn fn, void* arg) {
  (void)pool;
  (void)fn;
  (void)arg;

  while (1) {
    int rc = CocoPool_gonow(pool, fn, arg);
    if (rc == 0)
      return 0;

    if (rc == 1) {
      CocoWait wait;
      q_enq(&pool->waiters, &wait.node);
      COCO_AWAIT(&wait);
      continue;
    }
  }

  return 0;
}

int CocoPool_gonow(CocoPool* pool, CocoFn fn, void* arg) {
  Node* n = q_deq(&pool->free);
  if (n == NULL)
    return 1;

  CocoPoolItem* x = CONTAINER_OF(n, CocoPoolItem, node);
  x->work.fn      = fn;
  x->work.arg     = arg;
  CHECK0(mco_resume(x->co));

  return 0;
}
