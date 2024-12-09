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
