#pragma once

#include "minicoro.h"

typedef void (*CocoFn)(void*);

int coco_go(mco_coro** co, size_t stack_sz, CocoFn fn, void* arg);
