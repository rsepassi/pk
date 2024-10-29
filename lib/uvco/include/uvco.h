#pragma once

#include "uv.h"

ssize_t uvco_fs_stat(uv_loop_t *loop, uv_fs_t *req, const char *path);
