#pragma once

#include "optparse.h"
#include "stdtypes.h"

#include <stdio.h>

typedef struct {
  const char* cmd;
  int (*fn)(int, char**);
} CliCmd;

static inline void cli_usage(const char* name, const CliCmd* cmds,
                             struct optparse_long* opts) {
  fprintf(stderr, "%s [options] [subcommand] [suboptions] [args]\n", name);

  usize i;

  fprintf(stderr, "options:\n");
  i = 0;
  while (opts && opts[i].longname) {
    switch (opts[i].argtype) {
      case OPTPARSE_NONE:
        fprintf(stderr, "  --%s (-%c)\n", opts[i].longname, opts[i].shortname);
        break;
      case OPTPARSE_REQUIRED:
        fprintf(stderr, "  --%s=<arg> (-%c<arg>)\n", opts[i].longname,
                opts[i].shortname);
        break;
      case OPTPARSE_OPTIONAL:
        fprintf(stderr, "  --%s[=<arg>] (-%c[<arg>])\n", opts[i].longname,
                opts[i].shortname);
        break;
    }
    ++i;
  }

  fprintf(stderr, "subcommands:\n");
  i = 0;
  while (cmds && cmds[i].cmd)
    fprintf(stderr, "  - %s\n", cmds[i++].cmd);
}

static inline int cli_dispatch(const char* name, const CliCmd* cmds, int argc,
                               char** argv) {
  usize i = 0;
  while (cmds && cmds[i].cmd) {
    if (!strcmp(cmds[i].cmd, argv[0])) {
      return cmds[i].fn(argc, argv);
    }
    ++i;
  }

  fprintf(stderr, "unrecognized command %s\n", argv[0]);
  cli_usage(name, cmds, 0);
  return 1;
}
