// Discovery

#include "cli.h"
#include "log.h"

int disco_local(int argc, char** argv) {
  LOG("");
  return 0;
}

static const CliCmd disco_commands[] = {
    {"local", disco_local},  //
    {0},
};

int demo_disco(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "missing subcommand\n");
    cli_usage("disco", disco_commands, 0);
    return 1;
  }

  argc -= 1;
  argv += 1;

  return cli_dispatch("disco", disco_commands, argc, argv);
}
