pk
---

Builds depend on:
  yash make pkg-config clang-19
  ./scripts/bootstrap.sh builds yash make pkg-config

Build and run cli:
  make --silent -j cli && ./build/out/bin/cli

Build a library:
  make --silent -j vendor/sodium

Test a library:
  make --silent -j lib/cbase/test

Test all:
  make test-clean
  make test

build/: build artifacts
cli/: cli code
doc/: notes and documentation
lib/: supporting libraries
platform/: platform-specific
scripts/: shell/make helpers
vendor/: third-party dependencies
