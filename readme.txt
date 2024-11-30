pk
---

Build and run cli:
  make cli && ./build/cli/bin/cli

Build a library:
  make vendor/sodium

Test a library:
  make lib/cbase/test

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
