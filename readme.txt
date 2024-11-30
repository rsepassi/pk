pk
---

Build cli:
  make cli && ./build/cli/bin/cli

Build a library:
  make lib/vendor/sodium

Test a library:
  make test/lib/cbase

Test all:
  make test

build/: build artifacts
cli/: cli code
doc/: notes and documentation
lib/: supporting libraries
platform/: platform-specific
scripts/: shell/make helpers
vendor/: third-party dependencies
