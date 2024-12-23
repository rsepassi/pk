// Minimal pkg-config
//
// Env
// * PKG_CONFIG_PATH
//
// Flags
// * --define-variable=foo=bar
// * --cflags
// * --libs
//
// pc files
// * Cflags
// * Libs

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFVAR "--define-variable"
#define CFLAGS "--cflags"
#define LIBS   "--libs"

#define MAX_VARS     128
#define MAX_PATHS    128
#define DEFVAR_ERROR "--define-variable must be used as --define-variable=a=b"

#define ERROR(fmt, ...)                                                        \
  do {                                                                         \
    fprintf(stderr, "error: " fmt "\n", ##__VA_ARGS__);                        \
  } while (0)

#define CHECKE(x, fmt, ...)                                                    \
  do {                                                                         \
    if (!(x)) {                                                                \
      ERROR(fmt, ##__VA_ARGS__);                                               \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

#ifndef NDEBUG
#define LOG(fmt, ...)                                                          \
  do {                                                                         \
    fprintf(stderr, "I:" fmt "\n", ##__VA_ARGS__);                             \
  } while (0)
#else
#define LOG(fmt, ...)
#endif

typedef struct {
  char*  s;
  size_t len;
} Str;

typedef struct {
  char*  name;
  size_t name_len;
  char*  value;
  size_t value_len;
} Variable;

bool fexists(const char* path) { return access(path, F_OK) == 0; }

// path/pkg.pc
static void mk_pc_path(char* out, char* path, char* pkg) {
  size_t path_len = strlen(path);
  size_t pkg_len  = strlen(pkg);
  CHECKE(path_len + pkg_len + 4 < 255,
         "path size limit exceeded for path %s and package %s", path, pkg);

  memcpy(out, path, path_len);
  memcpy(out + path_len, "/", 1);
  memcpy(out + path_len + 1, pkg, pkg_len);
  memcpy(out + path_len + 1 + pkg_len, ".pc", 3);
  out[path_len + 1 + pkg_len + 3] = 0;
}

static char* find_pc_file(char* pkg, char** config_paths,
                          int config_paths_len) {
  static char path[255];

  for (int i = 0; i < config_paths_len; ++i) {
    mk_pc_path(path, config_paths[i], pkg);
    LOG("trying %s", path);
    if (fexists(path))
      return path;
  }
  return 0;
}

static void parse_var(Variable* var, char* arg) {
  size_t arg_len = strlen(arg);
  CHECKE(arg_len >= 4, DEFVAR_ERROR);
  CHECKE(arg[0] == '=', DEFVAR_ERROR);
  arg++;
  arg_len--;

  var->name     = arg;
  var->name_len = 0;
  while (arg_len && arg[0] != '=') {
    var->name_len++;
    arg_len--;
    arg++;
  }

  CHECKE(arg_len, DEFVAR_ERROR);
  CHECKE(arg[0] == '=', DEFVAR_ERROR);
  arg++;
  arg_len--;
  CHECKE(arg_len, DEFVAR_ERROR);

  var->value     = arg;
  var->value_len = arg_len;

  LOG("var=%.*s=%.*s", (int)var->name_len, var->name, (int)var->value_len,
      var->value);
}

static void parse_config_paths(char** paths, int* paths_len, char* val,
                               size_t val_len) {
  int max_paths = *paths_len;
  *paths_len    = 0;
  while (val_len) {
    CHECKE(*paths_len < max_paths,
           "maximum number of paths (%d) in PKG_CONFIG_PATH exceeded",
           max_paths);
    char* path     = val;
    int   path_len = 0;
    while (val_len && val[0] != ':') {
      path_len++;
      val++;
      val_len--;
    }

    paths[*paths_len] = malloc(path_len + 1);
    CHECKE(paths[*paths_len], "oom");
    memcpy(paths[*paths_len], path, path_len);
    paths[*paths_len][path_len] = 0;
    LOG("path=%s", paths[*paths_len]);
    *paths_len += 1;
  }
}

Str read_file(const char* path) {
  FILE* file = fopen(path, "rb");
  CHECKE(file, "could not open file %s", path);

  CHECKE(fseek(file, 0, SEEK_END) == 0, "could not read file %s", path);
  size_t file_size = ftell(file);
  CHECKE(file_size >= 0, "could not read file %s", path);
  CHECKE(fseek(file, 0, SEEK_SET) == 0, "could not read file %s", path);

  char* buffer = malloc(file_size + 1);
  CHECKE(buffer, "oom");

  size_t bytes_read = fread(buffer, 1, file_size, file);
  fclose(file);

  CHECKE(bytes_read == file_size, "could not read file %s", path);
  buffer[file_size] = 0;

  return (Str){buffer, file_size};
}

static Variable* lookup_var(Variable* vars, int vars_len, Str varname) {
  for (int i = 0; i < vars_len; ++i) {
    if (vars[i].name_len != varname.len)
      continue;
    if (memcmp(vars[i].name, varname.s, varname.len) == 0)
      return &vars[i];
  }
  return 0;
}

static void print_flags_vars(Str* pc, Variable* vars, int vars_len) {
  Str start = *pc;
  while (pc->len) {
    if (pc->s[0] == '\\') {
      printf("%.*s", (int)(pc->s - start.s), start.s);
      pc->s++;
      pc->len--;
      CHECKE(pc->len, "malformed pc file");
      pc->s++;
      pc->len--;
      start = *pc;
      continue;
    }

    if (pc->s[0] == '\n') {
      printf("%.*s", (int)(pc->s - start.s), start.s);
      pc->s++;
      pc->len--;
      return;
    }

    if (pc->len >= 2 && memcmp(pc->s, "${", 2) == 0) {
      printf("%.*s", (int)(pc->s - start.s), start.s);
      pc->s += 2;
      pc->len -= 2;

      // Variable name
      Str varname = {pc->s, 0};
      while (pc->len && pc->s[0] != '}') {
        pc->s++;
        pc->len--;
        varname.len++;
      }
      CHECKE(pc->len && varname.len, "bad variable name in pc file");
      pc->s++;
      pc->len--;

      Variable* val = lookup_var(vars, vars_len, varname);
      CHECKE(val, "variable %.*s not defined", (int)varname.len, varname.s);
      printf("%.*s", (int)val->value_len, val->value);

      start = *pc;
      continue;
    }

    pc->s++;
    pc->len--;
  }
}

static void print_flags_prefix(Str pc, Variable* vars, int vars_len,
                               Str prefix) {
  while (pc.len) {
    if (pc.len <= prefix.len)
      return;

    if (memcmp(pc.s, prefix.s, prefix.len) == 0) {
      pc.s += prefix.len;
      pc.len -= prefix.len;
      print_flags_vars(&pc, vars, vars_len);
      printf("\n");
      return;
    }

    pc.s++;
    pc.len--;
  }
}

static void print_flags(Str pc, Variable* vars, int vars_len, bool cflags,
                        bool libs) {
  if (cflags)
    print_flags_prefix(pc, vars, vars_len, (Str){"Cflags:", 7});
  if (libs)
    print_flags_prefix(pc, vars, vars_len, (Str){"Libs:", 5});
}

static void pkgconfig(char* pkg, char** config_paths, int config_paths_len,
                      Variable* vars, int vars_len, bool cflags, bool libs) {
  LOG("pkg=%s", pkg);
  char* pc_file = find_pc_file(pkg, config_paths, config_paths_len);
  CHECKE(pc_file, "no pc file found for %s", pkg);
  LOG("pc file %s", pc_file);
  Str pc_file_contents = read_file(pc_file);
  print_flags(pc_file_contents, vars, vars_len, cflags, libs);
  free(pc_file_contents.s);
}

int main(int argc, char** argv) {
  char** pkgs     = 0;
  int    pkgs_len = 0;

  bool cflags = false;
  bool libs   = false;

  Variable vars[MAX_VARS];
  int      vars_len = 0;

  for (int i = 1; i < argc; ++i) {
    char* arg = argv[i];
    if (arg[0] == '-') {
      if (memcmp(arg, DEFVAR, sizeof(DEFVAR) - 1) == 0) {
        CHECKE(vars_len < MAX_VARS, "maximum number of variables (%d) exceeded",
               MAX_VARS);
        parse_var(&vars[vars_len], arg + sizeof(DEFVAR) - 1);
        vars_len++;
      } else if (memcmp(arg, CFLAGS, sizeof(CFLAGS) - 1) == 0) {
        cflags = true;
        LOG("cflags=true");
      } else if (memcmp(arg, LIBS, sizeof(LIBS) - 1) == 0) {
        LOG("libs=true");
        libs = true;
      } else {
        CHECKE(false, "unrecognized flag %s", arg);
      }
    } else {
      pkgs     = &argv[i];
      pkgs_len = argc - i;
      break;
    }
  }

  CHECKE(pkgs_len, "must pass one or more package names");
  if (!cflags && !libs)
    return 0;

  char* pkg_config_path = getenv("PKG_CONFIG_PATH");
  CHECKE(pkg_config_path, "must set PKG_CONFIG_PATH");
  size_t pkg_config_path_len = strlen(pkg_config_path);
  CHECKE(pkg_config_path_len, "must set PKG_CONFIG_PATH");

  char* config_paths[MAX_PATHS];
  int   config_paths_len = MAX_PATHS;
  parse_config_paths(config_paths, &config_paths_len, pkg_config_path,
                     pkg_config_path_len);
  LOG("#paths=%d", config_paths_len);

  for (int i = 0; i < pkgs_len; ++i) {
    pkgconfig(pkgs[i], config_paths, config_paths_len, vars, vars_len, cflags,
              libs);
  }

  return 0;
}
