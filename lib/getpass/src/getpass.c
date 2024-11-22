#include "getpass.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32

#include <windows.h>

ssize_t getpass(char* pw, size_t maxlen) {
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
  DWORD mode = 0;
  ssize_t nread;

  if (!GetConsoleMode(hStdin, &mode))
    return -1;
  if (!SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT)))
    return -1;

  if (fgets(pw, (int)maxlen, stdin) == NULL) {
    SetConsoleMode(hStdin, mode);
    return -1;
  }

  nread = strlen(pw) - 1;
  pw[nread] = 0;

  // Print a newline since echo is disabled
  printf("\n");
  SetConsoleMode(hStdin, mode);
  return nread;
}

#else

#include <termios.h>

ssize_t getpass(char* pw, size_t maxlen) {
  struct termios old, new;
  ssize_t nread;

  if (tcgetattr(0, &old) != 0)
    return -1;

  new = old;
  new.c_lflag &= ~ECHO;
  new.c_lflag |= ECHONL;
  if (tcsetattr(0, TCSAFLUSH, &new) != 0)
    return -1;

  if (fgets(pw, (int)maxlen, stdin) == NULL) {
    tcsetattr(0, TCSAFLUSH, &old);
    return -1;
  }

  nread = strlen(pw) - 1;
  pw[nread] = 0;

  tcsetattr(0, TCSAFLUSH, &old);

  return nread;
}

#endif
