#include "str.h"

#define STDNET_INET6_ADDRSTRLEN 46

struct sockaddr;

typedef struct {
  char ip_buf[STDNET_INET6_ADDRSTRLEN];
  Str  ip;
  int  port;
} IpStr;

int IpStr_read(IpStr* out, const struct sockaddr* sa);
