#include "stdnet.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

const void* sa_get_in_addr(const struct sockaddr* sa) {
  switch (sa->sa_family) {
    case AF_INET: {
      const struct sockaddr_in* sa_in = (void*)sa;
      return &sa_in->sin_addr;
    }
    case AF_INET6: {
      const struct sockaddr_in6* sa_in6 = (void*)sa;
      return &sa_in6->sin6_addr;
    }
    default:
      return 0;
  }
}

static int sa_get_port(const struct sockaddr* sa) {
  switch (sa->sa_family) {
    case AF_INET: {
      const struct sockaddr_in* sa_in = (void*)sa;
      return ntohs(sa_in->sin_port);
    }
    case AF_INET6: {
      const struct sockaddr_in6* sa_in6 = (void*)sa;
      return ntohs(sa_in6->sin6_port);
    }
    default:
      return 0;
  }
}

int IpStr_read(IpStr* out, const struct sockaddr* sa) {
  const void* addr = sa_get_in_addr(sa);
  if (addr == NULL)
    return 1;

  if (inet_ntop(sa->sa_family, addr, out->ip_buf, sizeof(out->ip_buf)) == NULL)
    return 1;
  out->ip   = Str0(out->ip_buf);
  out->port = sa_get_port(sa);
  return 0;
}
