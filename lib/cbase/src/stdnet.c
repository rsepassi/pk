#include "stdnet.h"

#include "log.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#define IPv4_SZ       4
#define IPv6_SZ       STDNET_INET6_ADDRLEN
#define LOCALHOST_STR "localhost"

int IpStr_fromstr(IpStrStorage* out, const char* ip) {
  size_t ip_len = strlen(ip);

  char* colon = strrchr(ip, ':');
  if (colon != NULL) {
    ip_len    = colon - ip;
    int iport = atoi(colon + 1);
    if (iport > UINT16_MAX)
      return 1;
    out->port = (uint16_t)iport;
  }

  if (ip_len == 0 || memcmp(ip, LOCALHOST_STR, STRLEN(LOCALHOST_STR)) == 0) {
    ip     = STDNET_IPV4_LOCALHOST;
    ip_len = STRLEN(STDNET_IPV4_LOCALHOST);
  }

  if (ip_len >= sizeof(out->ip_buf))
    return 1;

  memcpy(out->ip_buf, ip, ip_len);
  out->ip_buf[ip_len] = 0;

  out->ip = Bytes(out->ip_buf, ip_len);
  return 0;
}

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

uint16_t stdnet_getport(const struct sockaddr* in) {
  int port = sa_get_port(in);
  if (port > UINT16_MAX)
    return 0;
  return (uint16_t)port;
}

int IpStr_read(IpStrStorage* out, const struct sockaddr* sa) {
  const void* addr = sa_get_in_addr(sa);
  if (addr == NULL)
    return 1;

  if (inet_ntop(sa->sa_family, addr, out->ip_buf, sizeof(out->ip_buf)) == NULL)
    return 1;
  out->ip   = Str0(out->ip_buf);
  out->port = (uint16_t)sa_get_port(sa);
  return 0;
}

int IpStr_frommsg(IpStrStorage* out, const IpMsg* in) {
  if (inet_ntop(in->ip_type == IpType_IPv4 ? AF_INET : AF_INET6, in->ip_buf,
                out->ip_buf, sizeof(out->ip_buf)) == NULL)
    return 1;
  out->ip   = Str0(out->ip_buf);
  out->port = ntohs(in->port);
  return 0;
}

int IpMsg_read(IpMsg* out, const struct sockaddr* sa) {
  STATIC_CHECK(sizeof(IpMsg) == STDNET_INET6_ADDRLEN + 4);
  switch (sa->sa_family) {
    case AF_INET: {
      const struct sockaddr_in* sa_in = (void*)sa;
      out->ip_type                    = IpType_IPv4;
      out->port                       = sa_in->sin_port;
      memcpy(out->ip_buf, &sa_in->sin_addr, IPv4_SZ);
    } break;
    case AF_INET6: {
      const struct sockaddr_in6* sa_in6 = (void*)sa;
      out->ip_type                      = IpType_IPv6;
      out->port                         = sa_in6->sin6_port;
      memcpy(out->ip_buf, &sa_in6->sin6_addr, IPv6_SZ);
    } break;
    default:
      return 1;
  }
  return 0;
}

int IpMsg_dump(struct sockaddr* out, const IpMsg* in) {
  if (in->ip_type >= IpType_MAX)
    return 1;
  IpType type = in->ip_type;
  switch (type) {
    case IpType_IPv4:
      out->sa_family            = AF_INET;
      struct sockaddr_in* sa_in = (void*)out;
      memcpy(&sa_in->sin_addr, in->ip_buf, IPv4_SZ);
      sa_in->sin_port = in->port;
      break;
    case IpType_IPv6:
      out->sa_family              = AF_INET6;
      struct sockaddr_in6* sa_in6 = (void*)out;
      memcpy(&sa_in6->sin6_addr, in->ip_buf, IPv6_SZ);
      sa_in6->sin6_port = in->port;
      break;
    default:
      return 1;
  }

  return 0;
}

static inline void stdnet_sockaddr4_cp(struct sockaddr_in*       out,
                                       const struct sockaddr_in* in) {
  memcpy(&out->sin_addr, &in->sin_addr, IPv4_SZ);
  out->sin_port = in->sin_port;
}

static inline void stdnet_sockaddr6_cp(struct sockaddr_in6*       out,
                                       const struct sockaddr_in6* in) {
  memcpy(&out->sin6_addr, &in->sin6_addr, IPv6_SZ);
  out->sin6_port = in->sin6_port;
}

int stdnet_sockaddr_cp(struct sockaddr* out, const struct sockaddr* in) {
  out->sa_family = in->sa_family;
  switch (in->sa_family) {
    case AF_INET:
      stdnet_sockaddr4_cp((void*)out, (void*)in);
      break;
    case AF_INET6:
      stdnet_sockaddr6_cp((void*)out, (void*)in);
      break;
    default:
      return 1;
  }
  return 0;
}
