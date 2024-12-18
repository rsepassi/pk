#include "stdnet.h"

#include "log.h"
#include "stdtypes.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#define IPv4_SZ       4
#define IPv6_SZ       STDNET_INET6_ADDRLEN
#define LOCALHOST_STR "localhost"

int stdnet_port_parse(u16* port, Bytes port_str) {
  i64 out;
  if (int_from_str(&out, port_str))
    return 1;

  if (out <= 0 || out > UINT16_MAX)
    return 1;

  *port = (u16)out;
  return 0;
}

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
  IpType t = in->ip4.ip_type;

  if (inet_ntop(t == IpType_IPv4 ? AF_INET : AF_INET6, in->ip4.ip_buf,
                out->ip_buf, sizeof(out->ip_buf)) == NULL)
    return 1;
  out->ip   = Str0(out->ip_buf);
  out->port = ntohs(in->ip4.port);
  return 0;
}

static int Ip4Msg_read(Ip4Msg* out, const struct sockaddr_in* sa) {
  out->ip_type = IpType_IPv4;
  out->port    = sa->sin_port;
  memcpy(out->ip_buf, &sa->sin_addr, IPv4_SZ);
  return 0;
}

static int Ip6Msg_read(Ip6Msg* out, const struct sockaddr_in6* sa) {
  out->ip_type = IpType_IPv6;
  out->port    = sa->sin6_port;
  memcpy(out->ip_buf, &sa->sin6_addr, IPv6_SZ);
  return 0;
}

int IpMsg_read(IpMsg* out, const struct sockaddr* sa) {
  STATIC_CHECK(sizeof(IpMsg) == STDNET_INET6_ADDRLEN + 4);
  switch (sa->sa_family) {
    case AF_INET:
      return Ip4Msg_read(&out->ip4, (void*)sa);
    case AF_INET6:
      return Ip6Msg_read(&out->ip6, (void*)sa);
    default:
      return 1;
  }
}

static int Ip4Msg_dump(struct sockaddr_in* out, const Ip4Msg* in) {
  out->sin_family = AF_INET;
  out->sin_port   = in->port;
  memcpy(&out->sin_addr, &in->ip_buf, IPv4_SZ);
  return 0;
}

static int Ip6Msg_dump(struct sockaddr_in6* out, const Ip6Msg* in) {
  out->sin6_family = AF_INET6;
  out->sin6_port   = in->port;
  memcpy(&out->sin6_addr, &in->ip_buf, IPv6_SZ);
  return 0;
}

int IpMsg_dump(struct sockaddr* out, const IpMsg* in) {
  IpType type = in->ip4.ip_type;
  if (type >= IpType_COUNT)
    return 1;
  switch (type) {
    case IpType_IPv4:
      return Ip4Msg_dump((void*)out, &in->ip4);
    case IpType_IPv6:
      return Ip6Msg_dump((void*)out, &in->ip6);
    default:
      return 1;
  }
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

bool stdnet_sockaddr4_eq(const struct sockaddr_in* a,
                         const struct sockaddr_in* b) {
  if (a->sin_port != b->sin_port)
    return false;
  return memcmp(&a->sin_addr, &b->sin_addr, IPv4_SZ) == 0;
}

bool stdnet_sockaddr6_eq(const struct sockaddr_in6* a,
                         const struct sockaddr_in6* b) {
  if (a->sin6_port != b->sin6_port)
    return false;
  return memcmp(&a->sin6_addr, &b->sin6_addr, IPv6_SZ) == 0;
}

bool stdnet_sockaddr_eq(const struct sockaddr* a, const struct sockaddr* b) {
  if (a->sa_family != b->sa_family)
    return false;
  switch (a->sa_family) {
    case AF_INET:
      return stdnet_sockaddr4_eq((void*)a, (void*)b);
    case AF_INET6:
      return stdnet_sockaddr6_eq((void*)a, (void*)b);
    default:
      return false;
  }
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
