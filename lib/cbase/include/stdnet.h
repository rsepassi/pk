#pragma once

#include "log.h"
#include "str.h"

#define STDNET_IPV4_ANY       "0.0.0.0"
#define STDNET_IPV6_ANY       "::"
#define STDNET_IPV4_LOCALHOST "127.0.0.1"
#define STDNET_IPV6_LOCALHOST "::1"

#define STDNET_INET6_ADDRSTRLEN (45 + 1)
#define STDNET_INET6_ADDRLEN    16
#define STDNET_INET4_ADDRSTRLEN (15 + 1)
#define STDNET_INET4_ADDRLEN    4

#define LOG_SOCK(tag, sa)                                                      \
  do {                                                                         \
    IpStrStorage __ips;                                                        \
    CHECK0(IpStr_read(&__ips, (struct sockaddr*)(sa)));                        \
    LOG("%s: %" PRIIpStr, (tag), IpStrPRI(__ips));                             \
  } while (0)
#define PRIIpStr    ".*s:%d"
#define IpStrPRI(x) (int)(x).ip.len, (x).ip.buf, (x).port

struct sockaddr;

typedef struct {
  Str      ip;
  uint16_t port;
  char     ip_buf[STDNET_INET6_ADDRSTRLEN];
} IpStrStorage;

typedef struct {
  Str      ip;
  uint16_t port;
} IpStr;

typedef enum {
  IpType_IPv4,
  IpType_IPv6,
  IpType_COUNT,
} IpType;

// Stable IP and port representations suitable to put on the network
typedef struct __attribute__((packed)) {
  uint8_t  ip_type;  // IpType
  uint16_t port;     // network byte order
  uint8_t  _pad;
  uint8_t  ip_buf[STDNET_INET4_ADDRLEN];
} Ip4Msg;

typedef struct __attribute__((packed)) {
  uint8_t  ip_type;  // IpType
  uint16_t port;     // network byte order
  uint8_t  _pad;
  uint8_t  ip_buf[STDNET_INET6_ADDRLEN];
} Ip6Msg;

typedef union {
  Ip4Msg ip4;
  Ip6Msg ip6;
} IpMsg;

int IpStr_read(IpStrStorage* out, const struct sockaddr* sa);
int IpStr_frommsg(IpStrStorage* out, const IpMsg* in);
int IpStr_fromstr(IpStrStorage* out, const char* ip);

int IpMsg_read(IpMsg* out, const struct sockaddr* sa);
int IpMsg_dump(struct sockaddr* out, const IpMsg* in);

uint16_t stdnet_getport(const struct sockaddr* in);
int      stdnet_sockaddr_cp(struct sockaddr* out, const struct sockaddr* in);
bool     stdnet_sockaddr_eq(const struct sockaddr* a, const struct sockaddr* b);
int      stdnet_port_parse(uint16_t* port, Str port_str);

void stdnet_sockaddr_ip4(struct sockaddr* sa, const char* ip, uint16_t port);
void stdnet_sockaddr_ip6(struct sockaddr* sa, const char* ip, uint16_t port);
