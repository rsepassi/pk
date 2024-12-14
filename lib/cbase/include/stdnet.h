#include "str.h"

#define STDNET_IPV4_ANY       "0.0.0.0"
#define STDNET_IPV6_ANY       "::"
#define STDNET_IPV4_LOCALHOST "127.0.0.1"
#define STDNET_IPV6_LOCALHOST "::1"

#define STDNET_INET6_ADDRSTRLEN (45 + 1)
#define STDNET_INET6_ADDRLEN    16

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

#define PRIIpStr    ".*s:%d"
#define IpStrPRI(x) (int)(x).ip.len, (x).ip.buf, (x).port

typedef enum {
  IpType_IPv4,
  IpType_IPv6,
  IpType_MAX,
} IpType;

// A stable IP and port representation suitable to put on the network
typedef struct __attribute__((packed)) {
  uint8_t  ip_buf[STDNET_INET6_ADDRLEN];  // IPv4=4 bytes, IPv6=16 bytes
  uint16_t port;                          // little-endian
  uint8_t  ip_type;                       // IpType
  uint8_t  _pad;
} IpMsg;

int IpStr_read(IpStrStorage* out, const struct sockaddr* sa);
int IpStr_frommsg(IpStrStorage* out, const IpMsg* in);
int IpStr_fromstr(IpStrStorage* out, const char* ip);

int IpMsg_read(IpMsg* out, const struct sockaddr* sa);
int IpMsg_dump(struct sockaddr* out, const IpMsg* in);

uint16_t stdnet_getport(const struct sockaddr* in);
int      stdnet_sockaddr_cp(struct sockaddr* out, const struct sockaddr* in);
