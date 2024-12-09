#include "str.h"

#define STDNET_INET6_ADDRSTRLEN 46
#define STDNET_INET6_ADDRLEN    16

struct sockaddr;

typedef struct {
  char ip_buf[STDNET_INET6_ADDRSTRLEN];
  Str  ip;
  int  port;
} IpStr;

typedef enum {
  IpType_IPv4,
  IpType_IPv6,
  IpType_MAX,
} IpType;

// A stable IP and port representation suitable to put on the network
typedef struct __attribute__((packed)) {
  uint8_t  ip_buf[STDNET_INET6_ADDRLEN];  // IPv4=4 bytes, IPv6=16 bytes
  uint16_t port;                          // network byte order
  uint8_t  ip_type;                       // IpType
  uint8_t  _pad;
} IpMsg;

int IpStr_read(IpStr* out, const struct sockaddr* sa);
int IpMsg_read(IpMsg* out, const struct sockaddr* sa);
