#include "stdnet.h"
#include "stdtypes.h"

#define P2PMsg_FIELDS                                                          \
  u8 type;                                                                     \
  u8 reserved[3]

#define P2PMsg_DEF(name, code)                                                 \
  typedef struct __attribute__((packed)) {                                     \
    P2PMsg_FIELDS;                                                             \
    code                                                                       \
  } Disco##name

P2PMsg_DEF(       //
    IpRequest,    //
    u16 request;  //
);

P2PMsg_DEF(         //
    Ip,             //
    u16   request;  //
    IpMsg ip;       //
);

P2PMsg_DEF(       //
    Ping,         //
    u64 channel;  //
    u64 sender;   //
);

P2PMsg_DEF(        //
    Pong,          //
    u64 channel;   //
    u64 sender;    //
    u64 receiver;  //
);

P2PMsg_DEF(        //
    Done,          //
    u64 channel;   //
    u64 sender;    //
    u64 receiver;  //
);

P2PMsg_DEF(       //
    LocalAdvert,  //
    u64 channel;  //
);

P2PMsg_DEF(       //
    RelayInit,    //
    u64 channel;  //
);

P2PMsg_DEF(       //
    RelayPost,    //
    u64 channel;  //
);

typedef enum {
  P2PMsgIpRequest,
  P2PMsgIp,
  P2PMsgPing,
  P2PMsgPong,
  P2PMsgDone,
  P2PMsgAdvert,
  P2PMsgRelayInit,
  P2PMsgRelayPost,
  P2PMsg_COUNT,
  P2PMsg_RESERVED = 255,
} P2PMsgType;

const char* P2PMsgType_strs[P2PMsg_COUNT] = {
    "IPREQ",      //
    "IP",         //
    "PING",       //
    "PONG",       //
    "DONE",       //
    "ADVERT",     //
    "RELAYINIT",  //
    "RELAY",      //
};

static inline const char* P2PMsgType_str(P2PMsgType t) {
  return P2PMsgType_strs[t];
}

size_t P2PMsg_SZ[P2PMsg_COUNT] = {
    sizeof(DiscoIpRequest),    //
    sizeof(DiscoIp),           //
    sizeof(DiscoPing),         //
    sizeof(DiscoPong),         //
    sizeof(DiscoDone),         //
    sizeof(DiscoLocalAdvert),  //
    sizeof(DiscoRelayInit),    //
    sizeof(DiscoRelayPost),    //
};
