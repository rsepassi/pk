#include "stdnet.h"  // for IpMsg
#include "stdtypes.h"

#define P2PMsg_FIELDS                                                          \
  u8 type;                                                                     \
  u8 reserved[3]

#define P2PMsg_DEF(name, code)                                                 \
  typedef struct __attribute__((packed)) {                                     \
    P2PMsg_FIELDS;                                                             \
    code                                                                       \
  } Disco##name

#define P2PMsg_decl(var, t)                                                    \
  Disco##t var = {0};                                                          \
  do {                                                                         \
    var.type = P2PMsg##t;                                                      \
  } while (0)

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
    u64 sender;   //
);

P2PMsg_DEF(       //
    RelayInit,    //
    u64 channel;  //
    u64 sender;   //
);

P2PMsg_DEF(        //
    RelayInitAck,  //
    u64 channel;   //
);

P2PMsg_DEF(       //
    RelayPost,    //
    u64 channel;  //
);

typedef enum {
  P2PMsg_UNKNOWN,
  P2PMsgIpRequest,
  P2PMsgIp,
  P2PMsgPing,
  P2PMsgPong,
  P2PMsgDone,
  P2PMsgLocalAdvert,
  P2PMsgRelayInit,
  P2PMsgRelayInitAck,
  P2PMsgRelayPost,
  P2PMsg_COUNT,
  P2PMsg_RESERVED = 255,
} P2PMsgType;

const char* P2PMsgType_strs[P2PMsg_COUNT] = {
    "UNKNOWN",       //
    "IPREQ",         //
    "IP",            //
    "PING",          //
    "PONG",          //
    "DONE",          //
    "ADVERT",        //
    "RELAYINIT",     //
    "RELAYINITACK",  //
    "RELAY",         //
};

size_t P2PMsg_SZ[P2PMsg_COUNT] = {
    0,
    sizeof(DiscoIpRequest),     //
    sizeof(DiscoIp),            //
    sizeof(DiscoPing),          //
    sizeof(DiscoPong),          //
    sizeof(DiscoDone),          //
    sizeof(DiscoLocalAdvert),   //
    sizeof(DiscoRelayInit),     //
    sizeof(DiscoRelayInitAck),  //
    sizeof(DiscoRelayPost),     //
};

static inline const char* P2PMsgType_str(P2PMsgType t) {
  return P2PMsgType_strs[t];
}

static inline bool P2PMsgType_valid(P2PMsgType t) {
  if (t == 0)
    return false;
  if (t >= P2PMsg_COUNT)
    return false;
  return true;
}

static inline bool P2PMsg_valid(Bytes b, P2PMsgType t) {
  if (!P2PMsgType_valid(t))
    return false;
  if (b.len != P2PMsg_SZ[t])
    return false;
  if (b.buf[0] != t)
    return false;
  return true;
}
