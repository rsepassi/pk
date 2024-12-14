// Discovery
//
// TODO:
// * Channel expiration
// * Use siphash since requester chooses channel id?
// * Authentication
// * Authorization
// * Encryption
// * Anonymity
// * Channel modifications (e.g. changing forwarding address)
// * Relay header?
// * Throttling sends

#include "allocatormi.h"
#include "cli.h"
#include "coco.h"
#include "crypto.h"
#include "hashmap.h"
#include "log.h"
#include "plum/plum.h"
#include "sodium.h"
#include "stdnet.h"
#include "stdtime.h"
#include "uvco.h"

extern uv_loop_t* loop;

static void log_sockaddr(const char* tag, const struct sockaddr* addr) {
  IpStrStorage ips;
  CHECK0(IpStr_read(&ips, (struct sockaddr*)addr));
  LOG("%s=%" PRIIpStr, tag, IpStrPRI(ips));
}

static u16 parse_port(const char* port_str) {
  int iport = atoi(port_str);
  CHECK(iport <= UINT16_MAX);
  return (u16)iport;
}

static void log_local_interfaces() {
  uv_interface_address_t* addrs;
  int                     count;
  CHECK0(uv_interface_addresses(&addrs, &count));
  for (int i = 0; i < count; ++i) {
    uv_interface_address_t* addr = &addrs[i];
    if (addr->is_internal)
      continue;
    if (((struct sockaddr*)&addr->address)->sa_family != AF_INET)
      continue;
    IpStrStorage ip;
    CHECK0(IpStr_read(&ip, (struct sockaddr*)&addr->address));
    LOG("local interface %s=%" PRIIpStr, addr->name, IpStrPRI(ip));
  }
}

static u16 udp_getsockport(uv_udp_t* udp) {
  struct sockaddr_storage me;
  int                     me_len = sizeof(me);
  CHECK0(uv_udp_getsockname(udp, (struct sockaddr*)&me, &me_len));
  CHECK(me_len == sizeof(struct sockaddr_in));
  CHECK(me.ss_family == AF_INET);

  IpStrStorage me_str;
  CHECK0(IpStr_read(&me_str, (struct sockaddr*)&me));
  return me_str.port;
}

#define P2PMsg_FIELDS                                                          \
  u8 type;                                                                     \
  u8 reserved[3]

typedef struct __attribute__((packed)) {
  P2PMsg_FIELDS;
} DiscoRelayMsgIp;

typedef struct __attribute__((packed)) {
  u64 id;
} DiscoLocalAdvert;

typedef struct {
  IpStr              multicast_addrs;
  struct sockaddr_in multicast_addr;
  uv_udp_t           multicast_udp;
  uv_udp_t           udp;
  int                port;
  u64                id;
} DiscoLocalCtx;

static u64 disco_channel_derive(Bytes in) {
  u64 out;
  CHECK0(
      crypto_generichash_blake2b((u8*)&out, sizeof(out), in.buf, in.len, 0, 0));
  return out;
}

static void disco_multicast4_derive(struct sockaddr_in* addr, u64 channel) {
  u8* h = (u8*)&channel;

  addr->sin_family = AF_INET;

  // First 2 bytes are used for the port
  // Windows, Mac use >=49152
  // Linux uses <=60999
  u16 port       = *(u16*)h;
  addr->sin_port = htons(49152 + (port % (60999 - 49152)));

  // Next 3 bytes are used for the IP
  // Multicast administratively scoped is 239/8
  u8* ip = (u8*)&addr->sin_addr;
  ip[0]  = 239;
  ip[1]  = h[2];
  ip[2]  = h[3];
  ip[3]  = h[4];

  // Leave 239.0.0.0 and 239.255.255.255 alone
  if (ip[1] == 0 && ip[2] == 0 && ip[3] == 0)
    ip[3] = 1;
  if (ip[1] == 255 && ip[2] == 255 && ip[3] == 255)
    ip[3] = 254;
}

static u64 disco_channel_generic() {
  return disco_channel_derive(Str("pk-disco-all"));
}

static u64 disco_channel_peer(const CryptoSignPK* pk) {
  return disco_channel_derive(BytesObj(*pk));
}

static u64 disco_channel_code(Str code) { return disco_channel_derive(code); }

static u64 disco_channel_mutual(const CryptoSignPK* me,
                                const CryptoSignSK* me_sk,
                                const CryptoSignPK* bob) {
  CryptoKxPK mex;
  CryptoKxSK me_skx;
  CryptoKxPK bobx;
  CHECK0(crypto_sign_ed25519_pk_to_curve25519((u8*)&mex, (u8*)me));
  CHECK0(crypto_sign_ed25519_sk_to_curve25519((u8*)&me_skx, (u8*)me_sk));
  CHECK0(crypto_sign_ed25519_pk_to_curve25519((u8*)&bobx, (u8*)bob));

  // memcmp OK: public key
  CryptoKxTx shared;
  if (memcmp(&mex, &bobx, sizeof(bobx)) > 0) {
    CHECK0(crypto_kx_server_session_keys((u8*)&shared, 0, (u8*)&mex,
                                         (u8*)&me_skx, (u8*)&bobx));
  } else {
    CHECK0(crypto_kx_client_session_keys((u8*)&shared, 0, (u8*)&mex,
                                         (u8*)&me_skx, (u8*)&bobx));
  }

  u8 subkey[32];
  STATIC_CHECK(sizeof(shared) == crypto_kdf_blake2b_KEYBYTES);
  CHECK0(crypto_kdf_blake2b_derive_from_key(subkey, sizeof(subkey), 1,
                                            "pk-disco", (u8*)&shared));

  return disco_channel_derive(BytesArray(subkey));
}

typedef struct {
  u16            internal_port;
  u16            external_port;
  uv_async_t*    async;
  int            mapping_id;
  plum_mapping_t mapping;
} PlumCtx;

static void mapping_callback(int id, plum_state_t state,
                             const plum_mapping_t* mapping) {
  PlumCtx* ctx = mapping->user_ptr;
  CHECK0(ctx->external_port);
  if (state == PLUM_STATE_SUCCESS)
    ctx->external_port = mapping->external_port;
  uv_async_send(ctx->async);
}

static void async_plumfn(uv_async_t* async, void* arg) {
  PlumCtx* ctx               = arg;
  ctx->async                 = async;
  ctx->mapping.protocol      = PLUM_IP_PROTOCOL_UDP;
  ctx->mapping.internal_port = ctx->internal_port;
  ctx->mapping.user_ptr      = ctx;
  ctx->mapping_id = plum_create_mapping(&ctx->mapping, mapping_callback);
}

// Disco relay service
// * Initialize channel
// * Post message to channel

typedef enum {
  DiscoRelayMsg_IP,
  DiscoRelayMsg_INIT,
  DiscoRelayMsg_POST,
  DiscoRelayMsg_N,
} DiscoRelayMsgType;

typedef struct __attribute__((packed)) {
  u8  type;
  u8  reserved[3];
  u64 channel_id;
} DiscoRelayMsgInit;

typedef struct __attribute__((packed)) {
  u8  type;
  u8  reserved[3];
  u64 channel_id;
  u16 payload_len;
} DiscoRelayMsgPost;

#define DISCO_MIN_MSG_SZ                                                       \
  MIN(sizeof(DiscoRelayMsgIp),                                                 \
      MIN(sizeof(DiscoRelayMsgInit), sizeof(DiscoRelayMsgPost)))
#define DISCO_MAX_MSG_SZ 1600

typedef struct {
  uv_udp_t udp;
  Hashmap  channels;  // u64 -> DiscoChannel
} DiscoCtx;

typedef struct {
  u64                     id;
  struct sockaddr_storage addr;
} DiscoChannel;

typedef struct {
  DiscoCtx*    ctx;
  UvcoUdpRecv* recv;
} DiscoDispatchArg;

static void disco_giveip(void* varg) {
  LOG("");
  DiscoDispatchArg* argp = varg;
  DiscoDispatchArg  arg  = *argp;

  UvcoUdpRecv* recv = arg.recv;
  IpMsg        msg;
  CHECK0(IpMsg_read(&msg, recv->addr));
  struct sockaddr addr = *recv->addr;
  uv_buf_t        buf  = UvBuf(BytesObj(msg));
  CHECK0(uvco_udp_send(recv->udp, &buf, 1, &addr));
}

static void disco_relay_init(void* varg) {
  LOG("");
  DiscoDispatchArg* argp = varg;
  DiscoDispatchArg  arg  = *argp;

  UvcoUdpRecv* recv = arg.recv;
  Bytes        msg  = UvBytes(recv->buf);

  if (msg.len != sizeof(DiscoRelayMsgInit))
    return;

  DiscoRelayMsgInit* init_msg = (void*)msg.buf;

  // New channel
  HashmapStatus ret;
  HashmapIter it = hashmap_put(&arg.ctx->channels, &init_msg->channel_id, &ret);
  switch (ret) {
    case HashmapStatus_Present:
    case HashmapStatus_ERR:
      return;
    default:
      break;
  }

  DiscoChannel* chan = hashmap_val(&arg.ctx->channels, it);
  ZERO(chan);

  chan->id   = init_msg->channel_id;
  chan->addr = *(struct sockaddr_storage*)recv->addr;

  IpStrStorage ipstr;
  CHECK0(IpStr_read(&ipstr, (struct sockaddr*)&chan->addr));
  LOG("new channel %" PRIu64 " %" PRIIpStr, chan->id, IpStrPRI(ipstr));

  // Send back an ack
  uv_buf_t ack = UvBuf(Str("\0"));
  CHECK0(uvco_udp_send(&arg.ctx->udp, &ack, 1, (struct sockaddr*)&chan->addr));
}

static void disco_relay_post(void* varg) {
  LOG("");
  DiscoDispatchArg* argp = varg;
  DiscoDispatchArg  arg  = *argp;

  UvcoUdpRecv* recv = arg.recv;
  Bytes        msg  = UvBytes(recv->buf);

  if (msg.len < sizeof(DiscoRelayMsgPost))
    return;
  Bytes header = bytes_advance(&msg, sizeof(DiscoRelayMsgPost));

  DiscoRelayMsgPost* post_msg = (void*)header.buf;
  if (post_msg->payload_len != msg.len)
    return;
  if (msg.len > DISCO_MAX_MSG_SZ)
    return;

  HashmapIter it = hashmap_get(&arg.ctx->channels, &post_msg->channel_id);
  if (it == hashmap_end(&arg.ctx->channels))
    return;

  DiscoChannel* chan = hashmap_val(&arg.ctx->channels, it);

  // Copy the message into our frame to keep it alive for sending
  u8    out_buf[DISCO_MAX_MSG_SZ];
  Bytes out = BytesArray(out_buf);
  bytes_copy(&out, msg);

  IpStrStorage ipstr;
  CHECK0(IpStr_read(&ipstr, (struct sockaddr*)recv->addr));
  LOG("channel post %" PRIu64 " from %" PRIIpStr, chan->id, IpStrPRI(ipstr));

  // Send message on channel
  uv_buf_t outuv = UvBuf(out);
  CHECK0(
      uvco_udp_send(&arg.ctx->udp, &outuv, 1, (struct sockaddr*)&chan->addr));
}

static void disco_dispatch(CocoPool* pool, DiscoCtx* ctx, UvcoUdpRecv* recv) {
  LOG("");
  Bytes msg = UvBytes(recv->buf);

  if (msg.len < DISCO_MIN_MSG_SZ)
    return;
  if (msg.len > DISCO_MAX_MSG_SZ)
    return;

  if (msg.buf[0] >= DiscoRelayMsg_N)
    return;
  DiscoRelayMsgType type = msg.buf[0];

  CocoFn handlers[DiscoRelayMsg_N] = {
      disco_giveip,
      disco_relay_init,
      disco_relay_post,
  };

  // gonow because the recv buf is ephemeral. If there's no handler now,
  // drop the request.
  DiscoDispatchArg arg = {0};
  arg.ctx              = ctx;
  arg.recv             = recv;
  CocoPool_gonow(pool, handlers[type], &arg);
}

static int disco_server(int argc, char** argv) {
  (void)argc;

  u16 port = 0;

  struct optparse opts;
  optparse_init(&opts, argv);
  int option;
  while ((option = optparse(&opts, "p:")) != -1) {
    switch (option) {
      case 'p':
        port = parse_port(opts.optarg);
        break;
      case '?':
        LOGE("unrecognized option %c", option);
        return 1;
    }
  }

  // Disco relay and rendezvous

  // Alice now asks the Disco server to aid in rendezvous with Bob
  //
  // Alice asks Disco to open a channel
  //   Channel ID:
  //     * Hash(Alice PK): allows others to find Alice
  //     * KDF(DH(Alice, Bob)): allows mutual finding
  //     * Pre-shared code
  //
  // Bob sends a message to the channel
  // Disco forwards the message to Alice
  // Alice now has Bob's IP+Port (+Key)
  //
  // Alice and Bob can try direct communication
  // If that fails, they can continue to use the channel

  Allocator al = allocatormi_allocator();

  DiscoCtx ctx = {0};
  CHECK0(Hashmap_u64_create(&ctx.channels, DiscoChannel, al));

  log_local_interfaces();

  CHECK0(uv_udp_init(loop, &ctx.udp));
  struct sockaddr_storage me;
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, port, (struct sockaddr_in*)&me));
  CHECK0(uv_udp_bind(&ctx.udp, (struct sockaddr*)&me, UV_UDP_REUSEADDR));
  port                                 = udp_getsockport(&ctx.udp);
  ((struct sockaddr_in*)&me)->sin_port = htons(port);
  log_sockaddr("me", (struct sockaddr*)&me);

  CocoPool pool;
  CHECK0(CocoPool_init(&pool, 64, 1024 * 4, al));

  UvcoUdpRecv recv;
  CHECK0(uvco_udp_recv_start(&recv, &ctx.udp));
  while (1) {
    CHECK(uvco_udp_recv_next(&recv) >= 0);
    disco_dispatch(&pool, &ctx, &recv);
  }

  hashmap_deinit(&ctx.channels);
  uvco_close((uv_handle_t*)&ctx.udp);
  CocoPool_deinit(&pool);
  return 0;
}

static int disco_relay_client(int argc, char** argv) {
  (void)argc;

  char* ip         = STDNET_IPV4_LOCALHOST;
  u16   port       = 443;
  u64   channel_id = 22;

  struct optparse opts;
  optparse_init(&opts, argv);
  int option;
  while ((option = optparse(&opts, "p:a:c:")) != -1) {
    switch (option) {
      case 'p':
        port = parse_port(opts.optarg);
        break;
      case 'a':
        ip = opts.optarg;
        break;
      case 'c':
        channel_id = atoi(opts.optarg);
        break;
      case '?':
        LOGE("unrecognized option %c", option);
        return 1;
    }
  }

  struct sockaddr_storage relay;
  CHECK0(uv_ip4_addr(ip, port, (struct sockaddr_in*)&relay));

  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  // Initiate a channel
  {
    DiscoRelayMsgInit init = {0};
    init.type              = DiscoRelayMsg_INIT;
    init.channel_id        = channel_id;
    uv_buf_t buf           = UvBuf(BytesObj(init));
    LOG("init channel");
    CHECK0(uvco_udp_send(&udp, &buf, 1, (struct sockaddr*)&relay));
  }

  // Listen for the ack
  UvcoUdpRecv recv;
  CHECK0(uvco_udp_recv_start(&recv, &udp));
  CHECK(uvco_udp_recv_next(&recv) >= 0);
  CHECK(recv.buf.len == 1);
  CHECK(recv.buf.base[0] == 0);
  LOG("acked");

  // Post to the channel
  {
    u8                 msg_buf[sizeof(DiscoRelayMsgPost) + 1];
    DiscoRelayMsgPost* post = (void*)msg_buf;
    ZERO(post);
    post->type                         = DiscoRelayMsg_POST;
    post->channel_id                   = channel_id;
    post->payload_len                  = 1;
    msg_buf[sizeof(DiscoRelayMsgPost)] = 88;
    uv_buf_t buf                       = UvBuf(BytesArray(msg_buf));
    LOG("post to channel");
    CHECK0(uvco_udp_send(&udp, &buf, 1, (struct sockaddr*)&relay));
  }

  // Listen for the forward
  CHECK(uvco_udp_recv_next(&recv) >= 0);
  CHECK(recv.buf.len == 1);
  CHECK(recv.buf.base[0] == 88);
  LOG("forwarded");

  uv_udp_recv_stop(&udp);
  uvco_close((uv_handle_t*)&udp);

  return 0;
}

static void parse_pk(CryptoSignPK* key, const char* s) {
  usize binlen;
  CHECK0(sodium_hex2bin((u8*)key, sizeof(*key), s, strlen(s), 0, &binlen, 0));
  CHECK(binlen == sizeof(*key));
}

static void parse_sk(CryptoSignSK* key, const char* s) {
  usize binlen;
  CHECK0(sodium_hex2bin((u8*)key, sizeof(*key), s, strlen(s), 0, &binlen, 0));
  CHECK(binlen == sizeof(*key));
}

typedef struct {
  Allocator  al;
  uv_loop_t* loop;
  u16        port;
  Str        code;
  IpStr      disco;
} P2PCtxOptions;

typedef enum {
  P2PMsgIp,
  P2PMsgPing,
  P2PMsgPong,
  P2PMsgDone,
  P2PMsg_MAX,
} P2PMsgType;

const char* P2PMsgType_strs[P2PMsg_MAX] = {
    "IP",
    "PING",
    "PONG",
    "DONE",
};

#define PRIP2PMsgType    "s"
#define P2PMsgTypePRI(t) (P2PMsgType_strs[(t)])

typedef struct __attribute__((packed)) {
  P2PMsg_FIELDS;
  u16   request;
  IpMsg ip;
} DiscoIp;

typedef struct __attribute__((packed)) {
  P2PMsg_FIELDS;
  u64 channel;
  u64 sender;
} DiscoPing;

typedef struct __attribute__((packed)) {
  P2PMsg_FIELDS;
  u64 channel;
  u64 sender;
  u64 receiver;
} DiscoPong;

typedef struct __attribute__((packed)) {
  P2PMsg_FIELDS;
  u64 channel;
  u64 sender;
  u64 receiver;
} DiscoDone;

size_t P2PMsg_SZ[P2PMsg_MAX] = {
    sizeof(DiscoIp),
    sizeof(DiscoPing),
    sizeof(DiscoPong),
    sizeof(DiscoDone),
};

typedef struct {
  u64                     id;
  Allocator               al;
  CocoPool                pool;
  uv_loop_t*              loop;
  uv_udp_t                udp;
  Str                     code;
  struct sockaddr_storage me_storage;
  struct sockaddr*        me;
  struct sockaddr_storage disco_storage;
  struct sockaddr*        disco;
  bool                    me_public_present;
  struct sockaddr_storage me_public_storage;
  struct sockaddr*        me_public;
  bool                    upnp_port_present;
  u16                     upnp_port;
  Queue2 waiters[P2PMsg_MAX];  // CocoWait, queue of waiters per message type
} P2PCtx;

void P2PCtx_bind(P2PCtx* ctx, u16 port) {
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, port, (struct sockaddr_in*)ctx->me));
  CHECK0(uv_udp_bind(&ctx->udp, ctx->me, 0));

  int me_len = sizeof(ctx->me_storage);
  CHECK0(uv_udp_getsockname(&ctx->udp, ctx->me, &me_len));

  IpStrStorage s;
  CHECK0(IpStr_read(&s, ctx->me));
  LOG("bound to %" PRIIpStr, IpStrPRI(s));
}

void P2PCtx_add_disco(P2PCtx* ctx, IpStr ip) {
  LOG("adding disco server %" PRIIpStr, IpStrPRI(ip));
  ctx->disco->sa_family = AF_INET;
  CHECK0(
      uv_ip4_addr((char*)ip.ip.buf, ip.port, (struct sockaddr_in*)ctx->disco));
}

int P2PCtx_await(P2PCtx* ctx, P2PMsgType mtype, UvcoUdpRecv** recv,
                 usize timeout_ms) {
  CocoWait wait = CocoWait();
  q2_enq(&ctx->waiters[mtype], &wait.node);

  int rc = uvco_await_timeout(ctx->loop, &wait, timeout_ms);
  if (rc == 0) {
    *recv = wait.data;
    return 0;
  } else {
    q2_del(&ctx->waiters[mtype], &wait.node);
  }
  return rc;
}

void P2PCtx_ping_listener(void* arg) {
  P2PCtx* ctx = arg;

  UvcoUdpRecv* recv;
  while (1) {
    int rc = P2PCtx_await(ctx, P2PMsgPing, &recv, 1000);
    if (rc == UV_ETIMEDOUT)
      continue;
    CHECK0(rc);

    if (!(recv->buf.len == sizeof(DiscoPing) &&
          recv->buf.base[0] == P2PMsgPing))
      continue;

    DiscoPing* ping = (void*)recv->buf.base;
    log_sockaddr("PING from", recv->addr);
    LOG("PING channel=%" PRIu64 " sender=%" PRIu64, ping->channel,
        ping->sender);

    // Send back a pong
    DiscoPong pong = {0};
    pong.type      = P2PMsgPong;
    pong.channel   = ping->channel;
    pong.sender    = ctx->id;
    pong.receiver  = ping->sender;

    uv_buf_t buf = UvBuf(BytesObj(pong));
    CHECK0(uvco_udp_send(&ctx->udp, &buf, 1, recv->addr));

    rc = P2PCtx_await(ctx, P2PMsgDone, &recv, 1000);
    if (rc == UV_ETIMEDOUT)
      continue;
    CHECK0(rc);

    LOG("DONE: connected!");

    // Connected!
    CHECK(false, "unimpl");
  }
}

void P2PCtx_init(P2PCtx* ctx, const P2PCtxOptions* opts) {
  ZERO(ctx);

  ctx->al        = opts->al;
  ctx->code      = opts->code;
  ctx->me        = (void*)&ctx->me_storage;
  ctx->disco     = (void*)&ctx->disco_storage;
  ctx->me_public = (void*)&ctx->me_public_storage;
  ctx->loop      = opts->loop;

  randombytes_buf(&ctx->id, sizeof(ctx->id));
  LOG("id=%" PRIu64, ctx->id);

  CHECK0(CocoPool_init(&ctx->pool, 16, 1024 * 16, ctx->al));
  CHECK0(uv_udp_init(opts->loop, &ctx->udp));
  P2PCtx_bind(ctx, opts->port);

  P2PCtx_add_disco(ctx, opts->disco);

  plum_config_t config = {0};
  config.log_level     = PLUM_LOG_LEVEL_WARN;
  plum_init(&config);

  CHECK0(CocoPool_gonow(&ctx->pool, P2PCtx_ping_listener, ctx));
}

void P2PCtx_deinit(P2PCtx* ctx) {
  // TODO: destroy plum mapping
  CHECK(false, "unimpl");
}

void P2PCtx_listener(void* arg) {
  P2PCtx* ctx = arg;

  UvcoUdpRecv recv;
  CHECK0(uvco_udp_recv_start(&recv, &ctx->udp));
  while (1) {
    CHECK0(uvco_udp_recv_next(&recv));

    if (recv.buf.len < 1)
      continue;
    if (recv.buf.base[0] >= P2PMsg_MAX)
      continue;

    P2PMsgType type = recv.buf.base[0];
    if (recv.buf.len != P2PMsg_SZ[type])
      continue;

    LOG("incoming p2p msg type=%" PRIP2PMsgType, P2PMsgTypePRI(type));
    Node2* n;
    q2_drain(&ctx->waiters[type], n, {
      CocoWait* wait = CONTAINER_OF(n, CocoWait, node);
      wait->data     = &recv;
      COCO_DONE(wait);
    });
  }
}

void P2PCtx_start_listener(P2PCtx* ctx) {
  CHECK0(CocoPool_gonow(&ctx->pool, P2PCtx_listener, ctx));
}

void P2PCtx_disco_getip(P2PCtx* ctx) {
  DiscoRelayMsgIp msgip = {0};
  msgip.type            = DiscoRelayMsg_IP;

  int          i  = 0;
  int          rc = UV_ETIMEDOUT;
  UvcoUdpRecv* recv;
  while (i < 3) {
    // Send request to Disco
    uv_buf_t buf = UvBuf(BytesObj(msgip));
    CHECK0(uvco_udp_send(&ctx->udp, &buf, 1, ctx->disco));

    // Wait for reply
    rc = P2PCtx_await(ctx, P2PMsgIp, &recv, 1000);
    if (rc == UV_ETIMEDOUT)
      continue;
    else
      break;

    i += 1;
  }

  CHECK0(rc);
  CHECK(recv->buf.len == sizeof(IpMsg));

  // Fill me_public
  IpMsg* public_ip = (IpMsg*)recv->buf.base;
  CHECK0(IpMsg_dump(ctx->me_public, public_ip));
  ctx->me_public_present = true;
}

void P2PCtx_pingpong(P2PCtx* ctx) { CHECK(false, "unimpl"); }

void P2PCtx_pingpong_relay(P2PCtx* ctx) { CHECK(false, "unimpl"); }

void P2PCtx_disco_channel(P2PCtx* ctx) { CHECK(false, "unimpl"); }

void P2PCtx_disco_dance(P2PCtx* ctx, usize timeout_secs, bool* connected) {
  CHECK(false, "unimpl");
}

void P2PCtx_local_validate(P2PCtx* ctx, u64 channel, UvcoUdpRecv* recv,
                           bool* connected) {
  {
    Bytes msg = UvBytes(recv->buf);
    if (msg.len != sizeof(DiscoLocalAdvert))
      return;
    DiscoLocalAdvert* advert = (void*)msg.buf;
    if (advert->id != channel)
      return;
  }

  // Match, validate route
  log_sockaddr("match from", recv->addr);

  DiscoPing ping = {0};
  ping.type      = P2PMsgPing;
  ping.channel   = channel;
  ping.sender    = ctx->id;

  int i = 0;
  int rc;
  while (i < 3) {
    uv_buf_t buf = UvBuf(BytesObj(ping));
    UVCHECK(uvco_udp_send(&ctx->udp, &buf, 1, recv->addr));
    rc = P2PCtx_await(ctx, P2PMsgPong, &recv, 1000);
    if (rc == 0)
      break;
    CHECK(rc == UV_ETIMEDOUT);
    ++i;
  }

  CHECK0(rc);

  DiscoPong* pong = (void*)recv->buf.base;

  DiscoDone done = {0};
  done.type      = P2PMsgDone;
  done.channel   = channel;
  done.sender    = ctx->id;
  done.receiver  = pong->sender;

  uv_buf_t buf = UvBuf(BytesObj(done));
  UVCHECK(uvco_udp_send(&ctx->udp, &buf, 1, recv->addr));

  LOG("PONG: connected!");
  *connected = true;
}

void P2PCtx_disco_local(P2PCtx* ctx, usize timeout_secs, bool* connected) {
  (void)disco_channel_mutual;
  (void)disco_channel_peer;
  (void)disco_channel_generic;

  *connected = false;
  CHECK(timeout_secs > 0);
  i64 expiry = stdtime_now_monotonic_ms() + (timeout_secs * 1000);

  // Determine our channel code
  u64 channel = disco_channel_code(ctx->code);

  struct sockaddr_in multicast_addr;
  disco_multicast4_derive(&multicast_addr, channel);
  log_sockaddr("multicast channel", (struct sockaddr*)&multicast_addr);

  struct sockaddr_in me;
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY,
                     stdnet_getport((struct sockaddr*)&multicast_addr), &me));
  log_sockaddr("multicast bind", (struct sockaddr*)&me);

  // Bind to the multicast port
  uv_udp_t udp;
  CHECK0(uv_udp_init(ctx->loop, &udp));
  UVCHECK(uv_udp_bind(&udp, (struct sockaddr*)&me, UV_UDP_REUSEADDR));

  // Join the multicast group
  IpStrStorage mstr;
  CHECK0(IpStr_read(&mstr, (struct sockaddr*)&multicast_addr));
  UVCHECK(uv_udp_set_membership(&udp, (char*)mstr.ip.buf, NULL, UV_JOIN_GROUP));

  UvcoUdpRecv recv;
  UVCHECK(uvco_udp_recv_start(&recv, &udp));
  i64 now = stdtime_now_monotonic_ms();

  // Jitter
  {
    u8 jitter;
    randombytes_buf(&jitter, 1);
    uvco_sleep(ctx->loop, jitter);
  }

  while (now < expiry) {
    LOG("local tick");
    // Advertise on multicast address...
    {
      DiscoLocalAdvert advert = {0};
      advert.id               = channel;
      uv_buf_t buf            = UvBuf(BytesObj(advert));
      UVCHECK(
          uvco_udp_send(&ctx->udp, &buf, 1, (struct sockaddr*)&multicast_addr));
    }

    // Skip our own message, which we expect to come through ~instantly
    CHECK0(uvco_udp_recv_next2(&recv, 1));

    // Listen for 1s...
    int rc = uvco_udp_recv_next2(&recv, 1000);
    if (rc == 0) {
      // ok
      P2PCtx_local_validate(ctx, channel, &recv, connected);
      if (*connected)
        break;
    } else if (rc == UV_ETIMEDOUT) {
      // timed out
    } else {
      UVCHECK(rc);
    }

    // Throttle
    i64 tick = now + 1000;
    now      = stdtime_now_monotonic_ms();
    if (now < tick) {
      LOG("sleep %d", (int)(tick - now));
      uvco_sleep(ctx->loop, tick - now);
    }
  }
}

void P2PCtx_upnp(P2PCtx* ctx) {
  PlumCtx pctx       = {0};
  pctx.internal_port = stdnet_getport(ctx->me);
  CHECK0(uvco_arun(ctx->loop, async_plumfn, &pctx));
  ctx->upnp_port = pctx.external_port;
  if (ctx->upnp_port)
    ctx->upnp_port_present = true;
}

// cli demo-disco p2p -i -p20000 -ca1b2c3 -d:30000
static int disco_p2p(int argc, char** argv) {
  LOG("");
  // Alice and Bob want to connect

  u16          port         = 0;
  Str          channel_code = {0};
  IpStrStorage disco_str    = {0};
  CryptoSignPK alice        = {0};
  CryptoSignPK bob          = {0};
  CryptoSignSK sk           = {0};
  bool         is_alice     = false;

  struct optparse opts;
  optparse_init(&opts, argv);
  int option;
  while ((option = optparse(&opts, "ip:c:d:b:a:s:")) != -1) {
    switch (option) {
      case 'i':
        // Initiator
        is_alice = true;
        break;
      case 'p':
        // Port
        port = parse_port(opts.optarg);
        break;
      case 'c':
        // Channel
        channel_code = Str0(opts.optarg);
        CHECK(channel_code.len >= 6);
        break;
      case 'd':
        // Disco
        CHECK0(IpStr_fromstr(&disco_str, opts.optarg));
        break;
      case 'b':
        // Bob
        parse_pk(&bob, opts.optarg);
        break;
      case 'a':
        // Alice
        parse_pk(&alice, opts.optarg);
        break;
      case 's':
        // SK
        parse_sk(&sk, opts.optarg);
        break;
      case '?':
        LOGE("unrecognized option %c", option);
        return 1;
    }
  }

  (void)is_alice;

  P2PCtxOptions p2p_opts = {
      .loop  = loop,
      .port  = port,
      .al    = allocatormi_allocator(),
      .code  = channel_code,
      .disco = *(IpStr*)&disco_str,
  };

  P2PCtx ctx;
  P2PCtx_init(&ctx, &p2p_opts);

  P2PCtx_start_listener(&ctx);

  bool connected = false;
  P2PCtx_disco_local(&ctx, 30, &connected);

  if (connected) {
    P2PCtx_pingpong(&ctx);
    return 0;
  }

  P2PCtx_disco_getip(&ctx);
  P2PCtx_upnp(&ctx);
  P2PCtx_disco_channel(&ctx);

  P2PCtx_disco_dance(&ctx, 30, &connected);

  if (connected) {
    P2PCtx_pingpong(&ctx);
    return 0;
  }

  P2PCtx_pingpong_relay(&ctx);

  P2PCtx_deinit(&ctx);
  return 0;
}

static const CliCmd disco_commands[] = {
    {"disco", disco_server},               //
    {"relay-client", disco_relay_client},  //
    {"p2p", disco_p2p},                    //
    {0},
};

int demo_disco(int argc, char** argv) {
  LOG("");

  if (argc < 2) {
    fprintf(stderr, "missing subcommand\n");
    cli_usage("disco", disco_commands, 0);
    return 1;
  }

  argc -= 1;
  argv += 1;

  return cli_dispatch("disco", disco_commands, argc, argv);
}
