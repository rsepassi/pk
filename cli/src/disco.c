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
#include "uvco.h"

extern uv_loop_t* loop;

static void log_sockaddr(const char* tag, struct sockaddr* addr) {
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
  addr->sin_port = 49152 + (port % (60999 - 49152));

  // Next 3 bytes are used for the IP
  u8* ip = (u8*)&addr->sin_addr;
  ip[0]  = 239;
  ip[1]  = h[2];
  ip[2]  = h[3];
  ip[3]  = h[4];
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

static void advertco_fn(void* data) {
  DiscoLocalCtx* ctx = data;

  DiscoLocalAdvert advert = {0};
  advert.id               = ctx->id;

  while (1) {
    uv_buf_t buf = UvBuf(BytesObj(advert));
    int      rc  = uvco_udp_send(&ctx->udp, &buf, 1,
                                 (struct sockaddr*)&ctx->multicast_addr);
    if (rc != 0)
      LOG("err=%s", uv_strerror(rc));
    uvco_sleep(loop, 1000);
  }
}

static int disco_local(int argc, char** argv) {
  LOG("");

  (void)disco_channel_peer;

  struct optparse options;
  optparse_init(&options, argv);
  int                  option;
  struct optparse_long longopts[] =  //
      {
          {"advertise", 'a', OPTPARSE_NONE},    //
          {"channel", 'c', OPTPARSE_REQUIRED},  //
          {0}                                   //
      };

  bool advertise = false;
  Str  channel   = {0};

  while ((option = optparse_long(&options, longopts, NULL)) != -1) {
    switch (option) {
      case 'a':
        advertise = true;
        break;
      case 'c':
        channel = Str0(options.optarg);
        break;
      case '?':
        cli_usage("disco local", 0, longopts);
        return 1;
    }
  }

  IpStrStorage  multicast_addrs;
  DiscoLocalCtx ctx = {0};
  {
    u64 channel_id;
    // Determine our multicast address
    if (channel.len > 0)
      channel_id = disco_channel_code(channel);
    else
      channel_id = disco_channel_generic();

    disco_multicast4_derive(&ctx.multicast_addr, channel_id);

    CHECK0(IpStr_read(&multicast_addrs, (struct sockaddr*)&ctx.multicast_addr));
    ctx.multicast_addrs = *(IpStr*)&multicast_addrs;
    LOG("multicast=%" PRIIpStr, IpStrPRI(multicast_addrs));
    // Initialize UDP handles
    CHECK0(uv_udp_init(loop, &ctx.multicast_udp));
    CHECK0(uv_udp_init(loop, &ctx.udp));
    randombytes_buf(&ctx.id, sizeof(ctx.id));
  }

  log_local_interfaces();

  // Bind to know our own local port
  {
    struct sockaddr_storage me;
    CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, 0, (struct sockaddr_in*)&me));
    CHECK0(uv_udp_bind(&ctx.udp, (struct sockaddr*)&me, UV_UDP_REUSEADDR));
    ctx.port = udp_getsockport(&ctx.udp);
    LOG("me=%s:%d", STDNET_IPV4_ANY, ctx.port);
  }

  // Advertise on the multicast group if requested
  mco_coro* advertco = 0;
  if (advertise)
    CHECK0(coco_go(&advertco, 0, advertco_fn, &ctx));

  // Listen on the multicast group
  struct sockaddr_storage multicast_me;
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, ctx.multicast_addrs.port,
                     (struct sockaddr_in*)&multicast_me));
  CHECK0(uv_udp_bind(&ctx.multicast_udp, (struct sockaddr*)&multicast_me,
                     UV_UDP_REUSEADDR));
  CHECK0(uv_udp_set_membership(&ctx.multicast_udp,
                               (char*)ctx.multicast_addrs.ip.buf, NULL,
                               UV_JOIN_GROUP));
  UvcoUdpRecv recv;
  CHECK0(uvco_udp_recv_start(&recv, &ctx.multicast_udp));
  while (1) {
    CHECK(uvco_udp_recv_next(&recv) >= 0);
    if (recv.buf.len != sizeof(DiscoLocalAdvert)) {
      LOG("malformed advert");
      continue;
    }
    DiscoLocalAdvert* advert = (void*)recv.buf.base;

    if (advert->id == ctx.id)
      continue;

    IpStrStorage sender;
    CHECK0(IpStr_read(&sender, recv.addr));
    LOG("sender=%" PRIIpStr, IpStrPRI(sender));
    LOG("id=%" PRIu64, advert->id);
  }

  uvco_close((uv_handle_t*)&ctx.udp);
  uvco_close((uv_handle_t*)&ctx.multicast_udp);

  return 0;
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

static int disco_plum(int argc, char** argv) {
  struct optparse options;
  optparse_init(&options, argv);
  int                  option;
  struct optparse_long longopts[] =  //
      {
          {"port", 'p', OPTPARSE_REQUIRED},  //
          {0}                                //
      };

  u16 port = 0;

  while ((option = optparse_long(&options, longopts, NULL)) != -1) {
    switch (option) {
      case 'p': {
        port = parse_port(options.optarg);
      } break;
      case '?':
        cli_usage("disco plum", 0, longopts);
        return 1;
    }
  }

  // UDP init
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  // Plum init
  plum_config_t config = {0};
  config.log_level     = PLUM_LOG_LEVEL_WARN;
  plum_init(&config);

  // Bind to know our own local port
  struct sockaddr_storage me;
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, port, (struct sockaddr_in*)&me));
  CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&me, 0));
  port = udp_getsockport(&udp);
  LOG("me=%s:%d", STDNET_IPV4_ANY, port);

  // Plum
  PlumCtx ctx       = {0};
  ctx.internal_port = port;
  CHECK0(uvco_arun(loop, async_plumfn, &ctx));
  CHECK(ctx.external_port, "no external port acquired");
  LOG("port=%d->%d", ctx.external_port, ctx.internal_port);

  // Listen
  UvcoUdpRecv recv;
  CHECK0(uvco_udp_recv_start(&recv, &udp));
  while (1) {
    CHECK(uvco_udp_recv_next(&recv) >= 0);

    IpStrStorage sender;
    CHECK0(IpStr_read(&sender, recv.addr));
    LOG("sender=%" PRIIpStr, IpStrPRI(sender));
    break;
  }
  uv_udp_recv_stop(&udp);

  plum_destroy_mapping(ctx.mapping_id);
  uvco_close((uv_handle_t*)&udp);

  return 0;
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
  u8 type;
  u8 reserved[3];
} DiscoRelayMsgIp;

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

static int parse_ipport(IpStr* out, const char* s) {
  char* colon = strrchr(s, ':');
  if (colon == NULL) {
    out->port = parse_port(s);
    out->ip   = Str(STDNET_IPV4_LOCALHOST);
  } else {
    out->port = parse_port(colon + 1);
    out->ip   = Bytes(s, colon - s);
  }
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

static void addr_read(struct sockaddr* addr, IpStr ip) {
  addr->sa_family = AF_INET;
  char ip_buf[STDNET_INET6_ADDRSTRLEN];
  memcpy(ip_buf, ip.ip.buf, ip.ip.len);
  ip_buf[ip.ip.len] = 0;
  CHECK0(uv_ip4_addr(ip_buf, ip.port, (struct sockaddr_in*)addr));
}

static int disco_p2p(int argc, char** argv) {
  LOG("");
  // Alice wants to allow Bob to connect to her

  u16          port         = 0;
  Str          channel_code = {0};
  IpStr        disco        = {0};
  CryptoSignPK alice        = {0};
  CryptoSignPK bob          = {0};
  CryptoSignSK sk           = {0};
  bool         initiator    = false;

  struct optparse opts;
  optparse_init(&opts, argv);
  int option;
  while ((option = optparse(&opts, "ip:c:d:b:a:s:")) != -1) {
    switch (option) {
      case 'i':
        // Initiator
        initiator = true;
        break;
      case 'p':
        // Port
        port = parse_port(opts.optarg);
        break;
      case 'c':
        // Channel
        channel_code = Str0(opts.optarg);
        break;
      case 'd':
        // Disco
        CHECK0(parse_ipport(&disco, opts.optarg));
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

  struct sockaddr_storage disco_addr;
  addr_read((struct sockaddr*)&disco_addr, disco);
  log_sockaddr("disco", (struct sockaddr*)&disco_addr);

  Allocator al = allocatormi_allocator();
  CocoPool pool;
  CHECK0(CocoPool_init(&pool, 8, 1024 * 4, al));

  // This is the port that we ultimately want to have connect to Bob
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  // Bind to the passed port
  struct sockaddr_storage me;
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, port, (struct sockaddr_in*)&me));
  CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&me, 0));
  port                                 = udp_getsockport(&udp);
  ((struct sockaddr_in*)&me)->sin_port = htons(port);
  log_sockaddr("me", (struct sockaddr*)&me);

  // Start listening
  UvcoUdpRecv recv;
  CHECK0(uvco_udp_recv_start(&recv, &udp));

  // Contact Disco to get our public IP+port
  IpMsg public_ip;
  {
    LOG("query disco for public ip");
    DiscoRelayMsgIp msgip = {0};
    msgip.type            = DiscoRelayMsg_IP;
    uv_buf_t buf          = UvBuf(BytesObj(msgip));
    CHECK0(uvco_udp_send(&udp, &buf, 1, (struct sockaddr*)&disco_addr));
    CHECK0(uvco_udp_recv_next(&recv));
    CHECK(recv.buf.len == sizeof(IpMsg));
    public_ip = *(IpMsg*)recv.buf.base;

    IpStrStorage ips;
    CHECK0(IpStr_frommsg(&ips, &public_ip));
    LOG("publicip=%" PRIIpStr, IpStrPRI(ips));
  }

  // If we're the initiator (Alice), create 3 channels on Disco
  // * A code channel
  // * An Alice-specific channel
  // * An Alice+Bob-specific channel
  u64 chan_peer   = disco_channel_peer(&alice);
  u64 chan_mutual = disco_channel_mutual(&alice, &sk, &bob);
  u64 chan_code   = disco_channel_code(channel_code);
  if (initiator) {
    u64               channels[3] = {chan_peer, chan_mutual, chan_code};
    DiscoRelayMsgInit inits[3]    = {0};
    uv_buf_t          bufs[3];

    LOG("init channels");
    for (int i = 0; i < 3; ++i) {
      LOG("channel %" PRIu64, channels[i]);
      inits[i].type       = DiscoRelayMsg_INIT;
      inits[i].channel_id = channels[i];
      bufs[i]             = UvBuf(BytesObj(inits[i]));
      uvco_sleep(loop, 20);
      CHECK0(uvco_udp_send(&udp, &bufs[i], 1, (struct sockaddr*)&disco_addr));
      // TODO: not checking for acks
      // TODO: keepalives
    }
  }

  // Try to open an external port
  // Plum init
  u16 upnp_port = 0;
  {
    plum_config_t config = {0};
    config.log_level     = PLUM_LOG_LEVEL_WARN;
    plum_init(&config);
    PlumCtx ctx       = {0};
    ctx.internal_port = port;
    CHECK0(uvco_arun(loop, async_plumfn, &ctx));
    upnp_port = ctx.external_port;
    if (upnp_port)
      LOG("upnp port=%d", ctx.external_port);
    // TODO: destroy plum mapping
  }

  // Initiate local discovery
  // Alice listens on the local network
  // * The generic channel
  // * An alphanum channel
  // * An Alice-specific channel
  // * An Alice+Bob-specific channel

  // At this point
  // Alice has:
  // * Retrieved her public IP+port
  // * Tried opening an external port
  // * Created and is listening on 3 channels on Disco
  // * Is listening on 4 channels locally
  // * Shared the relevant information out-of-band with Bob
  // Bob has:



  // What does Alice share with Bob?
  // Public IP+port
  // External port, if one was opened
  // Channel code
  // Keys:
  //   Identity key
  //   Short-term key
  //   Ephemeral key

  // Alice waits for Bob's IP+port on the channel
  // Alice tries Bob on his IP+port
  // Alice tries Bob on IP + random ports

  // Possible outcomes:
  // * Direct connection established
  // * Relay connection established
  // * Error

  return 0;
}

static const CliCmd disco_commands[] = {
    {"local", disco_local},                //
    {"plum", disco_plum},                  //
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
