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

static u16 parse_port(char* port_str) {
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

static void multicast_ipv4_addr_derive(struct sockaddr_in* addr, Bytes in) {
  u8 h[5];
  CHECK0(crypto_generichash_blake2b(h, sizeof(h), in.buf, in.len, 0, 0));

  addr->sin_family = AF_INET;

  // First 2 bytes are used for the port
  // Windows, Mac use >=49152
  // Linux uses <=60999
  u16 port       = *(u16*)h;
  addr->sin_port = 49152 + (port % (60999 - 49152));

  // Last 3 bytes are used for the IP
  u8* ip = (u8*)&addr->sin_addr;
  ip[0]  = 239;
  ip[1]  = h[2];
  ip[2]  = h[3];
  ip[3]  = h[4];
}

static void multicast_ipv4_addr_all(struct sockaddr_in* addr) {
  // 239.18.132.107:35544
  multicast_ipv4_addr_derive(addr, Str("pk-multicast"));
}

static void multicast_ipv4_addr_peer(struct sockaddr_in* addr,
                                     const CryptoSignPK* pk) {
  multicast_ipv4_addr_derive(addr, BytesObj(*pk));
}

static void multicast_ipv4_addr_channel(struct sockaddr_in* addr,
                                        Str                 channel_id) {
  multicast_ipv4_addr_derive(addr, channel_id);
}

static void multicast_ipv4_addr_peer_mutual(struct sockaddr_in*    addr,
                                            const CryptoKxKeypair* me,
                                            const CryptoKxPK*      bob) {
  // memcmp OK: public key
  CryptoKxTx shared;
  if (memcmp(&me->pk, bob, sizeof(*bob)) > 0) {
    CHECK0(crypto_kx_server_session_keys((u8*)&shared, 0, (u8*)&me->pk,
                                         (u8*)&me->sk, (u8*)bob));
  } else {
    CHECK0(crypto_kx_client_session_keys((u8*)&shared, 0, (u8*)&me->pk,
                                         (u8*)&me->sk, (u8*)bob));
  }

  u8 subkey[32];
  STATIC_CHECK(sizeof(shared) == crypto_kdf_blake2b_KEYBYTES);
  CHECK0(crypto_kdf_blake2b_derive_from_key(subkey, sizeof(subkey), 1,
                                            "pk-multi", (u8*)&shared));

  multicast_ipv4_addr_derive(addr, BytesArray(subkey));
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
  (void)multicast_ipv4_addr_peer;
  (void)multicast_ipv4_addr_peer_mutual;

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
    // Determine our multicast address
    if (channel.len > 0)
      multicast_ipv4_addr_channel(&ctx.multicast_addr, channel);
    else
      multicast_ipv4_addr_all(&ctx.multicast_addr);
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

void handle_giveip(void* arg) {
  UvcoUdpRecv* recv = arg;
  IpMsg        msg;
  CHECK0(IpMsg_read(&msg, recv->addr));

  IpStrStorage sender;
  CHECK0(IpStr_read(&sender, recv->addr));
  LOG("sender=%" PRIIpStr, IpStrPRI(sender));

  struct sockaddr addr = *recv->addr;
  uv_buf_t        buf  = UvBuf(BytesObj(msg));
  CHECK0(uvco_udp_send(recv->udp, &buf, 1, &addr));
}

static int disco_giveip(int argc, char** argv) {
  LOG("");

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
        int iport = atoi(options.optarg);
        CHECK(iport <= UINT16_MAX);
        port = (u16)iport;
      } break;
      case '?':
        cli_usage("disco giveip", 0, longopts);
        return 1;
    }
  }

  log_local_interfaces();

  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));
  struct sockaddr_storage me;
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, port, (struct sockaddr_in*)&me));
  CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&me, UV_UDP_REUSEADDR));
  port = udp_getsockport(&udp);
  LOG("me=%s:%d", STDNET_IPV4_ANY, port);

  Allocator al = allocatormi_allocator();

  CocoPool pool;
  CHECK0(CocoPool_init(&pool, 64, 1024 * 4, al));

  UvcoUdpRecv recv;
  CHECK0(uvco_udp_recv_start(&recv, &udp));
  while (1) {
    CHECK(uvco_udp_recv_next(&recv) >= 0);
    CHECK0(CocoPool_go(&pool, handle_giveip, &recv));
  }

  uvco_close((uv_handle_t*)&udp);
  CocoPool_deinit(&pool);
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
  MIN(sizeof(DiscoRelayMsgInit), sizeof(DiscoRelayMsgPost))
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
  Bytes msg = UvBytes(recv->buf);

  if (msg.len < DISCO_MIN_MSG_SZ)
    return;
  if (msg.len > DISCO_MAX_MSG_SZ)
    return;

  if (msg.buf[0] >= DiscoRelayMsg_N)
    return;
  DiscoRelayMsgType type = msg.buf[0];

  CocoFn handlers[DiscoRelayMsg_N] = {
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

static int disco_relay(int argc, char** argv) {
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
  port = udp_getsockport(&ctx.udp);
  LOG("me=%s:%d", STDNET_IPV4_ANY, port);

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
        channel_id = parse_port(opts.optarg);
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

static const CliCmd disco_commands[] = {
    {"local", disco_local},                //
    {"plum", disco_plum},                  //
    {"giveip", disco_giveip},              //
    {"relay", disco_relay},                //
    {"relay-client", disco_relay_client},  //
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
