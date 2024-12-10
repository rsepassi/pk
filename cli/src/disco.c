// Discovery

#include "allocatormi.h"
#include "cli.h"
#include "coco.h"
#include "crypto.h"
#include "log.h"
#include "plum/plum.h"
#include "sodium.h"
#include "stdnet.h"
#include "uvco.h"

extern uv_loop_t* loop;

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

  // Log our local IPV4 interfaces
  {
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
  u16         internal_port;
  u16         external_port;
  uv_async_t* async;
  int         mapping_id;
} PlumCtx;

static void mapping_callback(int id, plum_state_t state,
                             const plum_mapping_t* mapping) {
  PlumCtx* ctx = mapping->user_ptr;
  if (state == PLUM_STATE_SUCCESS)
    ctx->external_port = mapping->external_port;
  uv_async_send(ctx->async);
}

static void async_plumfn(uv_async_t* async, void* arg) {
  PlumCtx* ctx         = arg;
  ctx->async           = async;
  plum_config_t config = {0};
  config.log_level     = PLUM_LOG_LEVEL_WARN;
  plum_init(&config);
  plum_mapping_t mapping = {0};
  mapping.protocol       = PLUM_IP_PROTOCOL_UDP;
  mapping.internal_port  = ctx->internal_port;
  mapping.user_ptr       = ctx;
  ctx->mapping_id        = plum_create_mapping(&mapping, mapping_callback);
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
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  // Bind to know our own local port
  u16 port;
  {
    struct sockaddr_storage me;
    CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, 0, (struct sockaddr_in*)&me));
    CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&me, UV_UDP_REUSEADDR));
    port = udp_getsockport(&udp);
    LOG("me=%s:%d", STDNET_IPV4_ANY, port);
  }

  // Plum
  PlumCtx ctx       = {0};
  ctx.internal_port = port;
  CHECK0(uvco_arun(loop, async_plumfn, &ctx));
  LOG("port=%d->%d", ctx.external_port, ctx.internal_port);

  plum_destroy_mapping(ctx.mapping_id);
  uvco_close((uv_handle_t*)&udp);

  return 0;
}

static const CliCmd disco_commands[] = {
    {"local", disco_local},    //
    {"plum", disco_plum},      //
    {"giveip", disco_giveip},  //
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
