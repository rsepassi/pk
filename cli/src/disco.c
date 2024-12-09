// Discovery

#include "cli.h"
#include "coco.h"
#include "log.h"
#include "sodium.h"
#include "stdnet.h"
#include "uvco.h"

extern uv_loop_t* loop;

typedef struct __attribute__((packed)) {
  u64 id;
} DiscoLocalAdvert;

typedef struct {
  Str                multicast_group;
  int                multicast_port;
  uv_udp_t           multicast_udp;
  struct sockaddr_in multicast_addr;
  uv_udp_t           udp;
  int                port;
  u64                id;
} DiscoLocalCtx;

static void advertco_fn(void* data) {
  DiscoLocalCtx* ctx = data;

  DiscoLocalAdvert advert = {0};
  advert.id               = ctx->id;

  while (1) {
    uv_buf_t buf = UvBuf(BytesObj(advert));
    CHECK0(uvco_udp_send(&ctx->udp, &buf, 1,
                         (struct sockaddr*)&ctx->multicast_addr));
    uvco_sleep(loop, 1000);
  }
}

static int disco_local(int argc, char** argv) {
  LOG("");

  struct optparse options;
  optparse_init(&options, argv);
  int option;

  struct optparse_long longopts[] =        //
      {{"advertise", 'a', OPTPARSE_NONE},  //
       {0}};

  bool advertise = false;

  while ((option = optparse_long(&options, longopts, NULL)) != -1) {
    switch (option) {
      case 'a':
        advertise = true;
        break;
      case '?':
        cli_usage("disco local", 0, longopts);
        return 1;
    }
  }

  DiscoLocalCtx ctx   = {0};
  ctx.multicast_group = Str("239.0.0.22");
  ctx.multicast_port  = 20000;
  CHECK0(uv_ip4_addr((char*)ctx.multicast_group.buf, ctx.multicast_port,
                     &ctx.multicast_addr));
  CHECK0(uv_udp_init(loop, &ctx.multicast_udp));
  CHECK0(uv_udp_init(loop, &ctx.udp));
  randombytes_buf(&ctx.id, sizeof(ctx.id));

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

    int me_len = sizeof(me);
    CHECK0(uv_udp_getsockname(&ctx.udp, (struct sockaddr*)&me, &me_len));
    CHECK(me_len == sizeof(struct sockaddr_in));
    CHECK(me.ss_family == AF_INET);

    IpStrStorage me_str;
    CHECK0(IpStr_read(&me_str, (struct sockaddr*)&me));
    LOG("me=%" PRIIpStr " id=%" PRIu64, IpStrPRI(me_str), ctx.id);

    ctx.port = me_str.port;
  }

  // Advertise on the multicast group if requested
  mco_coro* advertco = 0;
  if (advertise)
    CHECK0(coco_go(&advertco, 4096, advertco_fn, &ctx));

  // Listen on the multicast group
  struct sockaddr_storage multicast_me;
  CHECK0(uv_ip4_addr(STDNET_IPV4_ANY, ctx.multicast_port,
                     (struct sockaddr_in*)&multicast_me));
  CHECK0(uv_udp_bind(&ctx.multicast_udp, (struct sockaddr*)&multicast_me,
                     UV_UDP_REUSEADDR));
  CHECK0(uv_udp_set_membership(
      &ctx.multicast_udp, (char*)ctx.multicast_group.buf, NULL, UV_JOIN_GROUP));
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

  return 0;
}

static const CliCmd disco_commands[] = {
    {"local", disco_local},  //
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
