#include "cli.h"
#include "log.h"
#include "minicoro.h"
#include "optparse.h"
#include "uv.h"
#include "uvco.h"

extern uv_loop_t* loop;

typedef struct {
  char ip_buf[INET6_ADDRSTRLEN];
  Str ip;
  int port;
} IpStr;

const void* sa_get_in_addr(const struct sockaddr* sa) {
  switch (sa->sa_family) {
    case AF_INET: {
      const struct sockaddr_in* sa_in = (const struct sockaddr_in*)sa;
      return &sa_in->sin_addr;
    }
    case AF_INET6: {
      const struct sockaddr_in6* sa_in6 = (const struct sockaddr_in6*)sa;
      return &sa_in6->sin6_addr;
    }
    default:
      return 0;
  }
}

static int sa_get_port(const struct sockaddr* sa) {
  switch (sa->sa_family) {
    case AF_INET: {
      const struct sockaddr_in* sa_in = (const struct sockaddr_in*)sa;
      return ntohs(sa_in->sin_port);
    }
    case AF_INET6: {
      const struct sockaddr_in6* sa_in6 = (const struct sockaddr_in6*)sa;
      return ntohs(sa_in6->sin6_port);
    }
    default:
      return 0;
  }
}

static void IpStr_log(const IpStr* s, Str tag) {
  LOG("%.*s=%.*s:%d", (int)tag.len, tag.buf, (int)s->ip.len, s->ip.buf,
      s->port);
}

static int IpStr_read(IpStr* out, const struct sockaddr* sa) {
  const void* addr = sa_get_in_addr(sa);
  if (addr == NULL)
    return 1;

  if (inet_ntop(sa->sa_family, addr, out->ip_buf, sizeof(out->ip_buf)) == NULL)
    return 1;
  out->ip = Bytes(out->ip_buf, strlen(out->ip_buf));
  out->port = sa_get_port(sa);
  return 0;
}

static void handle_message(UvcoUdpRecv* recv) {
  Str msg = Bytes(recv->buf.base, recv->buf.len);

  IpStr ip_str;
  CHECK0(IpStr_read(&ip_str, recv->addr));

  IpStr_log(&ip_str, Str("source="));
  LOGS(msg);

  CHECK0(uvco_udp_send(recv->udp, &recv->buf, 1, recv->addr));
}

static void handle_message_co(mco_coro* co) {
  UvcoUdpRecv* recv = mco_get_user_data(co);
  handle_message(recv);
}

int demo_echo(int argc, char** argv) {
  struct optparse options;
  optparse_init(&options, argv);
  int option;
  struct optparse_long longopts[] =       //
      {{"help", 'h', OPTPARSE_NONE},      //
       {"port", 'p', OPTPARSE_REQUIRED},  //
       {0}};

  int port = 0;

  while ((option = optparse_long(&options, longopts, NULL)) != -1) {
    switch (option) {
      case 'h':
        cli_usage("echo", 0, longopts);
        return 1;
      case 'p':
        port = atoi(options.optarg);
        break;
      case '?':
        cli_usage("echo", 0, longopts);
        return 1;
    }
  }

  CHECK(port > 0);
  LOG("port=%d", port);

  // Create UDP
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  // Bind to the port
  struct sockaddr_in myaddr;
  CHECK0(uv_ip4_addr("0.0.0.0", port, &myaddr));
  CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&myaddr, 0));

  IpStr me;
  IpStr_read(&me, (const struct sockaddr*)(&myaddr));
  IpStr_log(&me, Str("me"));

  // This coroutine will only be responsible for fielding incoming messages
  // and spawning a handler coroutine.
  LOG("Listening on port %d...", port);
  UvcoUdpRecv recv = {0};
  CHECK0(uvco_udp_recv_start(&recv, &udp));
  while (1) {
    CHECK(uvco_udp_recv_next(&recv) >= 0);

    // We can handle the message in-line here
    // Note that if this handler in turn suspends, which it does because it
    // echoes back the message, then other messages that arrive in the meantime
    // would be dropped because there is no active waiter.
    handle_message(&recv);

    // To get concurrent request handling, we use this coroutine to hand off
    // the request to other coroutines. That leaves this coroutine free to
    // handle requests as they come in.

    (void)handle_message_co;

    // // Spawn a handler coroutine
    // mco_desc desc = mco_desc_init(handle_message_co, 4096 * 4);
    // desc.user_data = &recv;
    // mco_coro* co;
    // CHECK0(mco_create(&co, &desc));
    // CHECK0(mco_resume(co));
  }

  // Max number of handlers, handler pool
  // Preallocate handlers and their stacks
  // How does a coroutine get cleaned up? At the end of its execution it needs
  // to notify someone. Then in the main loop maybe there's a reclaim call.

  return 0;
}
