#include "cli.h"
#include "log.h"
#include "minicoro.h"
#include "optparse.h"
#include "uv.h"
#include "uvco.h"

extern uv_loop_t* loop;

static void handle_message2(UvcoUdpRecv* recv) {
  LOGS(Bytes(recv->buf.base, recv->buf.len));
  CHECK0(uvco_udp_send(recv->udp, &recv->buf, 1, recv->addr));
}

static void handle_message(mco_coro* co) {
  UvcoUdpRecv* recv = mco_get_user_data(co);
  handle_message2(recv);
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

  LOG("port=%d", port);

  // Create UDP
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  // Bind to the port
  struct sockaddr_in myaddr;
  CHECK0(uv_ip4_addr("0.0.0.0", port, &myaddr));
  CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&myaddr, 0));

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
    handle_message2(&recv);

    // To get concurrent request handling, we use this coroutine to hand off
    // the request to other coroutines. That leaves this coroutine free to
    // handle requests as they come in.

    (void)handle_message;

    // // Spawn a handler coroutine
    // mco_desc desc = mco_desc_init(handle_message, 4096 * 4);
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
