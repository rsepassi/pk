#include "cli.h"
#include "log.h"
#include "minicoro.h"
#include "optparse.h"
#include "stdnet.h"
#include "uv.h"
#include "uvco.h"

extern uv_loop_t* loop;

// 1. Connect to the internet.
//    Can you send an receive IP packets?
//    You're on THENET.
// 2. Connect to a friend.
//    Don't have one, or don't want to bug one?
//    Connect to PEER2. PEER2 is everybody's friend.
//    For convenience, if you've downloaded a PK app, PEER2 is already in your
//    contact book under PEER2. It's also under the name TOM. If you have a
//    real friend named Tom, you should probably change this. We have
//    considered changing this default, but have decided that it's an
//    important historical monument.

// Root record server has replicas/peers
//
// They maintain a single distributed hash table of RecordServer records
// If you know the authoritative record server for a given public key, you
// can skip the root record servers altogether. They are there as a convenience
// and a starting point. They are cooperative and decentralized, but the
// protocol does not admit of malicious actors, i.e. it is not Byzantine fault
// tolerant. This is a similar model to Linux distributions' package
// repositories and mirrors.

// Unexpired records may be cached and replicated.

// Alice asks the root RecordServer for Bob's RecordServer
// Alice asks Bob's RecordServer for Bob's LiveLocation
// The LiveLocation specifies an address and if the address is publicly
// accessible or if it is a signaling service.

// What if on the same network? No signaling needed.
// But that's more in the cooperative use case, right?
// It's just another "signal" option. If Alice wants to signal Bob, she can
// broadcast locally and also contact Bob's signaling service.

// Alice and Bob are both online.
// They want to establish communications over IP.
//
// If Alice is unilaterally initiating without Bob's knowledge
//   If Bob has a publicly acessible IP
//     Alice contacts Bob there
//   Else
//     Alice tries to open an external facing port (PCP, UPnP)
//     If Bob has a connection to a signaling service
//       Alice contacts Bob's signaling server
//     Alice signals Bob on the local network
//
// Local network signaling
//   Publish a signal message on the multicast group
//   If Bob receives it, Bob will contact Alice on her local address
//
// Wide network signaling
//   Alice contacts Bob's signaling server
//   Bob's signaling server forwards Alice's address to Bob, and
//   returns Bob's address to Alice.
//
// Alice has Bob's public IP address and port, and vice-versa
// Alice maintains a connection to Bob's signaling service in case Bob is
// able to open an external port. If Bob signals Alice, then Alice can contact
// Bob directly.
//
// Alice attempts repeatedly contacting Bob on:
// * the initially given port
// * sequentially increasing ports
// * random ports (birthday)
//
// If nothing works, use a relay server
//   Alice and Bob offered their relay servers, if any, in the initial message
//
//
//
//
//
//
// Else if Alice and Bob are cooperatively initiating
//
// 2 scenarios:
// 1. Alice is unilaterally initiating without Bob's knowledge.
// 2. Alice and Bob are cooperatively initiating.
//
//
//
// Scenario 1:
// Alice needs to establish Bob's IP.
// Alice queries the record server for a LiveLocation.
// Alice sends a message to the LiveLocation
//
//
// Let's say Alice is initiating:
//   If Bob has a public IP.
//
// A signaling server to aid in NAT holepunching
//
// Scenario 1:
//   Alice has Bob's public key
//   Bob has Alice's public key
// Scenario 2:
//   Alice and Bob both have a short code

static void IpStr_log(const IpStr* s, Str tag) {
  LOG("%" PRIBytes "=%" PRIIpStr, BytesPRI(tag), IpStrPRI(*s));
}

static void handle_message(UvcoUdpRecv* recv) {
  IpStrStorage ip_str;
  CHECK0(IpStr_read(&ip_str, recv->addr));
  IpStr_log((IpStr*)&ip_str, Str("source"));

  Str msg = Bytes(recv->buf.base, recv->buf.len);
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
  int                  option;
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

  // Create UDP
  uv_udp_t udp;
  CHECK0(uv_udp_init(loop, &udp));

  // Bind to the port
  struct sockaddr_in myaddr;
  CHECK0(uv_ip4_addr("0.0.0.0", port, &myaddr));
  CHECK0(uv_udp_bind(&udp, (struct sockaddr*)&myaddr, 0));

  IpStrStorage me;
  IpStr_read(&me, (const struct sockaddr*)(&myaddr));
  IpStr_log((IpStr*)&me, Str("me"));

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
