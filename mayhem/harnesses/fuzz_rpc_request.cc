// Fuzz the NuRaft RPC request listener (src/asio_service.cxx rpc_session) over a
// real loopback TCP connection: the bytes a peer sends to a Raft server. The
// parsed req_msg is handed to raft_server::process_req and its handlers.
//
// Built twice:
//   fuzz_rpc_request_raw : input written to the socket verbatim (header CRC,
//                          flags, size checks, CRC_ON_ENTIRE_MESSAGE path).
//   fuzz_rpc_request     : FIX_CRC — the input is one request (54-byte header +
//                          payload); the harness sets data_size to the payload
//                          length and recomputes the CRC field exactly as
//                          asio_rpc_client::send does, so inputs reach the
//                          log-entry decoder and the raft_server handlers.
//
// State: the asio_service (worker thread pool, stateless) is kept for the whole
// process. Every input gets a fresh listener + raft_server + in-memory log store
// and state manager, torn down before returning, so a result depends only on
// its input.
#include "libnuraft/nuraft.hxx"
#include "in_memory_log_store.hxx"
#include "in_memory_state_mgr.hxx"
#include "echo/echo_state_machine.hxx"
#include "crc32.hxx"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace nuraft;

// raft_server reports fatal errors (e.g. an exception in the background commit thread,
// handle_commit.cxx) through state_mgr::system_exit() and then calls exit(). Abort there instead,
// so such an input is reported as a crash with a backtrace rather than "fuzz target exited".
class aborting_state_mgr : public inmem_state_mgr {
public:
    aborting_state_mgr(int id, const std::string& ep) : inmem_state_mgr(id, ep) {}
    void system_exit(const int exit_code) override { (void)exit_code; abort(); }
};

static ptr<asio_service> g_svc;
static int g_port;

static const size_t REQ_HDR = 54;
static const size_t CRC_POS = 46;
static const size_t SIZE_POS = 42;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
    asio_service::options opt;
    opt.thread_pool_size_ = 2;
    g_svc = cs_new<asio_service>(opt, nullptr);
    // Per-process port so parallel fuzz workers on one host don't collide.
    g_port = 20000 + (getpid() % 30000);
    return 0;
}

static void write_all(int fd, const uint8_t* p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w <= 0) return;  // server closed the session early
        p += w; n -= (size_t)w;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::vector<uint8_t> msg(data, data + size);
#ifdef FIX_CRC
    if (size < REQ_HDR) return -1;
    {
        uint32_t payload = (uint32_t)(size - REQ_HDR);
        // Little-endian, as buffer_serializer writes it.
        for (int i = 0; i < 4; ++i) msg[SIZE_POS + i] = (payload >> (8 * i)) & 0xff;
        uint32_t flags = 0;
        for (int i = 0; i < 4; ++i) flags |= (uint32_t)msg[CRC_POS + 4 + i] << (8 * i);
        uint32_t crc = crc32_8(msg.data(), CRC_POS, 0);
        if (flags & 0x8 /* CRC_ON_ENTIRE_MESSAGE */) {
            // Aligned copy: crc32_8 reads 32-bit words (src/crc32.cxx).
            std::vector<uint8_t> pl(msg.begin() + REQ_HDR, msg.end());
            crc = crc32_8(pl.data(), payload, crc);
        }
        for (int i = 0; i < 4; ++i) msg[CRC_POS + i] = (crc >> (8 * i)) & 0xff;
    }
#endif

    ptr<rpc_listener> listener;
    for (int tries = 0; tries < 100 && !listener; ++tries) {
        ptr<logger> nolog;
        listener = g_svc->create_rpc_listener((ushort)g_port, nolog);
        if (!listener) g_port = 20000 + ((g_port - 20000 + 7919) % 30000);
    }
    if (!listener) abort();

    raft_params params;
    // Timers long enough that the single node stays a follower while the input
    // is processed: the server's role must not depend on host speed.
    params.election_timeout_lower_bound_ = 1000000;
    params.election_timeout_upper_bound_ = 2000000;
    params.heart_beat_interval_ = 500000;
    params.return_method_ = raft_params::blocking;

    ptr<state_machine> sm = cs_new<echo_state_machine>();
    ptr<state_mgr> smgr = cs_new<aborting_state_mgr>(1, "127.0.0.1:" + std::to_string(g_port));
    ptr<delayed_task_scheduler> sched = g_svc;
    ptr<rpc_client_factory> cli = g_svc;
    context* ctx = new context(smgr, sm, listener, nullptr, cli, sched, params);
    raft_server::init_options iopt;
    iopt.skip_initial_election_timeout_ = true;
    ptr<raft_server> srv = cs_new<raft_server>(ctx, iopt);
    ptr<msg_handler> h = srv;
    listener->listen(h);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) abort();
    sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)g_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (sockaddr*)&a, sizeof(a)) == 0) {
        write_all(fd, msg.data(), msg.size());
        shutdown(fd, SHUT_WR);
        // Drain responses until the server closes the session.
        uint8_t tmp[4096];
        while (recv(fd, tmp, sizeof(tmp), 0) > 0) {}
    }
    close(fd);

    srv->shutdown();
    listener->stop();
    listener->shutdown();
    srv.reset();
    h.reset();
    return 0;
}
