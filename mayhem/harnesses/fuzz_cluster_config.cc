// Fuzz cluster_config::deserialize (and srv_config::deserialize, which it calls):
// the format of configuration log entries received from the leader and of persisted config.
#include "libnuraft/nuraft.hxx"
#include <cstring>
#include <stdexcept>

using namespace nuraft;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    ptr<buffer> buf = buffer::alloc(size);
    memcpy(buf->data_begin(), data, size);
    buf->pos(0);
    try {
        ptr<cluster_config> c = cluster_config::deserialize(*buf);
        if (c) {
            ptr<buffer> out = c->serialize();
            out->pos(0);
            cluster_config::deserialize(*out);
        }
    } catch (std::exception&) {
        // buffer getters throw std::overflow_error on short input: the library's
        // documented way of rejecting truncated data.
    }
    return 0;
}
